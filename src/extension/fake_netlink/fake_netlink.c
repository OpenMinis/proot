/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * fake_netlink: emulate an rtnetlink socket inside an unprivileged Android
 * app sandbox.
 *
 * ## The problem
 *
 * Android runs third-party apps in the SELinux `untrusted_app` domain, which
 * is not permitted to create an AF_NETLINK/NETLINK_ROUTE socket. The refusal
 * happens in the REAL kernel, before PRoot's ptrace stop has any say in it, so
 * the guest sees a bare EPERM:
 *
 *     route ip+net: netlinkrib: permission denied
 *
 * Go's net.Interfaces() reaches this through syscall.NetlinkRIB(), so anything
 * that enumerates interfaces (tailscale/tsnet is how we found it) fails at
 * startup even though it would be perfectly happy to learn that there are no
 * interfaces at all.
 *
 * ## Why this can be emulated at all
 *
 * PRoot is not a kernel, so it cannot make the real kernel say yes. What it
 * CAN do is decline to forward a syscall: writing PR_void into the syscall
 * number register at ptrace-enter makes the kernel execute a harmless no-op,
 * and PRoot then supplies the result itself at ptrace-exit (see the
 * SYSCALL_AVOIDER block in syscall/exit.c:74-86). `fake_id0` already fakes a
 * whole family of privileged calls this way ("These syscalls are fully
 * emulated", fake_id0.c:699-701), so the mechanism is load-bearing and
 * long-standing rather than something invented here.
 *
 * ## The one thing we do NOT fabricate: the fd
 *
 * A fabricated fd number would be a lie the rest of the system can detect —
 * poll/epoll/fcntl/dup/fork would all consult the real kernel about a
 * descriptor that does not exist there. So `socket(AF_NETLINK, …)` is turned
 * into a REAL `socketpair(AF_UNIX, SOCK_DGRAM, 0)` executed by the tracee
 * itself: the guest ends up holding a genuine kernel fd with ordinary
 * semantics, and only the DATA flowing over it is ours. This is the same
 * trick the iSH port used, for the same reason.
 *
 * Because that substitution needs a second syscall in the tracee, it is done
 * with PRoot's existing syscall-chaining machinery rather than by voiding.
 *
 * ## Scope of the emulation
 *
 * Deliberately minimal, matching what iSH shipped: RTM_GETLINK and
 * RTM_GETADDR are answered with an EMPTY interface list (just NLMSG_DONE).
 * "No interfaces" is a state every correct caller must already handle, which
 * is why an empty answer is safer than a fabricated eth0 that does not exist:
 * a caller that tries to bind to invented addresses would fail later and in a
 * much more confusing way. Everything that is not a NETLINK_ROUTE socket is
 * untouched and keeps going to the real kernel.
 */

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_addr.h>
#include <talloc.h>

#include "extension/fake_netlink/fake_netlink.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"
#include "arch.h"

/* Tracked fds per tracee. A guest that opens many rtnetlink sockets at once
 * is pathological; 16 covers real programs with room to spare, and the table
 * is fixed-size so no allocation happens on the syscall path. */
#define FAKE_NETLINK_MAX_FDS 16

typedef struct {
	/* Guest fd numbers we are emulating. -1 = free slot. */
	int fds[FAKE_NETLINK_MAX_FDS];
	/* Sequence number and pid from the last request seen on each fd, so
	 * the reply we synthesise echoes them back. A netlink client matches
	 * replies on these; returning zeros makes well-written clients
	 * (including Go's) discard the answer as unsolicited. */
	uint32_t last_seq[FAKE_NETLINK_MAX_FDS];
	uint32_t last_pid[FAKE_NETLINK_MAX_FDS];
	/* nlmsg_type of the last request, so the reply can describe the right
	 * thing (a GETLINK dump answers with RTM_NEWLINK, GETADDR with
	 * RTM_NEWADDR). */
	uint16_t last_type[FAKE_NETLINK_MAX_FDS];
	/* [T-android-fake-netlink-monitor] True when bind() asked for multicast
	 * groups, i.e. this is an EVENT-SUBSCRIPTION socket rather than a
	 * request/response one. The two need opposite treatment on recv --
	 * see the PR_bind and recv handling. */
	bool is_monitor[FAKE_NETLINK_MAX_FDS];
	/* Set while a socket() call is being converted, so the exit handler
	 * knows to adopt the resulting fd. */
	bool pending_socket;
	/* Capacity the caller passed to getsockname(), captured at ENTER.
	 * By the time we run at EXIT the kernel has already overwritten
	 * *optlen with ITS answer (2, for an unnamed AF_UNIX socket), so the
	 * caller's real buffer size is unrecoverable at that point. */
	socklen_t getsockname_capacity;
} FakeNetlinkConfig;

/* Syscalls we ask PRoot to stop on. Keeping this list tight matters: every
 * entry here is a ptrace stop the whole guest pays for, and with seccomp
 * filtering enabled PRoot uses it to avoid trapping anything else. */
static const FilteredSysnum filtered_sysnums[] = {
	{ PR_socket,	FILTER_SYSEXIT },
	{ PR_bind,	FILTER_SYSEXIT },
	{ PR_sendto,	FILTER_SYSEXIT },
	{ PR_sendmsg,	FILTER_SYSEXIT },
	{ PR_recvfrom,	FILTER_SYSEXIT },
	{ PR_recvmsg,	FILTER_SYSEXIT },
	/* getsockname needs BOTH: the caller's buffer capacity is only
	 * readable at enter (see getsockname_capacity), the value is only
	 * writable at exit. */
	{ PR_getsockname, FILTER_SYSEXIT },
	{ PR_close,	FILTER_SYSEXIT },
	/* [T-android-fake-so-mark] Not tied to our fake fds -- see
	 * handle_setsockopt_enter. */
	{ PR_setsockopt, FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

/* The port id we claim to have been assigned. A real kernel hands out the
 * tid by default; any non-zero value works as long as we are consistent,
 * because the only thing that consults it is the client comparing its own
 * getsockname() against the pid in our replies. */
#define FAKE_NETLINK_PORT_ID 1

static int slot_of(const FakeNetlinkConfig *cfg, int fd)
{
	if (fd < 0) return -1;
	for (int i = 0; i < FAKE_NETLINK_MAX_FDS; i++)
		if (cfg->fds[i] == fd) return i;
	return -1;
}

static int claim_slot(FakeNetlinkConfig *cfg, int fd)
{
	for (int i = 0; i < FAKE_NETLINK_MAX_FDS; i++) {
		if (cfg->fds[i] == -1) {
			cfg->fds[i] = fd;
			cfg->last_seq[i] = 0;
			cfg->last_pid[i] = 0;
			cfg->last_type[i] = 0;
			cfg->is_monitor[i] = false;
			return i;
		}
	}
	return -1;
}

static void release_slot(FakeNetlinkConfig *cfg, int fd)
{
	int slot = slot_of(cfg, fd);
	if (slot >= 0) cfg->fds[slot] = -1;
}

/**
 * Remember the sequence/pid of an outgoing request so the synthesised reply
 * can echo them. Reads only the fixed-size nlmsghdr; a short or unreadable
 * buffer simply leaves the previous values in place.
 */
static void note_request(Tracee *tracee, FakeNetlinkConfig *cfg, int slot,
			 word_t buf, word_t len)
{
	struct nlmsghdr hdr;

	if (slot < 0 || len < sizeof(hdr)) return;
	if (read_data(tracee, &hdr, buf, sizeof(hdr)) < 0) return;

	cfg->last_seq[slot] = hdr.nlmsg_seq;
	cfg->last_pid[slot] = hdr.nlmsg_pid;
	cfg->last_type[slot] = hdr.nlmsg_type;
}

/* Helper: append one attribute to a netlink message buffer. */
static size_t put_attr(char *p, size_t off, uint16_t type,
		       const void *val, size_t vlen)
{
	struct rtattr *rta = (struct rtattr *) (p + off);
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(vlen);
	memcpy(RTA_DATA(rta), val, vlen);
	return off + RTA_ALIGN(rta->rta_len);
}

/**
 * Build the reply to an RTM_GETLINK / RTM_GETADDR dump.
 *
 * [T-android-fake-netlink-loopback] This reports a LOOPBACK interface rather
 * than nothing, and that choice is the whole point.
 *
 * The first version answered every dump with a bare NLMSG_DONE — an empty
 * interface list. That was enough to get net.Interfaces() to succeed, but it
 * is also, to a networking stack, a machine with no connectivity at all.
 * tsnet read it exactly that way on device:
 *
 *   link state: interfaces.State{defaultRoute= ifs={} v4=false v6=false}
 *   magicsock: SetNetworkUp(false)
 *   control: setPaused(true)
 *   control: authRoutine: awaiting unpause    <- forever
 *
 * so the control client never dialled out and no login URL was ever produced.
 * "Honest" emptiness turned out to be the thing that blocked it.
 *
 * A loopback interface with 127.0.0.1 is the smallest answer that is both
 * TRUE (the sandbox really can talk to itself, and outbound TCP/UDP genuinely
 * work here — verified by resolving login.tailscale.com and completing an
 * HTTPS request from inside) and sufficient for a stack to consider itself
 * up. We deliberately do NOT invent an ethernet interface with a made-up
 * address: a caller that tried to bind or advertise it would fail later and
 * more confusingly, which is the failure mode this whole extension exists to
 * avoid.
 */
static int emit_dump_reply(Tracee *tracee, const FakeNetlinkConfig *cfg,
			   int slot, word_t buf, word_t len)
{
	/* One message plus NLMSG_DONE; generous headroom for alignment. */
	char msg[512];
	size_t off = 0;
	uint16_t req = slot >= 0 ? cfg->last_type[slot] : 0;
	uint32_t seq = slot >= 0 ? cfg->last_seq[slot] : 0;
	struct nlmsghdr *nh;
	struct nlmsghdr done;

	memset(msg, 0, sizeof(msg));

	if (req == RTM_GETLINK) {
		struct ifinfomsg ifi;
		const char *name = "lo";
		uint32_t mtu = 65536;
		/* 00:00:00:00:00:00 — loopback has no meaningful MAC. */
		char mac[6] = { 0 };

		memset(&ifi, 0, sizeof(ifi));
		ifi.ifi_family = AF_UNSPEC;
		ifi.ifi_type = ARPHRD_LOOPBACK;
		ifi.ifi_index = 1;
		ifi.ifi_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
		ifi.ifi_change = 0xFFFFFFFF;

		nh = (struct nlmsghdr *) msg;
		nh->nlmsg_type = RTM_NEWLINK;
		nh->nlmsg_flags = NLM_F_MULTI;
		nh->nlmsg_seq = seq;
		nh->nlmsg_pid = FAKE_NETLINK_PORT_ID;
		memcpy(NLMSG_DATA(nh), &ifi, sizeof(ifi));
		off = NLMSG_LENGTH(sizeof(ifi));
		off = put_attr(msg, off, IFLA_IFNAME, name, strlen(name) + 1);
		off = put_attr(msg, off, IFLA_MTU, &mtu, sizeof(mtu));
		off = put_attr(msg, off, IFLA_ADDRESS, mac, sizeof(mac));
		nh->nlmsg_len = off;
	} else if (req == RTM_GETADDR) {
		struct ifaddrmsg ifa;
		/* 127.0.0.1 in network byte order. */
		unsigned char v4[4] = { 127, 0, 0, 1 };
		const char *label = "lo";

		memset(&ifa, 0, sizeof(ifa));
		ifa.ifa_family = AF_INET;
		ifa.ifa_prefixlen = 8;
		ifa.ifa_flags = IFA_F_PERMANENT;
		ifa.ifa_scope = RT_SCOPE_HOST;
		ifa.ifa_index = 1;

		nh = (struct nlmsghdr *) msg;
		nh->nlmsg_type = RTM_NEWADDR;
		nh->nlmsg_flags = NLM_F_MULTI;
		nh->nlmsg_seq = seq;
		nh->nlmsg_pid = FAKE_NETLINK_PORT_ID;
		memcpy(NLMSG_DATA(nh), &ifa, sizeof(ifa));
		off = NLMSG_LENGTH(sizeof(ifa));
		off = put_attr(msg, off, IFA_ADDRESS, v4, sizeof(v4));
		off = put_attr(msg, off, IFA_LOCAL, v4, sizeof(v4));
		off = put_attr(msg, off, IFA_LABEL, label, strlen(label) + 1);
		nh->nlmsg_len = off;
	}
	/* Anything else (a request type we do not model) falls through with
	 * off == 0 and gets a bare DONE, which is a well-formed "nothing to
	 * report" rather than a hang. */

	/* Terminate the dump. NLM_F_MULTI is set on the payload messages
	 * above, so the client keeps reading until it sees this. */
	memset(&done, 0, sizeof(done));
	done.nlmsg_len = NLMSG_HDRLEN;
	done.nlmsg_type = NLMSG_DONE;
	done.nlmsg_flags = 0;
	done.nlmsg_seq = seq;
	done.nlmsg_pid = FAKE_NETLINK_PORT_ID;

	if (off + NLMSG_HDRLEN > sizeof(msg)) return -EINVAL;
	memcpy(msg + off, &done, NLMSG_HDRLEN);
	off += NLMSG_HDRLEN;

	if (len < off) return -EINVAL;
	if (write_data(tracee, buf, msg, off) < 0) return -EFAULT;
	return (int) off;
}

/**
 * socket(AF_NETLINK, *, NETLINK_ROUTE) → socketpair(AF_UNIX, SOCK_DGRAM, 0).
 *
 * Done at syscall ENTER by rewriting the number and arguments in place, so
 * the tracee itself performs the substituted call and the fd it receives is a
 * real one. The 4th argument needs a scratch buffer in the guest for
 * socketpair's int[2] out-parameter; alloc_mem gives us one on the tracee's
 * stack, which is reclaimed automatically when the syscall returns.
 */
static int convert_socket_enter(Tracee *tracee, FakeNetlinkConfig *cfg)
{
	word_t scratch;

	if (peek_reg(tracee, CURRENT, SYSARG_1) != AF_NETLINK) return 0;

	/* NETLINK_ROUTE is the only protocol we answer for. Anything else
	 * (NETLINK_KOBJECT_UEVENT, NETLINK_AUDIT, …) keeps its real EPERM,
	 * which is honest: we have nothing sensible to say for those. */
	if (peek_reg(tracee, CURRENT, SYSARG_3) != NETLINK_ROUTE) return 0;

	scratch = alloc_mem(tracee, 2 * sizeof(int));
	if (scratch == 0) return -ENOMEM;

	set_sysnum(tracee, PR_socketpair);
	poke_reg(tracee, SYSARG_1, AF_UNIX);
	poke_reg(tracee, SYSARG_2, SOCK_DGRAM);
	poke_reg(tracee, SYSARG_3, 0);
	poke_reg(tracee, SYSARG_4, scratch);

	cfg->pending_socket = true;
	return 0;
}

/**
 * Adopt the fd that the substituted socketpair() produced.
 *
 * socketpair returns 0 and writes two fds; the guest expects socket()'s
 * convention of "the fd IS the return value". So we read the pair back, hand
 * the guest the first, and record the second for closing. Both ends are kept
 * open on purpose — closing the peer here would make the guest's own end
 * readable-at-EOF, which some pollers read as a hangup.
 */
static void adopt_socket_exit(Tracee *tracee, FakeNetlinkConfig *cfg)
{
	word_t result;
	int pair[2];
	int slot;

	cfg->pending_socket = false;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) return;	/* socketpair itself failed; pass it through */

	if (read_data(tracee, pair, peek_reg(tracee, MODIFIED, SYSARG_4),
		      sizeof(pair)) < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t) -ENOMEM);
		return;
	}

	/* pair[1] is deliberately left OPEN in the guest and not
	 * tracked: nothing ever reads or writes it (recv is emulated at
	 * enter, so no data has to flow), but closing it would make the
	 * guest's own end report EOF/hangup to any poller. */
	slot = claim_slot(cfg, pair[0]);
	if (slot < 0) {
		/* Table full — refuse rather than hand back a socket we will
		 * not recognise later and would therefore emulate wrongly. */
		poke_reg(tracee, SYSARG_RESULT, (word_t) -EMFILE);
		return;
	}

	poke_reg(tracee, SYSARG_RESULT, (word_t) pair[0]);
}

/**
 * [T-android-fake-so-mark] Pretend `setsockopt(SOL_SOCKET, SO_MARK, …)`
 * succeeded.
 *
 * SO_MARK stamps an fwmark on outbound packets so routing rules can match
 * them. Setting it requires CAP_NET_ADMIN, which an unprivileged Android app
 * can never hold, so the real kernel answers EPERM.
 *
 * Tailscale sets it to keep its own traffic from being routed back through
 * its tunnel, and treats the failure as fatal: after the netlink emulation
 * let tsnet get further, startup died at
 *
 *     wgengine: magicsock: Rebind IPv4 failed: failed to bind any ports
 *
 * which a per-sockopt probe traced to SO_MARK alone -- plain binds,
 * SO_REUSEADDR/PORT, IP_PKTINFO, IP_RECVERR and IP_MTU_DISCOVER all succeed in
 * the sandbox. The same probe fails identically OUTSIDE proot, confirming this
 * is the kernel's rule and not something proot introduced.
 *
 * Reporting success is honest about the outcome rather than the mechanism: the
 * mark exists to steer packets through policy routing that this sandbox has no
 * way to install in the first place, so there is nothing for the caller to be
 * misled about. A guest that genuinely depends on the mark taking effect is
 * already unable to work here.
 *
 * Unlike the rest of this file, this is deliberately NOT restricted to fds we
 * created: Tailscale sets SO_MARK on its ordinary UDP sockets, which are real
 * kernel sockets we never touched. The narrowing is on the OPTION instead --
 * every other level/optname is passed straight through to the kernel.
 */
static void handle_setsockopt_enter(Tracee *tracee)
{
	/* SO_MARK is 36 on Linux and is not always exposed by the NDK headers
	 * for every API level, so it is spelled out rather than included. */
	const int SOL_SOCKET_LINUX = 1;
	const int SO_MARK_LINUX = 36;

	if ((int) peek_reg(tracee, CURRENT, SYSARG_2) != SOL_SOCKET_LINUX) return;
	if ((int) peek_reg(tracee, CURRENT, SYSARG_3) != SO_MARK_LINUX) return;

	/* Void the call and report success. The result MUST be set here, at
	 * enter: translate_syscall_exit() restores SYSARG_RESULT from the
	 * MODIFIED register set for any PR_void'd syscall (syscall/exit.c:76-87),
	 * and that runs after the extension's exit hook, so a poke_reg() from
	 * there would be silently discarded. */
	set_sysnum(tracee, PR_void);
	poke_reg(tracee, SYSARG_RESULT, 0);
}

int fake_netlink_callback(Extension *extension, ExtensionEvent event,
			  intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		FakeNetlinkConfig *cfg = talloc_zero(extension, FakeNetlinkConfig);
		if (cfg == NULL) return -ENOMEM;

			for (int i = 0; i < FAKE_NETLINK_MAX_FDS; i++) {
			cfg->fds[i] = -1;
			cfg->is_monitor[i] = false;
		}

		extension->config = cfg;
		extension->filtered_sysnums = filtered_sysnums;

		note(NULL, INFO, INTERNAL,
		     "fake_netlink: initialized (rtnetlink → loopback only; SO_MARK → no-op)");
		return 0;
	}

	case INHERIT_PARENT:
		/* Inherited across fork: a child keeps using fds it inherited,
		 * so its view of which ones are emulated must match. */
		return 0;

	case SYSCALL_ENTER_START: {
		Tracee *tracee = TRACEE(extension);
		FakeNetlinkConfig *cfg = extension->config;

		if (get_sysnum(tracee, CURRENT) == PR_setsockopt) {
			handle_setsockopt_enter(tracee);
			return 0;
		}

		if (get_sysnum(tracee, CURRENT) == PR_socket)
			return convert_socket_enter(tracee, cfg);

		/* [blocking] recvfrom/recvmsg on our AF_UNIX stand-in would sleep
		 * in the kernel forever: nothing ever writes to it, and a
		 * ptrace exit-stop only happens once the syscall RETURNS. So
		 * void the call at enter -- the kernel runs a harmless no-op --
		 * and let the exit handler below fill in the reply. This is the
		 * same PR_void mechanism fake_id0 uses to fully emulate a call.
		 *
		 * Verified on device: without this the guest hangs in recvfrom
		 * and never completes net.Interfaces(). */
		if (get_sysnum(tracee, CURRENT) == PR_recvfrom
		    || get_sysnum(tracee, CURRENT) == PR_recvmsg) {
			int rfd = (int) peek_reg(tracee, CURRENT, SYSARG_1);
			int rslot = slot_of(cfg, rfd);
			int n;

			if (rslot < 0) return 0;

			/* [T-android-fake-netlink-monitor] An event-subscription
			 * socket has nothing to report and never will: there is
			 * no netlink underneath to generate a link event. The
			 * honest answer is the one a real quiet system gives --
			 * block. Letting the call through to the real kernel on
			 * the empty AF_UNIX stand-in does exactly that, and it
			 * blocks in a way the guest can still interrupt or
			 * poll, unlike anything we could fabricate. */
			if (cfg->is_monitor[rslot]) return 0;

			/* Write the reply and set the result HERE, not at exit.
			 *
			 * translate_syscall_exit() restores SYSARG_RESULT from
			 * the MODIFIED register set for any PR_void'd syscall
			 * (syscall/exit.c:76-87), and that runs AFTER the
			 * extension's SYSCALL_EXIT_START. A poke_reg() from the
			 * exit hook is therefore silently overwritten -- which
			 * is exactly what made this return EINVAL on device
			 * despite emitting a correct NLMSG_DONE. */
			if (get_sysnum(tracee, CURRENT) == PR_recvfrom) {
				n = emit_dump_reply(tracee, cfg, rslot,
					      peek_reg(tracee, CURRENT, SYSARG_2),
					      peek_reg(tracee, CURRENT, SYSARG_3));
			} else {
				struct msghdr msg;
				struct iovec iov;
				word_t msg_addr = peek_reg(tracee, CURRENT, SYSARG_2);

				if (read_data(tracee, &msg, msg_addr, sizeof(msg)) < 0
				    || msg.msg_iovlen < 1
				    || read_data(tracee, &iov, (word_t) msg.msg_iov,
						 sizeof(iov)) < 0)
					n = -EFAULT;
				else
					n = emit_dump_reply(tracee, cfg, rslot,
						      (word_t) iov.iov_base,
						      (word_t) iov.iov_len);
			}

			set_sysnum(tracee, PR_void);
			poke_reg(tracee, SYSARG_RESULT, (word_t) n);
			return 0;
		}

		if (get_sysnum(tracee, CURRENT) == PR_getsockname) {
			/* Snapshot the caller's capacity before the kernel
			 * clobbers it with its own (much smaller) answer. */
			word_t lenp = peek_reg(tracee, CURRENT, SYSARG_3);
			socklen_t cap = 0;

			cfg->getsockname_capacity = 0;
			if (lenp != 0 && read_data(tracee, &cap, lenp, sizeof(cap)) >= 0)
				cfg->getsockname_capacity = cap;
		}
		return 0;
	}

	case SYSCALL_EXIT_START: {
		Tracee *tracee = TRACEE(extension);
		FakeNetlinkConfig *cfg = extension->config;
		word_t sysnum = get_sysnum(tracee, ORIGINAL);
		int fd, slot;

		if (sysnum == PR_socket) {
			if (cfg->pending_socket) adopt_socket_exit(tracee, cfg);
			return 0;
		}

		fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
		slot = slot_of(cfg, fd);
		if (slot < 0) return 0;	/* not one of ours */

		switch (sysnum) {
		case PR_bind: {
			/* The guest binds to pick up a port/groups. There is
			 * nothing to bind to, and the AF_UNIX fd underneath
			 * would reject an AF_NETLINK sockaddr, so report the
			 * success the guest is entitled to expect.
			 *
			 * [T-android-fake-netlink-monitor] While we are here,
			 * read nl_groups to learn which KIND of socket this is.
			 * A non-zero group mask means the caller subscribed to
			 * asynchronous link/address events (Tailscale's link
			 * monitor does this) rather than intending to send a
			 * request. Those two want opposite things from recv,
			 * and answering a monitor the way we answer a query is
			 * what made tsnet spin: it got an immediate
			 * NLMSG_DONE, logged "unhandled netlink msg type done",
			 * looped, and burned CPU writing 14 MB of log in a
			 * minute on device. */
			struct sockaddr_nl nl;
			word_t sa = peek_reg(tracee, ORIGINAL, SYSARG_2);
			word_t salen = peek_reg(tracee, ORIGINAL, SYSARG_3);

			if (sa != 0 && salen >= sizeof(nl)
			    && read_data(tracee, &nl, sa, sizeof(nl)) >= 0
			    && nl.nl_groups != 0) {
				cfg->is_monitor[slot] = true;
			}
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		}

		case PR_sendto:
		case PR_sendmsg:
			/* Record who is asking, then claim the whole request
			 * was sent. We do not inspect nlmsg_type here: the
			 * reply is the same empty NLMSG_DONE for GETLINK and
			 * GETADDR alike, and a type we do not model still
			 * gets a well-formed "nothing to report" rather than a
			 * hang. */
			note_request(tracee, cfg, slot,
				     peek_reg(tracee, ORIGINAL, SYSARG_2),
				     peek_reg(tracee, ORIGINAL, SYSARG_3));
			poke_reg(tracee, SYSARG_RESULT,
				 peek_reg(tracee, ORIGINAL, SYSARG_3));
			return 0;

		/* recvfrom/recvmsg are NOT handled here: they are voided and
		 * answered at syscall ENTER (see above), because a voided call's
		 * result is restored from the MODIFIED register set after this
		 * hook runs, and because a blocking read on the AF_UNIX stand-in
		 * would never return to give us an exit stop in the first place.
		 */

		case PR_getsockname: {
			/* The underlying fd is AF_UNIX, so the real kernel
			 * answers with sockaddr_un. Clients type-check this:
			 * Go asserts the result is *SockaddrNetlink and fails
			 * with EINVAL otherwise, which is exactly the error
			 * the first on-device run produced. Overwrite it with
			 * the sockaddr_nl the guest is entitled to see. */
			struct sockaddr_nl nl;
			word_t addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
			word_t lenp = peek_reg(tracee, ORIGINAL, SYSARG_3);
			socklen_t avail = 0;

			if (addr == 0 || lenp == 0) return 0;
			/* NOT read from *lenp: the kernel already replaced it
			 * with the length IT wrote (2 for an unnamed AF_UNIX
			 * socket), which is smaller than sockaddr_nl and would
			 * make us wrongly refuse. Use what the caller asked
			 * for, captured at enter. */
			avail = cfg->getsockname_capacity;
			if (avail < sizeof(nl)) {
				poke_reg(tracee, SYSARG_RESULT, (word_t) -EINVAL);
				return 0;
			}

			memset(&nl, 0, sizeof(nl));
			nl.nl_family = AF_NETLINK;
			nl.nl_pid    = FAKE_NETLINK_PORT_ID;
			nl.nl_groups = 0;

			avail = sizeof(nl);
			if (write_data(tracee, addr, &nl, sizeof(nl)) < 0
			    || write_data(tracee, lenp, &avail, sizeof(avail)) < 0) {
				poke_reg(tracee, SYSARG_RESULT, (word_t) -EFAULT);
				return 0;
			}
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		}

		case PR_close:
			release_slot(cfg, fd);
			return 0;

		default:
			return 0;
		}
	}

	default:
		return 0;
	}
}
