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
	/* The OTHER end of the socketpair backing each slot. Never read or
	 * written -- recv is emulated at enter, so no data ever has to flow --
	 * but kept recorded, and kept OPEN in the guest, because closing it
	 * would make the guest's own end report EOF/hangup to any poller. */
	int peer_fds[FAKE_NETLINK_MAX_FDS];
	/* Sequence number and pid from the last request seen on each fd, so
	 * the reply we synthesise echoes them back. A netlink client matches
	 * replies on these; returning zeros makes well-written clients
	 * (including Go's) discard the answer as unsolicited. */
	uint32_t last_seq[FAKE_NETLINK_MAX_FDS];
	uint32_t last_pid[FAKE_NETLINK_MAX_FDS];
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

static int claim_slot(FakeNetlinkConfig *cfg, int fd, int peer)
{
	for (int i = 0; i < FAKE_NETLINK_MAX_FDS; i++) {
		if (cfg->fds[i] == -1) {
			cfg->fds[i] = fd;
			cfg->peer_fds[i] = peer;
			cfg->last_seq[i] = 0;
			cfg->last_pid[i] = 0;
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
}

/**
 * Write a bare NLMSG_DONE into the guest's receive buffer — the wire form of
 * "that is the entire answer, and it is empty".
 *
 * Returns the number of bytes written, or a negative errno. A buffer too
 * small for a single header gets EINVAL rather than a truncated message,
 * because a partial nlmsghdr is not something a caller can parse.
 */
static int emit_done(Tracee *tracee, const FakeNetlinkConfig *cfg, int slot,
		     word_t buf, word_t len)
{
	struct nlmsghdr done;

	if (len < NLMSG_HDRLEN) return -EINVAL;

	memset(&done, 0, sizeof(done));
	done.nlmsg_len   = NLMSG_HDRLEN;
	done.nlmsg_type  = NLMSG_DONE;
	/* NLM_F_MULTI is deliberately NOT set: this is a single, complete
	 * reply, not the tail of a multipart dump. Setting it would tell the
	 * client to keep reading and it would block on a second message that
	 * is never coming. */
	done.nlmsg_flags = 0;
	/* Echo the request's sequence, and stamp OUR port id — not the
	 * request's. The client compares the reply's pid against what its own
	 * getsockname() reported (Go: netlink_linux.go NetlinkRIB, "m.Header.Pid
	 * != lsanl.Pid -> EINVAL"), and a request is normally sent with
	 * nlmsg_pid = 0 meaning "to the kernel". Copying that 0 back would fail
	 * the comparison. */
	done.nlmsg_seq   = slot >= 0 ? cfg->last_seq[slot] : 0;
	done.nlmsg_pid   = FAKE_NETLINK_PORT_ID;

	if (write_data(tracee, buf, &done, NLMSG_HDRLEN) < 0) return -EFAULT;
	return NLMSG_HDRLEN;
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

	slot = claim_slot(cfg, pair[0], pair[1]);
	if (slot < 0) {
		/* Table full — refuse rather than hand back a socket we will
		 * not recognise later and would therefore emulate wrongly. */
		poke_reg(tracee, SYSARG_RESULT, (word_t) -EMFILE);
		return;
	}

	poke_reg(tracee, SYSARG_RESULT, (word_t) pair[0]);
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
			cfg->peer_fds[i] = -1;
		}

		extension->config = cfg;
		extension->filtered_sysnums = filtered_sysnums;

		note(NULL, INFO, INTERNAL,
		     "fake_netlink: initialized (RTM_GETLINK/RTM_GETADDR → empty list)");
		return 0;
	}

	case INHERIT_PARENT:
		/* Inherited across fork: a child keeps using fds it inherited,
		 * so its view of which ones are emulated must match. */
		return 0;

	case SYSCALL_ENTER_START: {
		Tracee *tracee = TRACEE(extension);
		FakeNetlinkConfig *cfg = extension->config;

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
				n = emit_done(tracee, cfg, rslot,
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
					n = emit_done(tracee, cfg, rslot,
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
		case PR_bind:
			/* The guest binds to pick up a port/groups. There is
			 * nothing to bind to, and the AF_UNIX fd underneath
			 * would reject an AF_NETLINK sockaddr, so report the
			 * success the guest is entitled to expect. */
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;

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
