/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * xnet: transparent forwarding of guest TCP connections to the host app.
 *
 * Programs that ignore ALL_PROXY / HTTP(S)_PROXY (ssh, nc, database
 * clients, static binaries) connect() directly. MinisApp routes the shell's
 * traffic itself (Tailscale, an upstream proxy, direct); this extension
 * hands it the connections it wants:
 *
 *   1. socket() is watched so that only TCP sockets (AF_INET / AF_INET6,
 *      SOCK_STREAM) are ever touched. A UDP socket, or an fd whose origin
 *      is unknown (inherited through dup2, passed over a unix socket), is
 *      left alone: it connects directly, as before.
 *   2. connect() to an address the routes file hooks (and does not exempt)
 *      is sent to the app's listener on 127.0.0.1:<port4> (or [::1]:<port6>
 *      for an IPv6 destination), using a copy of the sockaddr on the
 *      tracee's stack - the guest's own buffer is never modified.
 *   3. When that connect() returns (0 or EINPROGRESS) the socket has a
 *      local port: a getsockname() is chained after it (the guest still
 *      sees connect()'s own result), and the original destination is
 *      written to <map_dir>/<local port>; the app's listener reads it to
 *      know where the connection was going, then routes and relays it.
 *      (/proc/net/tcp would name the port too, but Android 10+ keeps it
 *      from apps.)
 *
 * Falling back is the rule, never failing the guest's connection:
 *   - no routes file (the app turned forwarding off: direct route without
 *     Tailscale, Restore Direct Connections, entry stopped) -> untouched;
 *   - the routes file changes (the app rewrites it on every route change)
 *     -> picked up on the next connect(), by mtime + inode;
 *   - the app's listener does not answer (app killed, entry restarting) ->
 *     this connect() goes out directly, and forwarding pauses for
 *     XNET_RETRY_SECONDS before the listener is tried again. While it
 *     answers it is probed at most once per XNET_ALIVE_SECONDS; and if a
 *     redirected connect() is refused anyway, the guest's own connect() is
 *     run again unchanged (direct).
 *
 * Routes file, one directive per line ('#' comments):
 *   port4 <n>        listener on 127.0.0.1
 *   port6 <n>        listener on ::1 (optional; IPv6 destinations otherwise
 *                    use the IPv4-mapped port4)
 *   map <dir>        where destinations are written (owner-only directory)
 *   hook <prefix>    forward destinations inside it
 *   exempt <prefix>  never forward these (local networks, proxy bypass)
 *
 * [FEAT-261021-23] Stage 2 - UDP and DNS, the counterpart of iSH's
 * (deps/ish fs/xnet.h, c7fcfb037). More directives:
 *   udpport <n>      the app's UDP listener on 127.0.0.1 (connected sockets)
 *   socks <n>        the app's SOCKS5 entry on 127.0.0.1 (UDP ASSOCIATE)
 *   user <name>      / pass <password>: the entry's credentials (the tag)
 *   udphook <prefix> UDP destinations to forward (a proxy route cannot carry
 *                    UDP, so this can be narrower than hook)
 *   resolver <ip>    the shell's nameservers; with "dns 1" their port 53 is
 *                    the app's to answer (MagicDNS), over UDP and TCP
 *   failclosed 1     a hooked connection or datagram the app cannot take
 *                    fails (ENETUNREACH) instead of going out directly
 *
 * read()/write() cannot be trapped without slowing every file access, so
 * UDP takes two paths:
 *   - a connect()ed socket (Go's and glibc's resolvers, Go tools, ntpdate)
 *     is connected to the UDP listener instead, like TCP, and its
 *     destination written to <map_dir>/u<local port> ("dns" marks the
 *     resolver). Its datagrams are not touched; recvfrom/recvmsg and
 *     getpeername report the real peer.
 *   - an unconnected socket's sendto/sendmsg to a hooked address (musl's
 *     resolver, dig, nc -u) goes through a SOCKS5 UDP association that this
 *     process (the tracer) holds open for the socket: the datagram is sent
 *     to the relay with the SOCKS header put in front by an extra iovec (the
 *     payload is never copied), and a datagram coming back from the relay
 *     has its header removed and its real source restored. An association
 *     declares the socket's own port (a bind(0) is chained first if it has
 *     none), so nothing else on the device can use the relay.
 * sendto/sendmsg/recvfrom/recvmsg are already stopped on for every guest by
 * the fake_netlink extension; this adds getpeername and close.
 *
 * The file and the map directory live in the app's private storage, outside
 * the guest's rootfs, so the guest can neither read nor forge them.
 *
 * Debug: MINIS_NOFF_DEBUG=1 prints one line per decision on stderr.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef XNET_PURE_ONLY
#include <talloc.h>

#include "extension/xnet/xnet.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#else
/* Host unit test (tests/xnet/test-xnet.c): the pure helpers only.  */
#include <stdbool.h>
#include <stdint.h>
#define XNET_MAX_PREFIXES 512
typedef struct { int family; uint8_t addr[16]; int bits; } XnetPrefix;
#define XNET_MAX_RESOLVERS 8
typedef struct {
	uint16_t port4, port6; char map_dir[512];
	XnetPrefix hook[XNET_MAX_PREFIXES]; int n_hook;
	XnetPrefix exempt[XNET_MAX_PREFIXES]; int n_exempt;
	uint16_t udp_port, socks_port; char user[64], pass[128];
	XnetPrefix udp_hook[XNET_MAX_PREFIXES]; int n_udp_hook;
	XnetPrefix resolver[XNET_MAX_RESOLVERS]; int n_resolver;
	bool dns, fail_closed;
} XnetRoutes;
#endif

#define XNET_MAX_FDS		4096
#define XNET_RETRY_SECONDS	10
#define XNET_PROBE_TIMEOUT_MS	150
#define XNET_ALIVE_SECONDS	10

/* --- Pure helpers ------------------------------------------------------ */

bool xnet_parse_prefix(const char *s, XnetPrefix *out)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash;
	int max_bits;

	if (s == NULL || strlen(s) >= sizeof(buf))
		return false;
	strcpy(buf, s);
	memset(out, 0, sizeof(*out));
	slash = strchr(buf, '/');
	if (slash != NULL)
		*slash = '\0';

	if (inet_pton(AF_INET, buf, out->addr) == 1) {
		out->family = AF_INET;
		max_bits = 32;
	} else if (inet_pton(AF_INET6, buf, out->addr) == 1) {
		out->family = AF_INET6;
		max_bits = 128;
	} else
		return false;

	if (slash == NULL)
		out->bits = max_bits;
	else {
		char *end;
		long bits = strtol(slash + 1, &end, 10);
		if (*end != '\0' || end == slash + 1 || bits < 0 || bits > max_bits)
			return false;
		out->bits = (int) bits;
	}
	return true;
}

int xnet_parse_routes(const char *text, XnetRoutes *out)
{
	const char *line = text;

	memset(out, 0, sizeof(*out));
	while (line != NULL && *line != '\0') {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t) (nl - line) : strlen(line);
		char buf[600], key[16], val[560];

		if (len < sizeof(buf)) {
			memcpy(buf, line, len);
			buf[len] = '\0';
			if (buf[0] != '#' && sscanf(buf, "%15s %559s", key, val) == 2) {
				XnetPrefix p;
				if (strcmp(key, "port4") == 0)
					out->port4 = (uint16_t) atoi(val);
				else if (strcmp(key, "port6") == 0)
					out->port6 = (uint16_t) atoi(val);
				else if (strcmp(key, "map") == 0 && strlen(val) < sizeof(out->map_dir))
					strcpy(out->map_dir, val);
				else if (strcmp(key, "hook") == 0 && out->n_hook < XNET_MAX_PREFIXES
					 && xnet_parse_prefix(val, &p))
					out->hook[out->n_hook++] = p;
				else if (strcmp(key, "exempt") == 0 && out->n_exempt < XNET_MAX_PREFIXES
					 && xnet_parse_prefix(val, &p))
					out->exempt[out->n_exempt++] = p;
				else if (strcmp(key, "udpport") == 0)
					out->udp_port = (uint16_t) atoi(val);
				else if (strcmp(key, "socks") == 0)
					out->socks_port = (uint16_t) atoi(val);
				else if (strcmp(key, "user") == 0 && strlen(val) < sizeof(out->user))
					strcpy(out->user, val);
				else if (strcmp(key, "pass") == 0 && strlen(val) < sizeof(out->pass))
					strcpy(out->pass, val);
				else if (strcmp(key, "udphook") == 0 && out->n_udp_hook < XNET_MAX_PREFIXES
					 && xnet_parse_prefix(val, &p))
					out->udp_hook[out->n_udp_hook++] = p;
				else if (strcmp(key, "resolver") == 0 && out->n_resolver < XNET_MAX_RESOLVERS
					 && xnet_parse_prefix(val, &p))
					out->resolver[out->n_resolver++] = p;
				else if (strcmp(key, "dns") == 0)
					out->dns = atoi(val) != 0;
				else if (strcmp(key, "failclosed") == 0)
					out->fail_closed = atoi(val) != 0;
			}
		}
		line = nl ? nl + 1 : NULL;
	}
	if (out->port4 == 0 || out->map_dir[0] == '\0')
		return -1;
	if (out->user[0] == '\0')
		strcpy(out->user, "shell");
	return 0;
}

static bool prefix_contains(const XnetPrefix *p, int family, const uint8_t *addr)
{
	int full, rem;

	if (p->family != family)
		return false;
	full = p->bits / 8;
	rem = p->bits % 8;
	if (memcmp(p->addr, addr, full) != 0)
		return false;
	if (rem != 0) {
		uint8_t mask = (uint8_t) (0xff << (8 - rem));
		if ((p->addr[full] & mask) != (addr[full] & mask))
			return false;
	}
	return true;
}

static bool never_forwarded(int family, const uint8_t *a)
{
	static const uint8_t zero[16];

	if (family == AF_INET)
		return a[0] == 127 || a[0] == 0 || (a[0] & 0xf0) == 0xe0
			|| (a[0] == 169 && a[1] == 254) || a[0] == 255;
	return memcmp(a, zero, 16) == 0					/* :: */
		|| (memcmp(a, zero, 15) == 0 && a[15] == 1)		/* ::1 */
		|| a[0] == 0xff						/* multicast */
		|| (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);		/* fe80::/10 */
}

bool xnet_should_forward(const XnetRoutes *r, int family, const uint8_t *addr)
{
	static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
	int i;
	bool hooked = false;

	if (family == AF_INET6 && memcmp(addr, mapped, 12) == 0) {
		family = AF_INET;
		addr += 12;
	}
	if (family != AF_INET && family != AF_INET6)
		return false;
	if (never_forwarded(family, addr))
		return false;
	for (i = 0; i < r->n_hook && !hooked; i++)
		hooked = prefix_contains(&r->hook[i], family, addr);
	if (!hooked)
		return false;
	for (i = 0; i < r->n_exempt; i++)
		if (prefix_contains(&r->exempt[i], family, addr))
			return false;
	return true;
}

/* An IPv4-mapped IPv6 address is matched as IPv4.  */
static void unmap(int *family, const uint8_t **addr)
{
	static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };

	if (*family == AF_INET6 && memcmp(*addr, mapped, 12) == 0) {
		*family = AF_INET;
		*addr += 12;
	}
}

bool xnet_udp_should_forward(const XnetRoutes *r, int family, const uint8_t *addr)
{
	int i;
	bool hooked = false;

	if (r->udp_port == 0 && r->socks_port == 0)
		return false;
	unmap(&family, &addr);
	if (family != AF_INET && family != AF_INET6)
		return false;
	if (never_forwarded(family, addr))
		return false;
	for (i = 0; i < r->n_udp_hook && !hooked; i++)
		hooked = prefix_contains(&r->udp_hook[i], family, addr);
	if (!hooked)
		return false;
	for (i = 0; i < r->n_exempt; i++)
		if (prefix_contains(&r->exempt[i], family, addr))
			return false;
	return true;
}

bool xnet_is_dns(const XnetRoutes *r, int family, const uint8_t *addr, uint16_t port)
{
	int i;

	if (!r->dns || port != 53)
		return false;
	unmap(&family, &addr);
	for (i = 0; i < r->n_resolver; i++)
		if (prefix_contains(&r->resolver[i], family, addr))
			return true;
	return false;
}

/* (family, addr, port) of a sockaddr; false for anything but IPv4/IPv6.  */
static inline bool sockaddr_parts(const struct sockaddr_storage *ss, socklen_t len,
			   int *family, const uint8_t **addr, uint16_t *port)
{
	if (ss->ss_family == AF_INET && len >= (socklen_t) sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *in = (const struct sockaddr_in *) ss;
		*family = AF_INET;
		*addr = (const uint8_t *) &in->sin_addr;
		*port = ntohs(in->sin_port);
		return true;
	}
	if (ss->ss_family == AF_INET6 && len >= (socklen_t) sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) ss;
		*family = AF_INET6;
		*addr = (const uint8_t *) &in6->sin6_addr;
		*port = ntohs(in6->sin6_port);
		return true;
	}
	return false;
}

/* The SOCKS5 UDP header (RFC 1928 section 7) for a datagram to or from
 * (family, addr, port); returns its length (10 or 22).  */
int xnet_udp_header(uint8_t *out, int family, const uint8_t *addr, uint16_t port)
{
	int n;

	unmap(&family, &addr);
	out[0] = 0;
	out[1] = 0;
	out[2] = 0;			/* no fragmentation */
	if (family == AF_INET) {
		out[3] = 1;
		memcpy(out + 4, addr, 4);
		n = 8;
	} else {
		out[3] = 4;
		memcpy(out + 4, addr, 16);
		n = 20;
	}
	out[n] = (uint8_t) (port >> 8);
	out[n + 1] = (uint8_t) port;
	return n + 2;
}

/* Parse a relayed datagram's header into the source the guest must see, in
 * the guest socket's family (an IPv4 source to an AF_INET6 socket is
 * v4-mapped). Returns the header length, or -1 (fragment, unknown type, too
 * short: not a relay datagram).  */
int xnet_parse_udp_header(const uint8_t *in, size_t n, int sock_family,
			  struct sockaddr_storage *src, socklen_t *src_len)
{
	size_t alen;

	if (n < 4 || in[2] != 0)
		return -1;
	if (in[3] == 1)
		alen = 4;
	else if (in[3] == 4)
		alen = 16;
	else
		return -1;
	if (n < 4 + alen + 2)
		return -1;
	memset(src, 0, sizeof(*src));
	if (alen == 4 && sock_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *) src;
		s->sin_family = AF_INET;
		memcpy(&s->sin_addr, in + 4, 4);
		s->sin_port = htons((uint16_t) (in[8] << 8 | in[9]));
		*src_len = sizeof(*s);
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) src;
		s->sin6_family = AF_INET6;
		if (alen == 4) {
			s->sin6_addr.s6_addr[10] = 0xff;
			s->sin6_addr.s6_addr[11] = 0xff;
			memcpy(&s->sin6_addr.s6_addr[12], in + 4, 4);
		} else
			memcpy(&s->sin6_addr, in + 4, 16);
		s->sin6_port = htons((uint16_t) (in[4 + alen] << 8 | in[4 + alen + 1]));
		*src_len = sizeof(*s);
	}
	return (int) (4 + alen + 2);
}

/* Blocking I/O on the tracer's own control connection, with the timeout
 * set on the socket.  */
static bool io_all(int fd, void *buf, size_t n, bool reading)
{
	uint8_t *p = buf;

	while (n > 0) {
		ssize_t r = reading ? read(fd, p, n) : write(fd, p, n);
		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			return false;
		}
		p += r;
		n -= (size_t) r;
	}
	return true;
}

/* Open a SOCKS5 UDP association with the app's entry on 127.0.0.1:port, as
 * user/pass, for datagrams from 127.0.0.1:client_port. Returns the control
 * connection (the association lives as long as it is open) and the relay's
 * port, or -1. Bounded by timeout_ms for the connect and for each reply:
 * proot is single-threaded, every guest waits while this runs.  */
int xnet_socks_associate(uint16_t port, const char *user, const char *pass,
			 uint16_t client_port, int timeout_ms, uint16_t *relay_port)
{
	struct sockaddr_in to;
	struct pollfd pfd;
	struct timeval tv;
	uint8_t buf[600], reply[10];
	size_t ul = strlen(user), pl = strlen(pass), n;
	int s, err = 0, flags;
	socklen_t elen = sizeof(err);

	if (ul == 0 || ul > 255 || pl > 255)
		return -1;
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	fcntl(s, F_SETFD, FD_CLOEXEC);	/* never inherited by a guest */
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	to.sin_port = htons(port);
	flags = fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, flags | O_NONBLOCK);
	if (connect(s, (struct sockaddr *) &to, sizeof(to)) != 0) {
		if (errno != EINPROGRESS)
			goto fail;
		pfd.fd = s;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, timeout_ms) != 1
		    || getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0)
			goto fail;
	}
	fcntl(s, F_SETFL, flags);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	/* Greeting (username/password only), then RFC 1929 authentication. */
	if (!io_all(s, (uint8_t[]) { 5, 1, 2 }, 3, false) || !io_all(s, reply, 2, true)
	    || reply[0] != 5 || reply[1] != 2)
		goto fail;
	n = 0;
	buf[n++] = 1;
	buf[n++] = (uint8_t) ul;
	memcpy(buf + n, user, ul);
	n += ul;
	buf[n++] = (uint8_t) pl;
	memcpy(buf + n, pass, pl);
	n += pl;
	if (!io_all(s, buf, n, false) || !io_all(s, reply, 2, true) || reply[1] != 0)
		goto fail;

	/* UDP ASSOCIATE, declaring 127.0.0.1:client_port. */
	n = 0;
	buf[n++] = 5;
	buf[n++] = 3;
	buf[n++] = 0;
	buf[n++] = 1;
	buf[n++] = 127;
	buf[n++] = 0;
	buf[n++] = 0;
	buf[n++] = 1;
	buf[n++] = (uint8_t) (client_port >> 8);
	buf[n++] = (uint8_t) client_port;
	if (!io_all(s, buf, n, false) || !io_all(s, reply, 10, true)
	    || reply[0] != 5 || reply[1] != 0 || reply[3] != 1)
		goto fail;
	*relay_port = (uint16_t) (reply[8] << 8 | reply[9]);
	if (*relay_port == 0)
		goto fail;
	return s;
fail:
	close(s);
	return -1;
}

#ifndef XNET_PURE_ONLY
/* --- State ------------------------------------------------------------- */

#define XNET_ASSOC_TIMEOUT_MS	300	/* the tracer waits this long at most */
#define XNET_MAX_IOV		64	/* sendmsg iovecs we rewrite; more: direct */
#define XNET_RECV_SUBST_MAX	16384	/* largest recvfrom buffer moved to the stack */
#define XNET_HDR_MAX		22	/* SOCKS5 UDP header with an IPv6 address */
#define XNET_MAX_DATAGRAM	65536

/* A SOCKS5 UDP association this process (the tracer) keeps open for guest
 * sockets. Closing the control connection ends it in the app.  */
typedef struct {
	int ctl;
	uint16_t socks_port;	/* the entry it was opened with */
	uint16_t relay_port;	/* on 127.0.0.1 */
	int refs;		/* socket entries using it, in this and forked processes */
	bool dns;
} XnetAssoc;

/* A guest UDP socket (AF_INET / AF_INET6, SOCK_DGRAM).  */
typedef struct {
	int fd;
	int family;
	uint16_t lport;			/* its local port once learnt, 0 = not yet */
	bool mapped;			/* connect()ed to the app's UDP listener */
	bool dns;			/* ... in place of the resolver */
	bool no_relay;			/* the relay was unusable from it: direct */
	struct sockaddr_storage peer;	/* where it connect()ed to */
	socklen_t peer_len;
	XnetAssoc *assoc[2];		/* [0] datagrams, [1] DNS */
} XnetUdp;

/* The sockets of one process.  Shared by its threads (CLONE_FILES), copied
 * on fork.  */
typedef struct {
	uint64_t tcp[XNET_MAX_FDS / 64];
	XnetUdp *udp;			/* talloc'd, n_udp used of cap_udp */
	int n_udp, cap_udp;
} XnetFds;

typedef enum { SEND_NONE, SEND_DIRECT, SEND_LPORT, SEND_BIND, SEND_LPORT2, SEND_DATA } SendStep;
typedef enum { RECV_NONE, RECV_FROM, RECV_MSG, RECV_MAPPED_FROM, RECV_MAPPED_MSG } RecvStep;

/* Send scratch, in the tracee's stack (allocated at the original sysenter,
 * valid through its chained syscalls).  */
#define SB_MSG		0
#define SB_IOV		64
#define SB_HDR		(SB_IOV + (1 + XNET_MAX_IOV) * 16)
#define SB_RELAY	(SB_HDR + 24)
#define SB_NAME		(SB_RELAY + 32)
#define SB_NLEN		(SB_NAME + 128)
#define SB_BIND		(SB_NLEN + 8)
#define SB_SIZE		(SB_BIND + 32)

/* Receive scratch.  */
#define RB_NAME		0
#define RB_NLEN		128
#define RB_MSG		136
#define RB_BUF		(RB_MSG + 64)

/* Per tracee (thread).  */
typedef struct {
	XnetFds *fds;

	/* connect() */
	bool pending;			/* this connect() was redirected */
	bool awaiting_name;		/* our chained getsockname() is running */
	bool udp;			/* ... for a UDP socket */
	bool dns;			/* ... to the resolver's port 53 */
	int fd;
	struct sockaddr_storage dest;	/* where the guest wanted to go */
	socklen_t dest_len;
	word_t scratch;			/* tracee memory: sockaddr_storage + socklen_t */
	uint32_t id;

	/* sendto() / sendmsg() through an association */
	SendStep send;
	int send_fd;
	int send_kind;			/* 0 datagrams, 1 DNS */
	int hdr_len;
	word_t sbuf;
	word_t send_flags;

	/* recvfrom() / recvmsg() */
	RecvStep recv;
	int recv_fd;
	bool rsubst;			/* recvfrom's buffer moved to rbuf */
	word_t rbuf;
	word_t g_buf, g_len, g_flags, g_name, g_namelen, g_msg;
	struct msghdr g_hdr;		/* the guest's msghdr, recvmsg */
} XnetTracee;

/* Process-wide: proot is one process, the routes are the app's.  */
static const char *routes_path;
static XnetRoutes routes;
static bool routes_valid;
static struct timespec routes_mtime;
static ino_t routes_ino;
static time_t paused_until;
static time_t alive_until;		/* the listener answered a probe recently */
static time_t assoc_paused_until;	/* the entry refused an association recently */
static uint32_t next_id;
static bool debug_on;

#define DBG(...) do { if (debug_on) fprintf(stderr, "[xnet] " __VA_ARGS__); } while (0)

static void set_tcp(XnetFds *fds, int fd, bool tcp)
{
	if (fd < 0 || fd >= XNET_MAX_FDS)
		return;
	if (tcp)
		fds->tcp[fd / 64] |= (uint64_t) 1 << (fd % 64);
	else
		fds->tcp[fd / 64] &= ~((uint64_t) 1 << (fd % 64));
}

static bool is_tcp(const XnetFds *fds, int fd)
{
	if (fd < 0 || fd >= XNET_MAX_FDS)
		return false;
	return (fds->tcp[fd / 64] >> (fd % 64)) & 1;
}

static void assoc_release(XnetAssoc *a)
{
	if (a == NULL || --a->refs > 0)
		return;
	close(a->ctl);
	DBG("association on relay %u closed\n", a->relay_port);
	free(a);
}

/* Whether the app still holds the association: its control connection is
 * open (the app closes it when the association ends - idle, entry restart)
 * and the entry is still the one in the routes file.  */
static bool assoc_alive(const XnetAssoc *a)
{
	struct pollfd pfd = { .fd = a->ctl, .events = POLLIN };
	char c;
	ssize_t n;

	if (a->socks_port != routes.socks_port)
		return false;
	if (poll(&pfd, 1, 0) <= 0)
		return true;		/* nothing to read: open */
	if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
		return false;
	n = recv(a->ctl, &c, 1, MSG_PEEK | MSG_DONTWAIT);
	return n > 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

static XnetUdp *udp_find(XnetFds *fds, int fd)
{
	int i;

	for (i = 0; i < fds->n_udp; i++)
		if (fds->udp[i].fd == fd)
			return &fds->udp[i];
	return NULL;
}

static void udp_drop(XnetFds *fds, int fd)
{
	XnetUdp *u = udp_find(fds, fd);

	if (u == NULL)
		return;
	if (u->mapped && u->lport != 0 && routes.map_dir[0] != '\0') {
		/* The app keeps a connected socket's destination for as long as
		 * the socket lives.  */
		char path[600];
		snprintf(path, sizeof(path), "%s/u%u", routes.map_dir, u->lport);
		unlink(path);
	}
	assoc_release(u->assoc[0]);
	assoc_release(u->assoc[1]);
	*u = fds->udp[--fds->n_udp];
}

static void udp_add(XnetFds *fds, int fd, int family)
{
	XnetUdp *u;

	udp_drop(fds, fd);
	if (fds->n_udp == fds->cap_udp) {
		int cap = fds->cap_udp ? fds->cap_udp * 2 : 8;
		XnetUdp *grown = talloc_realloc(fds, fds->udp, XnetUdp, cap);
		if (grown == NULL)
			return;		/* untracked: it simply goes direct */
		fds->udp = grown;
		fds->cap_udp = cap;
	}
	u = &fds->udp[fds->n_udp++];
	memset(u, 0, sizeof(*u));
	u->fd = fd;
	u->family = family;
}

/* A process's sockets go with it: release its associations.  */
static int fds_destructor(XnetFds *fds)
{
	int i;

	for (i = 0; i < fds->n_udp; i++) {
		assoc_release(fds->udp[i].assoc[0]);
		assoc_release(fds->udp[i].assoc[1]);
	}
	fds->n_udp = 0;
	return 0;
}

static XnetFds *fds_new(const void *ctx)
{
	XnetFds *fds = talloc_zero(ctx, XnetFds);

	if (fds != NULL)
		talloc_set_destructor(fds, fds_destructor);
	return fds;
}

/* A forked process gets a copy of its parent's descriptor table.  */
static XnetFds *fds_copy(const void *ctx, const XnetFds *from)
{
	XnetFds *fds = fds_new(ctx);
	int i;

	if (fds == NULL)
		return NULL;
	memcpy(fds->tcp, from->tcp, sizeof(fds->tcp));
	if (from->n_udp > 0) {
		fds->udp = talloc_memdup(fds, from->udp, from->n_udp * sizeof(XnetUdp));
		if (fds->udp != NULL) {
			fds->n_udp = fds->cap_udp = from->n_udp;
			for (i = 0; i < fds->n_udp; i++) {
				if (fds->udp[i].assoc[0])
					fds->udp[i].assoc[0]->refs++;
				if (fds->udp[i].assoc[1])
					fds->udp[i].assoc[1]->refs++;
			}
		}
	}
	return fds;
}

/* 127.0.0.1:port as the guest socket's family sees it (v4-mapped for
 * AF_INET6).  */
static socklen_t loopback_addr(int family, uint16_t port, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;
		in6->sin6_family = AF_INET6;
		in6->sin6_addr.s6_addr[10] = 0xff;
		in6->sin6_addr.s6_addr[11] = 0xff;
		in6->sin6_addr.s6_addr[12] = 127;
		in6->sin6_addr.s6_addr[15] = 1;
		in6->sin6_port = htons(port);
		return sizeof(*in6);
	}
	struct sockaddr_in *in = (struct sockaddr_in *) ss;
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	in->sin_port = htons(port);
	return sizeof(*in);
}

/* Whether ss is 127.0.0.1:port (also v4-mapped).  */
static bool is_loopback_port(const struct sockaddr_storage *ss, socklen_t len, uint16_t port)
{
	int family;
	const uint8_t *a;
	uint16_t p;

	if (port == 0 || !sockaddr_parts(ss, len, &family, &a, &p))
		return false;
	unmap(&family, &a);
	return family == AF_INET && a[0] == 127 && a[1] == 0 && a[2] == 0 && a[3] == 1 && p == port;
}

static bool same_addr(const struct sockaddr_storage *a, socklen_t alen,
		      const struct sockaddr_storage *b, socklen_t blen)
{
	int fa, fb;
	const uint8_t *aa, *ab;
	uint16_t pa, pb;

	if (!sockaddr_parts(a, alen, &fa, &aa, &pa) || !sockaddr_parts(b, blen, &fb, &ab, &pb))
		return false;
	unmap(&fa, &aa);
	unmap(&fb, &ab);
	return fa == fb && pa == pb && memcmp(aa, ab, fa == AF_INET ? 4 : 16) == 0;
}

/* Write a source address the way the kernel does: at most *len_p bytes,
 * and the real length into *len_p.  */
static void write_name(Tracee *tracee, word_t name, word_t len_p,
		       const struct sockaddr_storage *ss, socklen_t len)
{
	socklen_t cap = 0;

	if (name == 0 || len_p == 0 || read_data(tracee, &cap, len_p, sizeof(cap)) < 0)
		return;
	(void) write_data(tracee, name, ss, cap < len ? cap : len);
	(void) write_data(tracee, len_p, &len, sizeof(len));
}

/* Reload the routes file when it changed; false when there is none.  */
static bool load_routes(void)
{
	struct stat st;
	char *text;
	int fd;
	ssize_t n;

	if (routes_path == NULL || stat(routes_path, &st) != 0) {
		routes_valid = false;
		return false;
	}
	if (routes_valid && st.st_ino == routes_ino
	    && st.st_mtim.tv_sec == routes_mtime.tv_sec
	    && st.st_mtim.tv_nsec == routes_mtime.tv_nsec)
		return true;

	routes_valid = false;
	if (st.st_size <= 0 || st.st_size > 256 * 1024)
		return false;
	fd = open(routes_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	text = malloc(st.st_size + 1);
	if (text == NULL) {
		close(fd);
		return false;
	}
	n = read(fd, text, st.st_size);
	close(fd);
	if (n <= 0) {
		free(text);
		return false;
	}
	text[n] = '\0';
	routes_valid = xnet_parse_routes(text, &routes) == 0;
	free(text);
	routes_ino = st.st_ino;
	routes_mtime = st.st_mtim;
	/* A new file is a new app state: try the listener again at once. */
	paused_until = 0;
	alive_until = 0;
	DBG("routes %s: port4=%u port6=%u hook=%d exempt=%d\n", routes_valid ? "loaded" : "invalid",
	    routes.port4, routes.port6, routes.n_hook, routes.n_exempt);
	return routes_valid;
}

/* Whether the app's listener accepts a connection now (proot's own probe,
 * not the guest's).  */
static bool listener_alive(int family, uint16_t port)
{
	struct sockaddr_storage ss;
	socklen_t len;
	struct pollfd pfd;
	int s, err = 0;
	socklen_t elen = sizeof(err);
	bool ok = false;

	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &ss;
		in6->sin6_family = AF_INET6;
		in6->sin6_addr = in6addr_loopback;
		in6->sin6_port = htons(port);
		len = sizeof(*in6);
	} else {
		struct sockaddr_in *in = (struct sockaddr_in *) &ss;
		in->sin_family = AF_INET;
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		in->sin_port = htons(port);
		len = sizeof(*in);
	}
	s = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (s < 0)
		return false;
	if (connect(s, (struct sockaddr *) &ss, len) == 0)
		ok = true;
	else if (errno == EINPROGRESS) {
		pfd.fd = s;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, XNET_PROBE_TIMEOUT_MS) == 1
		    && getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0)
			ok = true;
	}
	close(s);
	return ok;
}


/* --- Syscall handling -------------------------------------------------- */

static void on_socket_exit(Tracee *tracee, XnetTracee *x)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	int fd = (int) result;
	int domain = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	int type = (int) peek_reg(tracee, ORIGINAL, SYSARG_2) & 0xf;
	bool inet = domain == AF_INET || domain == AF_INET6;

	if ((long) result < 0)
		return;
	/* Every socket() result is recorded, TCP or not, so an fd number
	 * reused by another socket is never mistaken for an old one.  */
	set_tcp(x->fds, fd, inet && type == SOCK_STREAM);
	if (inet && type == SOCK_DGRAM)
		udp_add(x->fds, fd, domain);
	else
		udp_drop(x->fds, fd);
}

static void on_close_exit(Tracee *tracee, XnetTracee *x)
{
	if ((long) peek_reg(tracee, CURRENT, SYSARG_RESULT) == 0)
		udp_drop(x->fds, (int) peek_reg(tracee, ORIGINAL, SYSARG_1));
}

/* Whether the app's listener is there now (probed at most every
 * XNET_ALIVE_SECONDS, paused for XNET_RETRY_SECONDS after a failure).  */
static bool listener_up(bool v6_listener)
{
	time_t now = time(NULL);

	if (now < paused_until)
		return false;
	if (now >= alive_until) {
		if (!listener_alive(v6_listener ? AF_INET6 : AF_INET, v6_listener ? routes.port6 : routes.port4)) {
			paused_until = now + XNET_RETRY_SECONDS;
			DBG("listener not answering: direct for %ds\n", XNET_RETRY_SECONDS);
			return false;
		}
		alive_until = now + XNET_ALIVE_SECONDS;
	}
	return true;
}

/* connect(): a TCP connection or a UDP socket to a hooked destination (or
 * to the resolver's DNS port) is connected to the app instead. Returns 0,
 * or -ENETUNREACH when the app cannot take it and fail-closed is set.  */
static int on_connect_enter(Tracee *tracee, XnetTracee *x)
{
	int fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	word_t addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
	socklen_t addrlen = (socklen_t) peek_reg(tracee, ORIGINAL, SYSARG_3);
	struct sockaddr_storage ss;
	const uint8_t *ip;
	int family;
	uint16_t port;
	bool tcp, dns, v6_listener;
	XnetUdp *u;

	x->pending = false;
	tcp = is_tcp(x->fds, fd);
	u = tcp ? NULL : udp_find(x->fds, fd);
	if ((!tcp && u == NULL) || addr == 0)
		return 0;
	if (u != NULL)
		u->mapped = false;	/* whatever happens now, not the old peer any more */
	if (!load_routes())
		return 0;
	if (addrlen < sizeof(sa_family_t) || addrlen > sizeof(ss))
		return 0;
	memset(&ss, 0, sizeof(ss));
	if (read_data(tracee, &ss, addr, addrlen) < 0)
		return 0;
	if (!sockaddr_parts(&ss, addrlen, &family, &ip, &port))
		return 0;	/* AF_UNSPEC (dissolve), AF_UNIX, ...: untouched */

	dns = xnet_is_dns(&routes, family, ip, port);
	if (tcp) {
		if (!dns && !xnet_should_forward(&routes, family, ip))
			return 0;
	} else {
		if (routes.udp_port == 0 || (!dns && !xnet_udp_should_forward(&routes, family, ip)))
			return 0;
	}

	/* Fall back to direct while the app's listener is not answering -
	 * unless the user asked for the opposite (DNS always falls back:
	 * the resolver is this device's own).  */
	v6_listener = tcp && family == AF_INET6 && routes.port6 != 0;
	if (!listener_up(v6_listener))
		return routes.fail_closed && !dns ? -ENETUNREACH : 0;

	{
		struct sockaddr_storage to;
		socklen_t to_len;

		if (tcp && family == AF_INET6 && v6_listener) {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &to;
			memset(&to, 0, sizeof(to));
			in6->sin6_family = AF_INET6;
			in6->sin6_addr = in6addr_loopback;
			in6->sin6_port = htons(routes.port6);
			to_len = sizeof(*in6);
		} else
			to_len = loopback_addr(family, tcp ? routes.port4 : routes.udp_port, &to);
		if (set_sysarg_data(tracee, &to, to_len, SYSARG_2) < 0)
			return 0;
		poke_reg(tracee, SYSARG_3, to_len);
		/* Room for the chained getsockname() at exit (memory can only
		 * be taken from the tracee's stack while in sysenter).  */
		x->scratch = alloc_mem(tracee, sizeof(struct sockaddr_storage) + sizeof(socklen_t) + 8);
		if (x->scratch == 0)
			return 0;
	}

	x->pending = true;
	x->udp = !tcp;
	x->dns = dns;
	x->fd = fd;
	x->dest = ss;
	x->dest_len = addrlen;
	x->id = ++next_id;
	DBG("x%x fd %d %s%s -> app listener\n", x->id, fd, tcp ? "tcp" : "udp", dns ? " dns" : "");
	return 0;
}

/* connect() to the listener returned: ask the socket's local port with a
 * getsockname() chained after it; the guest gets connect()'s own result.  */
static void on_connect_exit(Tracee *tracee, XnetTracee *x)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	socklen_t len = sizeof(struct sockaddr_storage);

	x->pending = false;
	if ((long) result == -ECONNREFUSED) {
		/* The listener went away since the probe: run the guest's own
		 * connect() again, unchanged - it goes out directly.  */
		paused_until = time(NULL) + XNET_RETRY_SECONDS;
		alive_until = 0;
		DBG("x%x listener refused: retrying direct, paused %ds\n", x->id, XNET_RETRY_SECONDS);
		(void) restart_original_syscall(tracee);
		return;
	}
	if ((long) result != 0 && (long) result != -EINPROGRESS) {
		DBG("x%x connect to the listener failed: %ld\n", x->id, (long) result);
		return;
	}
	if (write_data(tracee, x->scratch + sizeof(struct sockaddr_storage), &len, sizeof(len)) < 0
	    || register_chained_syscall(tracee, PR_getsockname, x->fd, x->scratch,
					x->scratch + sizeof(struct sockaddr_storage), 0, 0, 0) < 0) {
		DBG("x%x could not chain getsockname\n", x->id);
		return;		/* the app closes a connection it cannot map */
	}
	force_chain_final_result(tracee, result);
	x->awaiting_name = true;
}

/* The chained getsockname() returned: write the destination file - for a
 * UDP socket "u<port>", kept while the socket uses it.  */
static void on_getsockname_exit(Tracee *tracee, XnetTracee *x)
{
	long result = (long) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	struct sockaddr_storage local;
	char ip[INET6_ADDRSTRLEN], path[600], tmp[620], body[200];
	uint16_t port;
	int lport, fd;

	x->awaiting_name = false;
	memset(&local, 0, sizeof(local));
	if (result != 0 || read_data(tracee, &local, x->scratch, sizeof(local)) < 0) {
		DBG("x%x getsockname failed: %ld\n", x->id, result);
		return;
	}
	if (local.ss_family == AF_INET)
		lport = ntohs(((struct sockaddr_in *) &local)->sin_port);
	else if (local.ss_family == AF_INET6)
		lport = ntohs(((struct sockaddr_in6 *) &local)->sin6_port);
	else
		lport = 0;
	if (lport == 0) {
		DBG("x%x no local port\n", x->id);
		return;
	}
	if (x->dest.ss_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *) &x->dest;
		inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
		port = ntohs(in->sin_port);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &x->dest;
		inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
		port = ntohs(in6->sin6_port);
	}
	snprintf(body, sizeof(body), "dst %s %u\nid x%x\n%s", ip, port, x->id, x->dns ? "dns\n" : "");
	snprintf(path, sizeof(path), "%s/%s%d", routes.map_dir, x->udp ? "u" : "", lport);
	snprintf(tmp, sizeof(tmp), "%s/.%s%d.%d", routes.map_dir, x->udp ? "u" : "", lport, (int) getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (write(fd, body, strlen(body)) != (ssize_t) strlen(body)) {
		close(fd);
		unlink(tmp);
		return;
	}
	close(fd);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return;
	}
	if (x->udp) {
		XnetUdp *u = udp_find(x->fds, x->fd);
		if (u != NULL) {
			u->mapped = true;
			u->dns = x->dns;
			u->lport = (uint16_t) lport;
			u->peer = x->dest;
			u->peer_len = x->dest_len;
		}
	}
	DBG("x%x local %s port %d -> %s:%u\n", x->id, x->udp ? "udp" : "tcp", lport, ip, port);
}

/* getpeername() on a connected-to-the-listener socket: the real peer.  */
static void on_getpeername_exit(Tracee *tracee, XnetTracee *x)
{
	XnetUdp *u = udp_find(x->fds, (int) peek_reg(tracee, ORIGINAL, SYSARG_1));

	if (u == NULL || !u->mapped || (long) peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
		return;
	write_name(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), peek_reg(tracee, ORIGINAL, SYSARG_3),
		   &u->peer, u->peer_len);
}

/* --- UDP: unconnected datagrams through a SOCKS5 association ------------ */

/* Finish a send that ran through the relay: the guest sees its own byte
 * count, without our header.  */
static word_t send_result(XnetTracee *x, long r)
{
	return (word_t) (r >= x->hdr_len ? r - x->hdr_len : r);
}

/* The datagram cannot go through the app: direct as before, or fail.  */
static void send_fallback(Tracee *tracee, XnetTracee *x, bool chained)
{
	x->send = SEND_NONE;
	if (routes.fail_closed && x->send_kind == 0) {
		if (chained)
			force_chain_final_result(tracee, (word_t) -ENETUNREACH);
		else
			poke_reg(tracee, SYSARG_RESULT, (word_t) -ENETUNREACH);
		return;
	}
	(void) restart_original_syscall(tracee);
}

/* The socket's local port is known: open its association, then send the
 * prepared sendmsg() as a chained syscall.  */
static void associate_and_send(Tracee *tracee, XnetTracee *x, uint16_t lport, bool chained)
{
	XnetUdp *u = udp_find(x->fds, x->send_fd);
	XnetAssoc *a;
	struct sockaddr_storage relay;
	socklen_t relay_len;
	char user[96];
	uint16_t relay_port = 0;
	int ctl;

	if (u == NULL || lport == 0) {
		send_fallback(tracee, x, chained);
		return;
	}
	u->lport = lport;
	snprintf(user, sizeof(user), "%s~x%x%s", routes.user, ++next_id, x->send_kind ? "~dns" : "");
	ctl = xnet_socks_associate(routes.socks_port, user, routes.pass, lport, XNET_ASSOC_TIMEOUT_MS, &relay_port);
	if (ctl < 0) {
		assoc_paused_until = time(NULL) + XNET_RETRY_SECONDS;
		DBG("x%x association refused or timed out: %s for %ds\n", next_id,
		    routes.fail_closed && x->send_kind == 0 ? "failing" : "direct", XNET_RETRY_SECONDS);
		send_fallback(tracee, x, chained);
		return;
	}
	a = calloc(1, sizeof(*a));
	if (a == NULL) {
		close(ctl);
		send_fallback(tracee, x, chained);
		return;
	}
	a->ctl = ctl;
	a->socks_port = routes.socks_port;
	a->relay_port = relay_port;
	a->refs = 1;
	a->dns = x->send_kind == 1;
	assoc_release(u->assoc[x->send_kind]);
	u->assoc[x->send_kind] = a;
	DBG("x%x %s association: local port %u, relay %u\n", next_id, a->dns ? "dns" : "udp", lport, relay_port);

	relay_len = loopback_addr(u->family, relay_port, &relay);
	if (write_data(tracee, x->sbuf + SB_RELAY, &relay, relay_len) < 0
	    || register_chained_syscall(tracee, PR_sendmsg, x->send_fd, x->sbuf + SB_MSG, x->send_flags, 0, 0, 0) < 0) {
		send_fallback(tracee, x, chained);
		return;
	}
	x->send = SEND_DATA;
}

/* sendto() / sendmsg() with an address on a tracked UDP socket.  */
static int on_send_enter(Tracee *tracee, XnetTracee *x, bool is_sendmsg)
{
	int fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	XnetUdp *u = udp_find(x->fds, fd);
	struct sockaddr_storage dest;
	socklen_t dest_len;
	struct msghdr gm, m;
	struct iovec iov[1 + XNET_MAX_IOV];
	uint8_t hdr[XNET_HDR_MAX + 2];
	const uint8_t *ip;
	word_t name, sbuf;
	int family, kind, n_iov;
	uint16_t port;
	bool dns;

	x->send = SEND_NONE;
	if (u == NULL || u->no_relay)
		return 0;
	if (is_sendmsg) {
		if (read_data(tracee, &gm, peek_reg(tracee, ORIGINAL, SYSARG_2), sizeof(gm)) < 0)
			return 0;
		name = (word_t) gm.msg_name;
		dest_len = gm.msg_namelen;
	} else {
		name = peek_reg(tracee, ORIGINAL, SYSARG_5);
		dest_len = (socklen_t) peek_reg(tracee, ORIGINAL, SYSARG_6);
	}
	if (name == 0 || dest_len < sizeof(sa_family_t) || dest_len > sizeof(dest))
		return 0;	/* no address: a connected socket's own peer */
	if (!load_routes())
		return 0;
	memset(&dest, 0, sizeof(dest));
	if (read_data(tracee, &dest, name, dest_len) < 0
	    || !sockaddr_parts(&dest, dest_len, &family, &ip, &port))
		return 0;

	if (u->mapped) {
		/* An explicit address on a socket connected to the listener:
		 * the peer it connected to goes the same way, anything else
		 * the kernel sends where it was asked.  */
		struct sockaddr_storage to;
		socklen_t to_len;
		if (is_sendmsg || !same_addr(&dest, dest_len, &u->peer, u->peer_len))
			return 0;
		to_len = loopback_addr(u->family, routes.udp_port, &to);
		if (set_sysarg_data(tracee, &to, to_len, SYSARG_5) == 0)
			poke_reg(tracee, SYSARG_6, to_len);
		return 0;
	}

	dns = xnet_is_dns(&routes, family, ip, port);
	if (!dns && !xnet_udp_should_forward(&routes, family, ip))
		return 0;
	kind = dns ? 1 : 0;
	if (u->assoc[kind] != NULL && !assoc_alive(u->assoc[kind])) {
		DBG("fd %d: association on relay %u ended in the app, opening a new one\n", fd, u->assoc[kind]->relay_port);
		assoc_release(u->assoc[kind]);
		u->assoc[kind] = NULL;
	}
	if (routes.socks_port == 0 || routes.pass[0] == '\0' || time(NULL) < assoc_paused_until)
		return routes.fail_closed && !dns ? -ENETUNREACH : 0;

	sbuf = alloc_mem(tracee, SB_SIZE);
	if (sbuf == 0)
		return 0;
	x->hdr_len = xnet_udp_header(hdr, family, ip, port);

	/* iov[0] is our header, then the guest's own buffers - never copied. */
	iov[0].iov_base = (void *) (sbuf + SB_HDR);
	iov[0].iov_len = (size_t) x->hdr_len;
	if (is_sendmsg) {
		if (gm.msg_iovlen > XNET_MAX_IOV)
			return 0;
		n_iov = (int) gm.msg_iovlen;
		if (n_iov > 0 && read_data(tracee, &iov[1], (word_t) gm.msg_iov, n_iov * sizeof(struct iovec)) < 0)
			return 0;
		m = gm;
	} else {
		n_iov = 1;
		iov[1].iov_base = (void *) peek_reg(tracee, ORIGINAL, SYSARG_2);
		iov[1].iov_len = (size_t) peek_reg(tracee, ORIGINAL, SYSARG_3);
		memset(&m, 0, sizeof(m));
	}
	m.msg_name = (void *) (sbuf + SB_RELAY);
	m.msg_namelen = u->family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	m.msg_iov = (struct iovec *) (sbuf + SB_IOV);
	m.msg_iovlen = (size_t) (1 + n_iov);
	if (write_data(tracee, sbuf + SB_HDR, hdr, (word_t) x->hdr_len) < 0
	    || write_data(tracee, sbuf + SB_IOV, iov, (1 + n_iov) * sizeof(struct iovec)) < 0
	    || write_data(tracee, sbuf + SB_MSG, &m, sizeof(m)) < 0)
		return 0;

	x->sbuf = sbuf;
	x->send_fd = fd;
	x->send_kind = kind;
	x->send_flags = peek_reg(tracee, ORIGINAL, is_sendmsg ? SYSARG_3 : SYSARG_4);

	if (u->assoc[kind] != NULL) {
		struct sockaddr_storage relay;
		socklen_t relay_len = loopback_addr(u->family, u->assoc[kind]->relay_port, &relay);
		if (write_data(tracee, sbuf + SB_RELAY, &relay, relay_len) < 0)
			return 0;
		set_sysnum(tracee, PR_sendmsg);
		poke_reg(tracee, SYSARG_1, (word_t) fd);
		poke_reg(tracee, SYSARG_2, sbuf + SB_MSG);
		poke_reg(tracee, SYSARG_3, x->send_flags);
		x->send = SEND_DIRECT;
		return 0;
	}

	/* No association yet: learn the socket's port first (this call
	 * becomes a getsockname(); the datagram goes in a chained sendmsg).  */
	{
		socklen_t nlen = 128;
		if (write_data(tracee, sbuf + SB_NLEN, &nlen, sizeof(nlen)) < 0)
			return 0;
	}
	set_sysnum(tracee, PR_getsockname);
	poke_reg(tracee, SYSARG_1, (word_t) fd);
	poke_reg(tracee, SYSARG_2, sbuf + SB_NAME);
	poke_reg(tracee, SYSARG_3, sbuf + SB_NLEN);
	x->send = SEND_LPORT;
	return 0;
}

static uint16_t read_lport(Tracee *tracee, XnetTracee *x)
{
	struct sockaddr_storage local;
	int family;
	const uint8_t *a;
	uint16_t port = 0;

	memset(&local, 0, sizeof(local));
	if ((long) peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0
	    || read_data(tracee, &local, x->sbuf + SB_NAME, sizeof(local)) < 0
	    || !sockaddr_parts(&local, sizeof(local), &family, &a, &port))
		return 0;
	return port;
}

/* The send's own syscall returned (the sendmsg, or the getsockname it was
 * turned into).  */
static void on_send_exit(Tracee *tracee, XnetTracee *x)
{
	long r = (long) peek_reg(tracee, CURRENT, SYSARG_RESULT);

	if (x->send == SEND_DIRECT) {
		x->send = SEND_NONE;
		if (r >= 0)
			poke_reg(tracee, SYSARG_RESULT, send_result(x, r));
		else if (r == -EINVAL || r == -ENETUNREACH || r == -EAFNOSUPPORT) {
			/* An IPv6-only socket cannot reach the v4 relay: this
			 * one goes direct from now on.  */
			XnetUdp *u = udp_find(x->fds, x->send_fd);
			if (u != NULL && u->family == AF_INET6)
				u->no_relay = true;
		}
		return;
	}
	if (x->send != SEND_LPORT)
		return;
	{
		uint16_t lport = read_lport(tracee, x);
		XnetUdp *u = udp_find(x->fds, x->send_fd);

		if (lport != 0) {
			associate_and_send(tracee, x, lport, false);
			return;
		}
		/* Unbound: bind it to an ephemeral port first, as the kernel
		 * would on its first send, then ask again.  */
		if (u == NULL) {
			send_fallback(tracee, x, false);
			return;
		}
		{
			struct sockaddr_storage any;
			socklen_t any_len = loopback_addr(u->family, 0, &any);
			socklen_t nlen = 128;
			if (u->family == AF_INET)
				((struct sockaddr_in *) &any)->sin_addr.s_addr = htonl(INADDR_ANY);
			else
				memset(&((struct sockaddr_in6 *) &any)->sin6_addr, 0, 16);
			if (write_data(tracee, x->sbuf + SB_BIND, &any, any_len) < 0
			    || write_data(tracee, x->sbuf + SB_NLEN, &nlen, sizeof(nlen)) < 0
			    || register_chained_syscall(tracee, PR_bind, x->send_fd, x->sbuf + SB_BIND, any_len, 0, 0, 0) < 0
			    || register_chained_syscall(tracee, PR_getsockname, x->send_fd, x->sbuf + SB_NAME,
							x->sbuf + SB_NLEN, 0, 0, 0) < 0) {
				send_fallback(tracee, x, false);
				return;
			}
			x->send = SEND_BIND;
		}
	}
}

/* One of the send's chained syscalls returned.  */
static void on_send_chained_exit(Tracee *tracee, XnetTracee *x)
{
	switch (x->send) {
	case SEND_BIND:			/* bind(): the getsockname() follows */
		x->send = SEND_LPORT2;
		return;
	case SEND_LPORT2:
		associate_and_send(tracee, x, read_lport(tracee, x), true);
		return;
	case SEND_DATA: {
		long r = (long) peek_reg(tracee, CURRENT, SYSARG_RESULT);
		x->send = SEND_NONE;
		force_chain_final_result(tracee, r >= 0 ? send_result(x, r) : (word_t) r);
		return;
	}
	default:
		return;
	}
}

/* Which association of u a datagram from (ss, len) came through, or -1.  */
static int relay_index(const XnetUdp *u, const struct sockaddr_storage *ss, socklen_t len)
{
	int k;

	for (k = 0; k < 2; k++)
		if (u->assoc[k] != NULL && is_loopback_port(ss, len, u->assoc[k]->relay_port))
			return k;
	return -1;
}

/* recvfrom() / recvmsg() on a tracked UDP socket: prepare to see where the
 * datagram comes from.  */
static void on_recv_enter(Tracee *tracee, XnetTracee *x, bool is_recvmsg)
{
	int fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	XnetUdp *u = udp_find(x->fds, fd);
	socklen_t nlen = 128;

	x->recv = RECV_NONE;
	if (u == NULL)
		return;
	if (u->mapped) {
		/* Only the source needs rewriting, after the fact; remember how
		 * much room the guest gave for it (the kernel overwrites that).  */
		socklen_t cap = 0;
		word_t len_p;
		if (is_recvmsg) {
			struct msghdr gm;
			if (read_data(tracee, &gm, peek_reg(tracee, ORIGINAL, SYSARG_2), sizeof(gm)) < 0
			    || gm.msg_name == NULL)
				return;
			cap = gm.msg_namelen;
		} else {
			len_p = peek_reg(tracee, ORIGINAL, SYSARG_6);
			if (peek_reg(tracee, ORIGINAL, SYSARG_5) == 0 || len_p == 0
			    || read_data(tracee, &cap, len_p, sizeof(cap)) < 0)
				return;
		}
		x->g_len = cap;
		x->recv = is_recvmsg ? RECV_MAPPED_MSG : RECV_MAPPED_FROM;
		x->recv_fd = fd;
		return;
	}
	if (u->assoc[0] == NULL && u->assoc[1] == NULL)
		return;

	x->recv_fd = fd;
	if (is_recvmsg) {
		struct msghdr sm;
		x->g_msg = peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (read_data(tracee, &x->g_hdr, x->g_msg, sizeof(x->g_hdr)) < 0)
			return;
		x->rbuf = alloc_mem(tracee, RB_BUF);
		if (x->rbuf == 0)
			return;
		sm = x->g_hdr;
		sm.msg_name = (void *) (x->rbuf + RB_NAME);
		sm.msg_namelen = nlen;
		if (write_data(tracee, x->rbuf + RB_MSG, &sm, sizeof(sm)) < 0)
			return;
		poke_reg(tracee, SYSARG_2, x->rbuf + RB_MSG);
		x->recv = RECV_MSG;
		return;
	}

	x->g_buf = peek_reg(tracee, ORIGINAL, SYSARG_2);
	x->g_len = peek_reg(tracee, ORIGINAL, SYSARG_3);
	x->g_flags = peek_reg(tracee, ORIGINAL, SYSARG_4);
	x->g_name = peek_reg(tracee, ORIGINAL, SYSARG_5);
	x->g_namelen = peek_reg(tracee, ORIGINAL, SYSARG_6);
	/* A datagram from the relay carries up to XNET_HDR_MAX more bytes than
	 * the guest asked for: read it into a buffer that has room for them
	 * (bounded: this is the tracee's stack).  */
	x->rsubst = x->g_len <= XNET_RECV_SUBST_MAX;
	x->rbuf = alloc_mem(tracee, RB_BUF + (x->rsubst ? x->g_len + XNET_HDR_MAX : 0));
	if (x->rbuf == 0)
		return;
	if (write_data(tracee, x->rbuf + RB_NLEN, &nlen, sizeof(nlen)) < 0)
		return;
	poke_reg(tracee, SYSARG_5, x->rbuf + RB_NAME);
	poke_reg(tracee, SYSARG_6, x->rbuf + RB_NLEN);
	if (x->rsubst) {
		poke_reg(tracee, SYSARG_2, x->rbuf + RB_BUF);
		poke_reg(tracee, SYSARG_3, x->g_len + XNET_HDR_MAX);
	}
	x->recv = RECV_FROM;
}

static void finish_recvfrom(Tracee *tracee, XnetTracee *x, XnetUdp *u, long r)
{
	struct sockaddr_storage name, src;
	socklen_t name_len = 0, src_len;
	word_t data = x->rsubst ? x->rbuf + RB_BUF : x->g_buf;
	word_t cap = x->rsubst ? x->g_len + XNET_HDR_MAX : x->g_len;
	word_t avail = (word_t) r < cap ? (word_t) r : cap;
	uint8_t *buf = NULL;
	int h = -1;

	memset(&name, 0, sizeof(name));
	if (read_data(tracee, &name_len, x->rbuf + RB_NLEN, sizeof(name_len)) < 0)
		name_len = 0;
	if (name_len > sizeof(name))
		name_len = sizeof(name);
	if (name_len > 0)
		(void) read_data(tracee, &name, x->rbuf + RB_NAME, name_len);

	if (relay_index(u, &name, name_len) >= 0 || x->rsubst) {
		buf = malloc(avail > 0 ? avail : 1);
		if (buf == NULL || (avail > 0 && read_data(tracee, buf, data, avail) < 0)) {
			free(buf);
			return;
		}
	}
	if (buf != NULL && relay_index(u, &name, name_len) >= 0)
		h = xnet_parse_udp_header(buf, avail, u->family, &src, &src_len);

	if (h >= 0) {
		word_t plen = avail - (word_t) h;
		word_t copy = plen < x->g_len ? plen : x->g_len;
		if (copy > 0)
			(void) write_data(tracee, x->g_buf, buf + h, copy);
		poke_reg(tracee, SYSARG_RESULT, (x->g_flags & MSG_TRUNC) ? (word_t) (r - h) : copy);
		write_name(tracee, x->g_name, x->g_namelen, &src, src_len);
	} else {
		if (x->rsubst) {
			word_t copy = avail < x->g_len ? avail : x->g_len;
			if (copy > 0)
				(void) write_data(tracee, x->g_buf, buf, copy);
			poke_reg(tracee, SYSARG_RESULT, (x->g_flags & MSG_TRUNC) ? (word_t) r : copy);
		}
		write_name(tracee, x->g_name, x->g_namelen, &name, name_len);
	}
	free(buf);
}

static void finish_recvmsg(Tracee *tracee, XnetTracee *x, XnetUdp *u, long r)
{
	struct msghdr sm, gm = x->g_hdr;
	struct sockaddr_storage name, src;
	socklen_t name_len, src_len;
	struct iovec iov[XNET_MAX_IOV];
	int n_iov = (int) (gm.msg_iovlen < XNET_MAX_IOV ? gm.msg_iovlen : XNET_MAX_IOV);
	int h = -1, i;

	if (read_data(tracee, &sm, x->rbuf + RB_MSG, sizeof(sm)) < 0)
		return;
	name_len = sm.msg_namelen > sizeof(name) ? sizeof(name) : sm.msg_namelen;
	memset(&name, 0, sizeof(name));
	if (name_len > 0)
		(void) read_data(tracee, &name, x->rbuf + RB_NAME, name_len);

	if (relay_index(u, &name, name_len) >= 0 && n_iov > 0
	    && read_data(tracee, iov, (word_t) gm.msg_iov, n_iov * sizeof(struct iovec)) == 0) {
		/* Gather what the kernel scattered, drop the header, scatter
		 * the payload back.  */
		size_t total = 0, off = 0;
		uint8_t *buf;
		for (i = 0; i < n_iov; i++)
			total += iov[i].iov_len;
		if ((size_t) r < total)
			total = (size_t) r;
		buf = malloc(total > 0 ? total : 1);
		if (buf != NULL) {
			for (i = 0; i < n_iov && off < total; i++) {
				size_t take = iov[i].iov_len < total - off ? iov[i].iov_len : total - off;
				if (read_data(tracee, buf + off, (word_t) iov[i].iov_base, take) < 0)
					break;
				off += take;
			}
			if (off == total)
				h = xnet_parse_udp_header(buf, total, u->family, &src, &src_len);
			if (h >= 0) {
				size_t plen = total - (size_t) h, done = 0;
				for (i = 0; i < n_iov && done < plen; i++) {
					size_t put = iov[i].iov_len < plen - done ? iov[i].iov_len : plen - done;
					(void) write_data(tracee, (word_t) iov[i].iov_base, buf + h + done, put);
					done += put;
				}
				poke_reg(tracee, SYSARG_RESULT, (word_t) (r - h));
			}
			free(buf);
		}
	}
	if (h >= 0) {
		name = src;
		name_len = src_len;
	}
	if (gm.msg_name != NULL) {
		socklen_t put = gm.msg_namelen < name_len ? gm.msg_namelen : name_len;
		(void) write_data(tracee, (word_t) gm.msg_name, &name, put);
	}
	gm.msg_namelen = name_len;
	gm.msg_controllen = sm.msg_controllen;
	gm.msg_flags = sm.msg_flags;
	(void) write_data(tracee, x->g_msg, &gm, sizeof(gm));
}

/* A connected-to-the-listener socket: the kernel reports the listener as
 * the source; the guest must see the peer it connected to.  */
static void finish_mapped_recv(Tracee *tracee, XnetTracee *x, XnetUdp *u, bool is_recvmsg)
{
	socklen_t cap = (socklen_t) x->g_len;
	struct sockaddr_storage name;
	socklen_t len = 0;
	word_t name_p, len_p;

	if (is_recvmsg) {
		struct msghdr gm;
		word_t g_msg = peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (read_data(tracee, &gm, g_msg, sizeof(gm)) < 0 || gm.msg_name == NULL)
			return;
		name_p = (word_t) gm.msg_name;
		len_p = g_msg + offsetof(struct msghdr, msg_namelen);
	} else {
		name_p = peek_reg(tracee, ORIGINAL, SYSARG_5);
		len_p = peek_reg(tracee, ORIGINAL, SYSARG_6);
		if (name_p == 0 || len_p == 0)
			return;
	}
	if (read_data(tracee, &len, len_p, sizeof(len)) < 0)
		return;
	if (len > cap)
		len = cap;		/* what the kernel actually wrote */
	if (len > sizeof(name))
		len = sizeof(name);
	memset(&name, 0, sizeof(name));
	if (read_data(tracee, &name, name_p, len) < 0 || !is_loopback_port(&name, len, routes.udp_port))
		return;
	(void) write_data(tracee, name_p, &u->peer, cap < u->peer_len ? cap : u->peer_len);
	(void) write_data(tracee, len_p, &u->peer_len, sizeof(u->peer_len));
}

static void on_recv_exit(Tracee *tracee, XnetTracee *x)
{
	long r = (long) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	RecvStep step = x->recv;
	XnetUdp *u;

	x->recv = RECV_NONE;
	if (step == RECV_NONE || r < 0)
		return;
	u = udp_find(x->fds, x->recv_fd);
	if (u == NULL)
		return;
	switch (step) {
	case RECV_FROM:
		finish_recvfrom(tracee, x, u, r);
		return;
	case RECV_MSG:
		finish_recvmsg(tracee, x, u, r);
		return;
	case RECV_MAPPED_FROM:
		finish_mapped_recv(tracee, x, u, false);
		return;
	case RECV_MAPPED_MSG:
		finish_mapped_recv(tracee, x, u, true);
		return;
	default:
		return;
	}
}

/* --- Extension --------------------------------------------------------- */

int xnet_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	switch (event) {
	case INITIALIZATION: {
		/* sendto/sendmsg/recvfrom/recvmsg/close are stopped on anyway by
		 * fake_netlink; getpeername is the one this adds.  */
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_socket, FILTER_SYSEXIT },
			{ PR_connect, FILTER_SYSEXIT },
			{ PR_sendto, FILTER_SYSEXIT },
			{ PR_sendmsg, FILTER_SYSEXIT },
			{ PR_recvfrom, FILTER_SYSEXIT },
			{ PR_recvmsg, FILTER_SYSEXIT },
			{ PR_getpeername, FILTER_SYSEXIT },
			{ PR_close, FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		XnetTracee *x = talloc_zero(extension, XnetTracee);
		const char *value = (const char *) data1;

		if (x == NULL)
			return -ENOMEM;
		x->fds = fds_new(x);
		if (x->fds == NULL)
			return -ENOMEM;
		if (value == NULL || value[0] == '\0')
			return -EINVAL;
		routes_path = talloc_strdup(NULL, value);
		{
			const char *dbg = getenv("MINIS_NOFF_DEBUG");
			debug_on = dbg != NULL && dbg[0] != '\0' && dbg[0] != '0';
		}
		extension->config = x;
		extension->filtered_sysnums = filtered_sysnums;
		DBG("initialized, routes file %s\n", routes_path);
		return 0;
	}

	case INHERIT_PARENT:
		return 1;	/* per-thread state, fd table shared or copied */

	case INHERIT_CHILD: {
		Extension *parent = (Extension *) data1;
		XnetTracee *px = parent->config;
		XnetTracee *x = talloc_zero(extension, XnetTracee);

		if (x == NULL)
			return -ENOMEM;
		if ((data2 & CLONE_FILES) != 0)
			x->fds = talloc_reference(x, px->fds);
		else
			x->fds = fds_copy(x, px->fds);
		if (x->fds == NULL)
			return -ENOMEM;
		extension->config = x;
		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		XnetTracee *x = extension->config;
		word_t sysnum;

		if (x == NULL || get_abi(tracee) != ABI_DEFAULT)
			return 0;
		sysnum = get_sysnum(tracee, ORIGINAL);
		x->send = SEND_NONE;
		x->recv = RECV_NONE;
		if (sysnum == PR_connect)
			return on_connect_enter(tracee, x);
		if (sysnum == PR_sendto || sysnum == PR_sendmsg)
			return on_send_enter(tracee, x, sysnum == PR_sendmsg);
		if (sysnum == PR_recvfrom || sysnum == PR_recvmsg)
			on_recv_enter(tracee, x, sysnum == PR_recvmsg);
		return 0;
	}

	case SYSCALL_EXIT_END: {
		Tracee *tracee = TRACEE(extension);
		XnetTracee *x = extension->config;
		word_t sysnum = get_sysnum(tracee, ORIGINAL);

		if (x == NULL)
			return 0;
		if (sysnum == PR_socket)
			on_socket_exit(tracee, x);
		else if (sysnum == PR_connect && x->pending)
			on_connect_exit(tracee, x);
		else if ((sysnum == PR_sendto || sysnum == PR_sendmsg) && x->send != SEND_NONE)
			on_send_exit(tracee, x);
		else if (sysnum == PR_recvfrom || sysnum == PR_recvmsg)
			on_recv_exit(tracee, x);
		else if (sysnum == PR_getpeername)
			on_getpeername_exit(tracee, x);
		else if (sysnum == PR_close)
			on_close_exit(tracee, x);
		return 0;
	}

	case SYSCALL_CHAINED_EXIT: {
		Tracee *tracee = TRACEE(extension);
		XnetTracee *x = extension->config;

		if (x == NULL)
			return 0;
		if (x->awaiting_name)
			on_getsockname_exit(tracee, x);
		else if (x->send != SEND_NONE)
			on_send_chained_exit(tracee, x);
		return 0;
	}

	default:
		return 0;
	}
}
#endif /* XNET_PURE_ONLY */
