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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#else
/* Host unit test (tests/xnet/test-xnet.c): the pure helpers only.  */
#include <stdbool.h>
#include <stdint.h>
#define XNET_MAX_PREFIXES 512
typedef struct { int family; uint8_t addr[16]; int bits; } XnetPrefix;
typedef struct {
	uint16_t port4, port6; char map_dir[512];
	XnetPrefix hook[XNET_MAX_PREFIXES]; int n_hook;
	XnetPrefix exempt[XNET_MAX_PREFIXES]; int n_exempt;
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
			}
		}
		line = nl ? nl + 1 : NULL;
	}
	if (out->port4 == 0 || out->map_dir[0] == '\0')
		return -1;
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

#ifndef XNET_PURE_ONLY
/* --- State ------------------------------------------------------------- */

/* Which fds of one process are TCP sockets created by socket().  Shared by
 * the threads of a process (CLONE_FILES), copied on fork.  */
typedef struct {
	uint64_t tcp[XNET_MAX_FDS / 64];
} XnetFds;

/* Per tracee (thread).  */
typedef struct {
	XnetFds *fds;
	bool pending;			/* this connect() was redirected */
	bool awaiting_name;		/* our chained getsockname() is running */
	int fd;
	struct sockaddr_storage dest;	/* where the guest wanted to go */
	word_t scratch;			/* tracee memory: sockaddr_storage + socklen_t */
	uint32_t id;
} XnetTracee;

/* Process-wide: proot is one process, the routes are the app's.  */
static const char *routes_path;
static XnetRoutes routes;
static bool routes_valid;
static struct timespec routes_mtime;
static ino_t routes_ino;
static time_t paused_until;
static time_t alive_until;		/* the listener answered a probe recently */
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

	if ((long) result < 0)
		return;
	/* Every socket() result is recorded, TCP or not, so an fd number
	 * reused by a UDP socket is never mistaken for an old TCP one.  */
	set_tcp(x->fds, fd, (domain == AF_INET || domain == AF_INET6) && type == SOCK_STREAM);
}

static void on_connect_enter(Tracee *tracee, XnetTracee *x)
{
	int fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	word_t addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
	socklen_t addrlen = (socklen_t) peek_reg(tracee, ORIGINAL, SYSARG_3);
	struct sockaddr_storage ss;
	const uint8_t *ip;
	int family;
	bool v6_listener;
	time_t now;

	x->pending = false;
	if (!is_tcp(x->fds, fd) || addr == 0 || !load_routes())
		return;
	if (addrlen < sizeof(struct sockaddr_in) || addrlen > sizeof(ss))
		return;
	memset(&ss, 0, sizeof(ss));
	if (read_data(tracee, &ss, addr, addrlen) < 0)
		return;

	family = ss.ss_family;
	if (family == AF_INET)
		ip = (const uint8_t *) &((struct sockaddr_in *) &ss)->sin_addr;
	else if (family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6))
		ip = (const uint8_t *) &((struct sockaddr_in6 *) &ss)->sin6_addr;
	else
		return;
	if (!xnet_should_forward(&routes, family, ip))
		return;

	/* Fall back to direct while the app's listener is not answering. */
	now = time(NULL);
	if (now < paused_until)
		return;
	v6_listener = family == AF_INET6 && routes.port6 != 0;
	if (now >= alive_until) {
		if (!listener_alive(v6_listener ? AF_INET6 : AF_INET, v6_listener ? routes.port6 : routes.port4)) {
			paused_until = now + XNET_RETRY_SECONDS;
			DBG("listener not answering: direct for %ds\n", XNET_RETRY_SECONDS);
			return;
		}
		alive_until = now + XNET_ALIVE_SECONDS;
	}

	{
		struct sockaddr_storage to;
		socklen_t to_len;

		memset(&to, 0, sizeof(to));
		if (family == AF_INET) {
			struct sockaddr_in *in = (struct sockaddr_in *) &to;
			in->sin_family = AF_INET;
			in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			in->sin_port = htons(routes.port4);
			to_len = sizeof(*in);
		} else {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &to;
			in6->sin6_family = AF_INET6;
			if (v6_listener) {
				in6->sin6_addr = in6addr_loopback;
				in6->sin6_port = htons(routes.port6);
			} else {
				/* ::ffff:127.0.0.1 */
				in6->sin6_addr.s6_addr[10] = 0xff;
				in6->sin6_addr.s6_addr[11] = 0xff;
				in6->sin6_addr.s6_addr[12] = 127;
				in6->sin6_addr.s6_addr[15] = 1;
				in6->sin6_port = htons(routes.port4);
			}
			to_len = sizeof(*in6);
		}
		if (set_sysarg_data(tracee, &to, to_len, SYSARG_2) < 0)
			return;
		poke_reg(tracee, SYSARG_3, to_len);
		/* Room for the chained getsockname() at exit (memory can only
		 * be taken from the tracee's stack while in sysenter).  */
		x->scratch = alloc_mem(tracee, sizeof(struct sockaddr_storage) + sizeof(socklen_t) + 8);
		if (x->scratch == 0)
			return;
	}

	x->pending = true;
	x->fd = fd;
	x->dest = ss;
	x->id = ++next_id;
	DBG("x%x fd %d -> app listener\n", x->id, fd);
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

/* The chained getsockname() returned: write the destination file.  */
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
	snprintf(body, sizeof(body), "dst %s %u\nid x%x\n", ip, port, x->id);
	snprintf(path, sizeof(path), "%s/%d", routes.map_dir, lport);
	snprintf(tmp, sizeof(tmp), "%s/.%d.%d", routes.map_dir, lport, (int) getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (write(fd, body, strlen(body)) != (ssize_t) strlen(body)) {
		close(fd);
		unlink(tmp);
		return;
	}
	close(fd);
	if (rename(tmp, path) != 0)
		unlink(tmp);
	DBG("x%x local port %d -> %s:%u\n", x->id, lport, ip, port);
}

/* --- Extension --------------------------------------------------------- */

int xnet_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	switch (event) {
	case INITIALIZATION: {
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_socket, FILTER_SYSEXIT },
			{ PR_connect, FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		XnetTracee *x = talloc_zero(extension, XnetTracee);
		const char *value = (const char *) data1;

		if (x == NULL)
			return -ENOMEM;
		x->fds = talloc_zero(x, XnetFds);
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
		else {
			x->fds = talloc_zero(x, XnetFds);
			if (x->fds != NULL)
				memcpy(x->fds, px->fds, sizeof(*x->fds));
		}
		if (x->fds == NULL)
			return -ENOMEM;
		extension->config = x;
		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		XnetTracee *x = extension->config;

		if (x != NULL && get_sysnum(tracee, ORIGINAL) == PR_connect)
			on_connect_enter(tracee, x);
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
		return 0;
	}

	case SYSCALL_CHAINED_EXIT: {
		Tracee *tracee = TRACEE(extension);
		XnetTracee *x = extension->config;

		if (x != NULL && x->awaiting_name)
			on_getsockname_exit(tracee, x);
		return 0;
	}

	default:
		return 0;
	}
}
#endif /* XNET_PURE_ONLY */
