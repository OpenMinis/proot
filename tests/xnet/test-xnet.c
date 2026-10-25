/* Host unit test for the xnet extension's pure helpers.
 *
 *   cc -DXNET_PURE_ONLY -I../../src -o /tmp/test-xnet test-xnet.c ../../src/extension/xnet/xnet.c && /tmp/test-xnet
 *
 * (run.sh does exactly that.)  */
#ifndef XNET_PURE_ONLY
#define XNET_PURE_ONLY
#endif
#include "../../src/extension/xnet/xnet.c"

#include <assert.h>
#include <sys/wait.h>

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static bool fwd(const XnetRoutes *r, const char *ip)
{
	uint8_t a[16];
	if (inet_pton(AF_INET, ip, a) == 1)
		return xnet_should_forward(r, AF_INET, a);
	inet_pton(AF_INET6, ip, a);
	return xnet_should_forward(r, AF_INET6, a);
}

/* A fake SOCKS5 entry in a child process: checks the greeting, the
 * credentials (refuses when refuse), the ASSOCIATE request declaring
 * 127.0.0.1:5000, and answers relay port 4321. Returns what
 * xnet_socks_associate returned for the relay port, or -1.  */
static int socks_associate_test(const char *user, const char *pass, int refuse)
{
	struct sockaddr_in a;
	socklen_t al = sizeof(a);
	int ls = socket(AF_INET, SOCK_STREAM, 0), ctl;
	uint16_t relay = 0;
	pid_t pid;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(ls, (struct sockaddr *) &a, sizeof(a));
	listen(ls, 1);
	getsockname(ls, (struct sockaddr *) &a, &al);
	pid = fork();
	if (pid == 0) {
		uint8_t b[600];
		int c = accept(ls, NULL, NULL);
		ssize_t n;
		n = read(c, b, 3);
		if (n != 3 || b[0] != 5 || b[2] != 2)
			_exit(1);
		write(c, "\x05\x02", 2);
		n = read(c, b, sizeof(b));
		if (n < 3 || b[0] != 1 || b[1] != strlen(user) || memcmp(b + 2, user, b[1]) != 0)
			_exit(2);
		write(c, refuse ? "\x01\x01" : "\x01\x00", 2);
		if (refuse)
			_exit(0);
		n = read(c, b, 10);
		if (n != 10 || b[1] != 3 || b[4] != 127 || b[7] != 1 || (b[8] << 8 | b[9]) != 5000)
			_exit(3);
		write(c, "\x05\x00\x00\x01\x7f\x00\x00\x01\x10\xe1", 10);	/* 127.0.0.1:4321 */
		read(c, b, 1);		/* until the control connection closes */
		_exit(0);
	}
	close(ls);
	ctl = xnet_socks_associate(ntohs(a.sin_port), user, pass, 5000, 1000, &relay);
	if (ctl >= 0)
		close(ctl);
	{
		int st = 0;
		waitpid(pid, &st, 0);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}
	return ctl >= 0 ? relay : -1;
}

int main(void)
{
	static XnetRoutes r;
	XnetPrefix p;

	/* Prefix parsing. */
	CHECK(xnet_parse_prefix("100.64.0.0/10", &p) && p.family == AF_INET && p.bits == 10);
	CHECK(xnet_parse_prefix("fd7a:115c:a1e0::/48", &p) && p.family == AF_INET6 && p.bits == 48);
	CHECK(xnet_parse_prefix("100.64.0.42", &p) && p.bits == 32);
	CHECK(!xnet_parse_prefix("100.64.0.0/33", &p));
	CHECK(!xnet_parse_prefix("not-an-ip", &p));
	CHECK(!xnet_parse_prefix("10.0.0.0/", &p));

	/* A file without a listener or map dir forwards nothing. */
	CHECK(xnet_parse_routes("hook 0.0.0.0/0\n", &r) == -1);
	CHECK(xnet_parse_routes("port4 4000\nhook 0.0.0.0/0\n", &r) == -1);

	/* Tailnet only (a direct shell route with Tailscale up). */
	CHECK(xnet_parse_routes(
		"# written by MinisApp\n"
		"port4 41000\nport6 41001\nmap /data/x/map\n"
		"hook 100.64.0.0/10\nhook fd7a:115c:a1e0::/48\n"
		"exempt 10.1.1.0/24\n", &r) == 0);
	CHECK(r.port4 == 41000 && r.port6 == 41001 && strcmp(r.map_dir, "/data/x/map") == 0);
	CHECK(r.n_hook == 2 && r.n_exempt == 1);
	CHECK(fwd(&r, "100.64.0.42"));
	CHECK(fwd(&r, "fd7a:115c:a1e0::1"));
	CHECK(fwd(&r, "::ffff:100.64.0.42"));		/* v4-mapped matched as v4 */
	CHECK(!fwd(&r, "93.184.216.34"));			/* public: direct */
	CHECK(!fwd(&r, "10.1.1.5"));				/* not hooked */

	/* Everything (exit node / proxy route) minus the LAN. */
	CHECK(xnet_parse_routes("port4 1\nmap /m\nhook 0.0.0.0/0\nhook ::/0\nexempt 10.1.1.0/24\nexempt 192.168.0.0/16\n", &r) == 0);
	CHECK(fwd(&r, "93.184.216.34"));
	CHECK(fwd(&r, "2606:2800:220:1::1"));
	CHECK(!fwd(&r, "10.1.1.5"));				/* exempt LAN */
	CHECK(!fwd(&r, "192.168.3.4"));
	CHECK(fwd(&r, "10.1.2.5"));				/* outside the exempt /24 */
	/* Never forwarded, whatever the lists say. */
	CHECK(!fwd(&r, "127.0.0.1"));
	CHECK(!fwd(&r, "127.5.6.7"));
	CHECK(!fwd(&r, "0.0.0.0"));
	CHECK(!fwd(&r, "224.0.0.251"));
	CHECK(!fwd(&r, "169.254.1.1"));
	CHECK(!fwd(&r, "255.255.255.255"));
	CHECK(!fwd(&r, "::1"));
	CHECK(!fwd(&r, "::"));
	CHECK(!fwd(&r, "ff02::fb"));
	CHECK(!fwd(&r, "fe80::1"));
	CHECK(!fwd(&r, "::ffff:127.0.0.1"));

	/* A non-byte-aligned prefix. */
	CHECK(xnet_parse_routes("port4 1\nmap /m\nhook 100.64.0.0/10\n", &r) == 0);
	CHECK(fwd(&r, "100.127.255.255"));
	CHECK(!fwd(&r, "100.128.0.1"));
	CHECK(!fwd(&r, "100.63.255.255"));

	/* [FEAT-261021-23] Stage 2: UDP and DNS. */
	CHECK(xnet_parse_routes(
		"port4 41000\nmap /m\nhook 0.0.0.0/0\nudpport 41002\nsocks 41003\n"
		"pass s3cret\nudphook 100.64.0.0/10\nresolver 198.18.0.4\nresolver fd00::53\n"
		"dns 1\nfailclosed 1\nexempt 10.1.1.0/24\n", &r) == 0);
	CHECK(r.udp_port == 41002 && r.socks_port == 41003 && strcmp(r.pass, "s3cret") == 0);
	CHECK(strcmp(r.user, "shell") == 0);			/* default tag */
	CHECK(r.n_udp_hook == 1 && r.n_resolver == 2 && r.dns && r.fail_closed);
	{
		uint8_t a[16];
		inet_pton(AF_INET, "100.64.0.42", a);
		CHECK(xnet_udp_should_forward(&r, AF_INET, a));
		inet_pton(AF_INET, "93.184.216.34", a);
		CHECK(!xnet_udp_should_forward(&r, AF_INET, a));	/* TCP hooks it, UDP not (proxy route) */
		CHECK(xnet_should_forward(&r, AF_INET, a));
		inet_pton(AF_INET, "198.18.0.4", a);
		CHECK(xnet_is_dns(&r, AF_INET, a, 53));
		CHECK(!xnet_is_dns(&r, AF_INET, a, 5353));
		inet_pton(AF_INET6, "::ffff:198.18.0.4", a);
		CHECK(xnet_is_dns(&r, AF_INET6, a, 53));		/* v4-mapped */
		inet_pton(AF_INET6, "fd00::53", a);
		CHECK(xnet_is_dns(&r, AF_INET6, a, 53));
		inet_pton(AF_INET, "8.8.8.8", a);
		CHECK(!xnet_is_dns(&r, AF_INET, a, 53));		/* not the shell's resolver */
	}
	/* "dns 0" (Tailscale down): the resolver is not the app's. */
	CHECK(xnet_parse_routes("port4 1\nmap /m\nresolver 198.18.0.4\ndns 0\n", &r) == 0);
	{
		uint8_t a[4];
		inet_pton(AF_INET, "198.18.0.4", a);
		CHECK(!xnet_is_dns(&r, AF_INET, a, 53));
		CHECK(!xnet_udp_should_forward(&r, AF_INET, a));	/* no udp listener at all */
	}

	/* SOCKS5 UDP header round trip, in both socket families. */
	{
		uint8_t h[32], a4[4], a6[16];
		struct sockaddr_storage src;
		socklen_t len;
		inet_pton(AF_INET, "100.64.0.42", a4);
		CHECK(xnet_udp_header(h, AF_INET, a4, 53) == 10);
		CHECK(h[3] == 1 && h[8] == 0 && h[9] == 53);
		CHECK(xnet_parse_udp_header(h, 10, AF_INET, &src, &len) == 10);
		CHECK(len == sizeof(struct sockaddr_in) && ((struct sockaddr_in *) &src)->sin_port == htons(53)
		      && memcmp(&((struct sockaddr_in *) &src)->sin_addr, a4, 4) == 0);
		CHECK(xnet_parse_udp_header(h, 10, AF_INET6, &src, &len) == 10);	/* v4 to a v6 socket */
		CHECK(len == sizeof(struct sockaddr_in6) && src.ss_family == AF_INET6
		      && ((struct sockaddr_in6 *) &src)->sin6_addr.s6_addr[10] == 0xff
		      && memcmp(&((struct sockaddr_in6 *) &src)->sin6_addr.s6_addr[12], a4, 4) == 0);
		inet_pton(AF_INET6, "fd7a:115c:a1e0::1", a6);
		CHECK(xnet_udp_header(h, AF_INET6, a6, 443) == 22);
		CHECK(xnet_parse_udp_header(h, 22, AF_INET6, &src, &len) == 22
		      && ((struct sockaddr_in6 *) &src)->sin6_port == htons(443));
		inet_pton(AF_INET6, "::ffff:100.64.0.42", a6);
		CHECK(xnet_udp_header(h, AF_INET6, a6, 1) == 10);		/* v4-mapped sent as IPv4 */
		CHECK(xnet_parse_udp_header(h, 9, AF_INET, &src, &len) == -1);	/* short */
		h[2] = 1;
		CHECK(xnet_parse_udp_header(h, 10, AF_INET, &src, &len) == -1);	/* fragment */
		h[2] = 0;
		h[3] = 3;
		CHECK(xnet_parse_udp_header(h, 10, AF_INET, &src, &len) == -1);	/* domain: never from the relay */
	}

	/* The tracer's UDP ASSOCIATE against a fake entry. */
	CHECK(socks_associate_test("shell~x1", "pw", 0) == 4321);
	CHECK(socks_associate_test("shell~x1", "wrong", 1) == -1);	/* auth refused */
	CHECK(xnet_socks_associate(1, "shell", "pw", 5000, 200, &(uint16_t){0}) == -1);	/* nothing listening */

	if (failures == 0)
		printf("xnet helpers: all checks passed\n");
	return failures == 0 ? 0 : 1;
}
