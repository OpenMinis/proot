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

int main(void)
{
	static XnetRoutes r;
	XnetPrefix p;

	/* Prefix parsing. */
	CHECK(xnet_parse_prefix("100.64.0.0/10", &p) && p.family == AF_INET && p.bits == 10);
	CHECK(xnet_parse_prefix("fd7a:115c:a1e0::/48", &p) && p.family == AF_INET6 && p.bits == 48);
	CHECK(xnet_parse_prefix("100.78.206.85", &p) && p.bits == 32);
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
	CHECK(fwd(&r, "100.78.206.85"));
	CHECK(fwd(&r, "fd7a:115c:a1e0::1"));
	CHECK(fwd(&r, "::ffff:100.78.206.85"));		/* v4-mapped matched as v4 */
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

	/* /proc parsing. */
	CHECK(xnet_socket_inode("socket:[123456]") == 123456);
	CHECK(xnet_socket_inode("pipe:[1]") == 0);
	CHECK(xnet_socket_inode("/dev/null") == 0);
	{
		const char *tcp =
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			"   0: 0100007F:A0C8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 777 1 0000000000000000 100 0 0 10 0\n"
			"   1: 0100007F:D431 0100007F:A028 02 00000000:00000000 01:00000064 00000000 10123        0 123456 1 0000000000000000 100 0 0 10 0\n";
		CHECK(xnet_local_port(tcp, 123456) == 0xD431);
		CHECK(xnet_local_port(tcp, 777) == 0xA0C8);
		CHECK(xnet_local_port(tcp, 999) == 0);
		const char *tcp6 =
			"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			"   0: 0000000000000000FFFF00000100007F:C001 0000000000000000FFFF00000100007F:A028 01 00000000:00000000 00:00000000 00000000 10123        0 4242 1 0000000000000000 20 4 30 10 -1\n";
		CHECK(xnet_local_port(tcp6, 4242) == 0xC001);
	}

	if (failures == 0)
		printf("xnet helpers: all checks passed\n");
	return failures == 0 ? 0 : 1;
}
