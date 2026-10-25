/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * xnet: transparent forwarding of guest TCP connections to the host app's
 * network router (MinisApp's nethub), for programs that ignore proxy
 * variables (ssh, nc, database clients, static binaries).
 *
 * See xnet.c for the protocol and the rules.
 */

#ifndef XNET_H
#define XNET_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "extension/extension.h"

/* Callback for the PRoot extension machinery.  */
extern int xnet_callback(Extension *extension, ExtensionEvent event,
			 intptr_t data1, intptr_t data2);

/* --- Pure helpers, exposed for the unit test (tests/test-xnet.c). --- */

#define XNET_MAX_PREFIXES 512

typedef struct {
	int family;		/* AF_INET or AF_INET6 */
	uint8_t addr[16];	/* network byte order; IPv4 in the first 4 */
	int bits;
} XnetPrefix;

#define XNET_MAX_RESOLVERS 8

typedef struct {
	uint16_t port4;		/* app listener on 127.0.0.1, 0 = none */
	uint16_t port6;		/* app listener on ::1, 0 = none */
	char map_dir[512];	/* where a forwarded connection's destination is written */
	XnetPrefix hook[XNET_MAX_PREFIXES];
	int n_hook;
	XnetPrefix exempt[XNET_MAX_PREFIXES];
	int n_exempt;
	/* [FEAT-261021-23] stage 2: UDP and DNS */
	uint16_t udp_port;	/* app UDP listener on 127.0.0.1 (connected sockets), 0 = none */
	uint16_t socks_port;	/* app SOCKS5 entry on 127.0.0.1 (UDP ASSOCIATE), 0 = none */
	char user[64];		/* the entry's username (the policy tag), "shell" by default */
	char pass[128];		/* the entry's password */
	XnetPrefix udp_hook[XNET_MAX_PREFIXES];
	int n_udp_hook;
	XnetPrefix resolver[XNET_MAX_RESOLVERS];	/* the shell's nameservers */
	int n_resolver;
	bool dns;		/* their port 53 is the app's to answer */
	bool fail_closed;	/* never fall back to direct for a hooked destination */
} XnetRoutes;

/* Parse a routes file's text (see xnet.c). Returns 0, or -1 when it names
 * no listener or no map directory (nothing can be forwarded).  */
extern int xnet_parse_routes(const char *text, XnetRoutes *out);

/* Parse "a.b.c.d/n", "x::y/n" or a bare address.  */
extern bool xnet_parse_prefix(const char *s, XnetPrefix *out);

/* Whether a connection to (family, addr) goes to the app: inside a hook
 * prefix, outside every exempt prefix, and never loopback, unspecified,
 * multicast or link-local. An IPv4-mapped IPv6 address is matched as IPv4.  */
extern bool xnet_should_forward(const XnetRoutes *r, int family, const uint8_t *addr);

/* The same for a UDP datagram (udphook instead of hook).  */
extern bool xnet_udp_should_forward(const XnetRoutes *r, int family, const uint8_t *addr);

/* Whether (family, addr, port) is the shell's resolver's DNS port and the
 * app answers it.  */
extern bool xnet_is_dns(const XnetRoutes *r, int family, const uint8_t *addr, uint16_t port);

/* SOCKS5 UDP header: build one (returns 10 or 22), or parse one into the
 * source the guest must see (returns the header length, or -1).  */
extern int xnet_udp_header(uint8_t *out, int family, const uint8_t *addr, uint16_t port);
extern int xnet_parse_udp_header(const uint8_t *in, size_t n, int sock_family,
				 struct sockaddr_storage *src, socklen_t *src_len);

/* Open a UDP association with the app's entry; returns the control fd and
 * the relay port, or -1.  */
extern int xnet_socks_associate(uint16_t port, const char *user, const char *pass,
				uint16_t client_port, int timeout_ms, uint16_t *relay_port);

#endif /* XNET_H */
