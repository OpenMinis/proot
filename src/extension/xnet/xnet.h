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

typedef struct {
	uint16_t port4;		/* app listener on 127.0.0.1, 0 = none */
	uint16_t port6;		/* app listener on ::1, 0 = none */
	char map_dir[512];	/* where a forwarded connection's destination is written */
	XnetPrefix hook[XNET_MAX_PREFIXES];
	int n_hook;
	XnetPrefix exempt[XNET_MAX_PREFIXES];
	int n_exempt;
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

#endif /* XNET_H */
