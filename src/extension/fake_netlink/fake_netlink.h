/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * fake_netlink: emulate a rtnetlink (AF_NETLINK/NETLINK_ROUTE) socket so
 * that programs which enumerate network interfaces keep working inside an
 * unprivileged Android app sandbox, where the real kernel refuses to create
 * the socket at all.
 *
 * See fake_netlink.c for the full rationale.
 */

#ifndef FAKE_NETLINK_H
#define FAKE_NETLINK_H

#include "extension/extension.h"

/* Callback for the PRoot extension machinery.  */
extern int fake_netlink_callback(Extension *extension, ExtensionEvent event,
				 intptr_t data1, intptr_t data2);

#endif /* FAKE_NETLINK_H */
