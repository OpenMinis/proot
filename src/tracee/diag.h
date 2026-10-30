/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * Minis: evidence lines for the app's diagnostics (FIX-261030-14).
 *
 * proot's stderr is merged into the command's stdout in release builds of
 * the app, so these lines never go to stderr by default: they are appended
 * to the file named by MINIS_PROOT_DIAG_FILE, and mirrored to stderr with a
 * "[proot_diag] " prefix only when MINIS_PROOT_DIAG_STDERR=1 (the app sets
 * that only in DEV_TOOLS builds, whose stderr drain filters the prefix).
 * Neither variable set: nothing happens.
 */

#ifndef TRACEE_DIAG_H
#define TRACEE_DIAG_H

/* Open MINIS_PROOT_DIAG_FILE once, in the tracer, before the first fork:
 * the first tracee writes its line after it is ptraced, when its own
 * open(2) would be translated into the guest rootfs, so it must use this
 * inherited descriptor (O_CLOEXEC: gone at its execve, never the guest's). */
extern void proot_diag_open(void);

/* Write one line (no trailing newline needed). Failures are ignored and a
 * process stops writing after DIAG_MAX_BYTES; callers dedup themselves. */
extern void proot_diag_line(const char *line);

#endif /* TRACEE_DIAG_H */
