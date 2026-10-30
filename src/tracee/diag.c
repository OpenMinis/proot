/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * Minis: evidence lines for the app's diagnostics (FIX-261030-14).
 * See tracee/diag.h for why this is a file and not stderr.
 */

#include <fcntl.h>      /* open(2), O_*, */
#include <unistd.h>     /* write(2), close(2), */
#include <stdlib.h>     /* getenv(3), */
#include <string.h>     /* strlen(3), strcmp(3), */
#include <errno.h>      /* errno, */

#include "tracee/diag.h"

/* Stop after this much per process, so a bug can never flood the file. */
#define DIAG_MAX_BYTES 8192

static size_t diag_written = 0;
static int diag_fd = -1;

void proot_diag_open(void)
{
	const char *path = getenv("MINIS_PROOT_DIAG_FILE");
	int saved_errno = errno;

	if (diag_fd >= 0 || path == NULL || path[0] == '\0')
		return;
	diag_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	errno = saved_errno;
}

static void write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return;
		buf += n;
		len -= (size_t) n;
	}
}

void proot_diag_line(const char *line)
{
	const char *mirror = getenv("MINIS_PROOT_DIAG_STDERR");
	size_t len;
	int saved_errno = errno;

	if (line == NULL)
		return;
	len = strlen(line);
	if (diag_written + len + 1 > DIAG_MAX_BYTES)
		return;
	diag_written += len + 1;

	if (diag_fd >= 0) {
		write_all(diag_fd, line, len);
		write_all(diag_fd, "\n", 1);
	}

	if (mirror != NULL && strcmp(mirror, "1") == 0) {
		write_all(2, "[proot_diag] ", 13);
		write_all(2, line, len);
		write_all(2, "\n", 1);
	}

	/* Never disturb the caller's errno (the child reads it right after). */
	errno = saved_errno;
}
