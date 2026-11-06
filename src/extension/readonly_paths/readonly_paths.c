/*
 * readonly_paths: refuse every write into a set of host directories with
 * EROFS, as a read-only mount would.
 *
 * Why an extension and not permission bits: with -0, fake_id0 simulates
 * CAP_DAC_OVERRIDE by chmod-ing every path component to rwx while a syscall
 * is translated (override_permissions), so a 0444 file in a 0555 directory
 * is as writable as any other, and a real chmod by the tracee succeeds too
 * because the files belong to the tracer's own uid. Minis ships a read-only
 * manual that the guest must not change, so the guard has to sit in the
 * tracer.
 *
 * Enabled by PROOT_READONLY_PATHS, a ':'-separated list of absolute HOST
 * paths (the host side of a binding). Each one and everything under it is
 * protected:
 *  - HOST_PATH: a protected component is not handed to fake_id0's
 *    override_permissions (this extension is initialized last, so it is
 *    first in the list and its non-zero return stops the notification).
 *  - SYSCALL_ENTER_END: after translation every path argument is an
 *    absolute host path; a mutating syscall naming a protected path (or an
 *    fd opened on one) fails with -EROFS before it reaches the kernel or
 *    any later extension (link2symlink moves files in its own handler).
 */

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "syscall/seccomp.h"
#include "path/path.h"

#define MAX_PREFIXES 8

typedef struct {
	int count;
	char *prefix[MAX_PREFIXES];
	size_t length[MAX_PREFIXES];
} Config;

static bool is_protected(const Config *config, const char *path)
{
	int i;

	for (i = 0; i < config->count; i++) {
		size_t n = config->length[i];
		if (strncmp(path, config->prefix[i], n) == 0 && (path[n] == '\0' || path[n] == '/'))
			return true;
	}
	return false;
}

/* True when the path in @sysarg (CURRENT, already translated) is protected.
 * A NULL pointer (utimensat on a fd) is not a path.  */
static bool arg_protected(const Tracee *tracee, const Config *config, Reg sysarg)
{
	char path[PATH_MAX];
	word_t address = peek_reg(tracee, CURRENT, sysarg);

	if (address == 0)
		return false;
	if (read_path(tracee, path, address) < 0)
		return false;
	return is_protected(config, path);
}

static bool fd_protected(const Tracee *tracee, const Config *config, Reg sysarg)
{
	char path[PATH_MAX];
	int fd = (int) peek_reg(tracee, ORIGINAL, sysarg);

	if (fd < 0)
		return false;
	if (readlink_proc_pid_fd(tracee->pid, fd, path) < 0)
		return false;
	return is_protected(config, path);
}

static bool opens_for_writing(word_t flags)
{
	return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

static int handle_sysenter_end(const Tracee *tracee, const Config *config)
{
	bool hit = false;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_open:
		hit = opens_for_writing(peek_reg(tracee, ORIGINAL, SYSARG_2)) && arg_protected(tracee, config, SYSARG_1);
		break;
	case PR_openat:
		hit = opens_for_writing(peek_reg(tracee, ORIGINAL, SYSARG_3)) && arg_protected(tracee, config, SYSARG_2);
		break;

	case PR_creat:
	case PR_mkdir:
	case PR_mknod:
	case PR_unlink:
	case PR_rmdir:
	case PR_chmod:
	case PR_chown:
	case PR_chown32:
	case PR_lchown:
	case PR_lchown32:
	case PR_truncate:
	case PR_truncate64:
	case PR_utime:
	case PR_utimes:
	case PR_setxattr:
	case PR_lsetxattr:
	case PR_removexattr:
	case PR_lremovexattr:
		hit = arg_protected(tracee, config, SYSARG_1);
		break;

	case PR_mkdirat:
	case PR_mknodat:
	case PR_unlinkat:
	case PR_fchmodat:
	case PR_fchownat:
	case PR_futimesat:
		hit = arg_protected(tracee, config, SYSARG_2);
		break;

	case PR_utimensat:
		/* A NULL path means the dirfd itself.  */
		hit = peek_reg(tracee, CURRENT, SYSARG_2) != 0
			? arg_protected(tracee, config, SYSARG_2)
			: fd_protected(tracee, config, SYSARG_1);
		break;

	case PR_rename:
	case PR_link:
		hit = arg_protected(tracee, config, SYSARG_1) || arg_protected(tracee, config, SYSARG_2);
		break;
	case PR_symlink:
		hit = arg_protected(tracee, config, SYSARG_2);
		break;
	case PR_renameat:
	case PR_renameat2:
	case PR_linkat:
		hit = arg_protected(tracee, config, SYSARG_2) || arg_protected(tracee, config, SYSARG_4);
		break;
	case PR_symlinkat:
		hit = arg_protected(tracee, config, SYSARG_3);
		break;

	case PR_fchmod:
	case PR_fchown:
	case PR_fchown32:
	case PR_ftruncate:
	case PR_ftruncate64:
	case PR_fallocate:
	case PR_fsetxattr:
	case PR_fremovexattr:
		hit = fd_protected(tracee, config, SYSARG_1);
		break;

	default:
		break;
	}

	return hit ? -EROFS : 0;
}

int readonly_paths_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_open, 0 }, { PR_openat, 0 }, { PR_creat, 0 },
			{ PR_mkdir, 0 }, { PR_mkdirat, 0 }, { PR_mknod, 0 }, { PR_mknodat, 0 },
			{ PR_unlink, 0 }, { PR_unlinkat, 0 }, { PR_rmdir, 0 },
			{ PR_rename, 0 }, { PR_renameat, 0 }, { PR_renameat2, 0 },
			{ PR_link, 0 }, { PR_linkat, 0 }, { PR_symlink, 0 }, { PR_symlinkat, 0 },
			{ PR_chmod, 0 }, { PR_fchmod, 0 }, { PR_fchmodat, 0 },
			{ PR_chown, 0 }, { PR_chown32, 0 }, { PR_lchown, 0 }, { PR_lchown32, 0 },
			{ PR_fchown, 0 }, { PR_fchown32, 0 }, { PR_fchownat, 0 },
			{ PR_truncate, 0 }, { PR_truncate64, 0 }, { PR_ftruncate, 0 }, { PR_ftruncate64, 0 },
			{ PR_fallocate, 0 },
			{ PR_utime, 0 }, { PR_utimes, 0 }, { PR_utimensat, 0 }, { PR_futimesat, 0 },
			{ PR_setxattr, 0 }, { PR_lsetxattr, 0 }, { PR_fsetxattr, 0 },
			{ PR_removexattr, 0 }, { PR_lremovexattr, 0 }, { PR_fremovexattr, 0 },
			FILTERED_SYSNUM_END,
		};
		const char *spec = (const char *) data1;
		Config *config;
		char *copy, *item, *save = NULL;

		if (spec == NULL || spec[0] == '\0')
			return -1;

		extension->config = talloc_zero(extension, Config);
		if (extension->config == NULL)
			return -1;
		config = extension->config;

		copy = talloc_strdup(extension->config, spec);
		if (copy == NULL)
			return -1;
		for (item = strtok_r(copy, ":", &save); item != NULL && config->count < MAX_PREFIXES;
		     item = strtok_r(NULL, ":", &save)) {
			size_t n = strlen(item);
			while (n > 1 && item[n - 1] == '/')
				item[--n] = '\0';
			if (item[0] != '/')
				continue;
			config->prefix[config->count] = item;
			config->length[config->count] = n;
			config->count++;
		}
		if (config->count == 0)
			return -1;

		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT:
		/* Children share the parent's (read-only) config.  */
		return 0;

	case HOST_PATH:
		/* Keep fake_id0 from making a protected path writable.  */
		return is_protected(talloc_get_type_abort(extension->config, Config), (const char *) data1) ? 1 : 0;

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		int status = (int) data1;

		/* Already failing: keep that error.  */
		if (status < 0)
			return 0;
		return handle_sysenter_end(tracee, config);
	}

	default:
		return 0;
	}
}
