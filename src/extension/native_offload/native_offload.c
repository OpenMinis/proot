/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * native_offload extension.
 *
 * When a tracee tries to execve a registered handler name, we send
 * argv/env/cwd to a host-side server over an abstract unix socket.
 * The server runs the handler (in-process on the Android side),
 * writes its combined stdout+stderr to a tmpfile visible inside the
 * rootfs, and replies with the tmpfile guest path + exit code.
 *
 * The extension then rewrites the execve into `/bin/cat <tmpfile>`
 * so the guest receives the handler output as if it had run a
 * native binary.  Exit code from handler cannot be propagated via
 * `cat` — we accept that limitation for now (matches iOS behaviour
 * where offloaded tools similarly return 0 on success).
 *
 * Wire protocol (all little-endian):
 *   request:  u32 magic='NOFF', u32 version=1, u32 pid,
 *             u32 argc, { u32 len, bytes[len] } * argc,
 *             u32 envc, { u32 len, bytes[len] } * envc,
 *             u32 cwd_len, bytes[cwd_len]
 *   response: u32 magic='NOFR', i32 exit_code,
 *             u32 tmpfile_len, bytes[tmpfile_len]
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <talloc.h>

#include "cli/note.h"
#include "extension/native_offload/native_offload.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/tracee.h"

#define NOFF_MAGIC_REQ  0x46464F4Eu  /* "NOFF" */
#define NOFF_MAGIC_RSP  0x52464F4Eu  /* "NOFR" */
#define NOFF_VERSION    1u
#define NOFF_MAX_ARGS   256
#define NOFF_MAX_ENVS   1024
#define NOFF_MAX_STR    8192
#define NOFF_MAX_TMPFILE 512

/* Debug logging, gated by MINIS_NOFF_DEBUG env var.
 * Writes to stderr directly (proot's note() suppresses INFO unless -v is set,
 * which would drown us in noise from other subsystems). */
static int noff_debug_enabled(void)
{
	static int cached = -1;
	if (cached == -1) {
		const char *e = getenv("MINIS_NOFF_DEBUG");
		cached = (e != NULL && e[0] != '\0' && e[0] != '0') ? 1 : 0;
	}
	return cached;
}

#define NOFF_DBG(fmt, ...) do { \
	if (noff_debug_enabled()) \
		fprintf(stderr, "[native_offload] " fmt "\n", ##__VA_ARGS__); \
} while (0)

/* ------------------------------------------------------------------ */
/* Handler registry                                                   */
/* ------------------------------------------------------------------ */

typedef struct HandlerEntry {
	struct HandlerEntry *next;
	char *name;
} HandlerEntry;

static HandlerEntry *handlers;
static char *offload_socket_name;

int native_offload_add_handler(const char *name)
{
	if (name == NULL || name[0] == '\0')
		return -EINVAL;

	for (HandlerEntry *e = handlers; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0)
			return 0;
	}

	HandlerEntry *entry = talloc_zero(NULL, HandlerEntry);
	if (entry == NULL)
		return -ENOMEM;

	entry->name = talloc_strdup(entry, name);
	if (entry->name == NULL) {
		talloc_free(entry);
		return -ENOMEM;
	}
	entry->next = handlers;
	handlers = entry;
	NOFF_DBG("register handler '%s'", name);
	return 0;
}

static const HandlerEntry *native_offload_lookup(const char *name)
{
	if (name == NULL)
		return NULL;
	for (HandlerEntry *e = handlers; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0)
			return e;
	}
	return NULL;
}

typedef struct {
	const char *socket_name;
} NativeOffloadConfig;

static FilteredSysnum filtered_sysnums[] = {
	{ PR_execve,	0 },
	{ PR_execveat,	0 },
	FILTERED_SYSNUM_END,
};

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static const char *basename_of(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash != NULL ? slash + 1 : path;
}

static int parse_cli_arg(TALLOC_CTX *ctx, const char *cli, const char **out_socket)
{
	const char *socket = NATIVE_OFFLOAD_DEFAULT_SOCKET;
	const char *handler_list = NULL;

	if (cli != NULL && cli[0] != '\0') {
		char *dup = talloc_strdup(ctx, cli);
		if (dup == NULL)
			return -ENOMEM;

		char *colon = strchr(dup, ':');
		if (colon != NULL) {
			*colon = '\0';
			handler_list = colon + 1;
		}
		if (dup[0] != '\0')
			socket = dup;
	}

	if (handler_list != NULL) {
		char *copy = talloc_strdup(ctx, handler_list);
		if (copy == NULL)
			return -ENOMEM;
		for (char *tok = strtok(copy, ","); tok != NULL; tok = strtok(NULL, ","))
			native_offload_add_handler(tok);
	}

	*out_socket = socket;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Socket I/O helpers                                                 */
/* ------------------------------------------------------------------ */

static int connect_abstract(const char *name)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	struct sockaddr_un addr = {0};
	addr.sun_family = AF_UNIX;
	size_t nlen = strlen(name);
	if (nlen + 1 >= sizeof(addr.sun_path)) {
		close(fd);
		return -ENAMETOOLONG;
	}
	addr.sun_path[0] = '\0';
	memcpy(addr.sun_path + 1, name, nlen);
	socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 1 + nlen;

	if (connect(fd, (struct sockaddr *) &addr, alen) < 0) {
		int e = -errno;
		NOFF_DBG("connect_abstract('%s') failed: errno=%d (%s)", name, -e, strerror(-e));
		close(fd);
		return e;
	}
	NOFF_DBG("connect_abstract('%s') -> fd=%d", name, fd);
	return fd;
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		p += n;
		len -= n;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		p += n;
		len -= n;
	}
	return 0;
}

static int write_u32(int fd, uint32_t v)
{
	return write_all(fd, &v, sizeof(v));
}

static int write_lenbytes(int fd, const char *s)
{
	uint32_t len = s != NULL ? (uint32_t) strlen(s) : 0;
	int status = write_u32(fd, len);
	if (status < 0) return status;
	if (len > 0) return write_all(fd, s, len);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Reading argv / env from tracee memory                              */
/* ------------------------------------------------------------------ */

/* Read argv (NULL-terminated array of char*) at @addr into a newly
 * allocated talloc array of C strings (NULL-terminated sentinel).
 * Caller must talloc_free(result).  Returns -errno on failure.  */
static int read_stringv(Tracee *tracee, word_t addr, TALLOC_CTX *ctx,
			char ***out, int max_count)
{
	char **result = talloc_array(ctx, char *, max_count + 1);
	if (result == NULL) return -ENOMEM;

	int count = 0;
	for (; count < max_count; count++) {
		word_t ptr = peek_word(tracee, addr + count * sizeof(word_t));
		if (errno != 0) {
			talloc_free(result);
			return -errno;
		}
		if (ptr == 0) break;

		char buf[NOFF_MAX_STR];
		int status = read_string(tracee, buf, ptr, sizeof(buf));
		if (status < 0) {
			talloc_free(result);
			return status;
		}
		result[count] = talloc_strdup(result, buf);
		if (result[count] == NULL) {
			talloc_free(result);
			return -ENOMEM;
		}
	}
	result[count] = NULL;
	*out = result;
	return count;
}

/* ------------------------------------------------------------------ */
/* Core: perform the offload request                                  */
/* ------------------------------------------------------------------ */

typedef struct {
	int32_t exit_code;
	char tmpfile[NOFF_MAX_TMPFILE];
} OffloadResponse;

static int do_offload(Tracee *tracee, const char *socket_name,
		      char **argv, char **envp, const char *cwd,
		      OffloadResponse *rsp)
{
	int fd = connect_abstract(socket_name);
	if (fd < 0) return fd;

	int argc = 0; for (; argv[argc] != NULL; argc++) {}
	int envc = 0; for (; envp != NULL && envp[envc] != NULL; envc++) {}

	int status;
	if ((status = write_u32(fd, NOFF_MAGIC_REQ)) < 0) goto out;
	if ((status = write_u32(fd, NOFF_VERSION)) < 0) goto out;
	if ((status = write_u32(fd, (uint32_t) tracee->pid)) < 0) goto out;
	if ((status = write_u32(fd, (uint32_t) argc)) < 0) goto out;
	for (int i = 0; i < argc; i++) {
		if ((status = write_lenbytes(fd, argv[i])) < 0) goto out;
	}
	if ((status = write_u32(fd, (uint32_t) envc)) < 0) goto out;
	for (int i = 0; i < envc; i++) {
		if ((status = write_lenbytes(fd, envp[i])) < 0) goto out;
	}
	if ((status = write_lenbytes(fd, cwd != NULL ? cwd : "")) < 0) goto out;

	uint32_t magic;
	if ((status = read_all(fd, &magic, sizeof(magic))) < 0) goto out;
	if (magic != NOFF_MAGIC_RSP) { status = -EPROTO; goto out; }

	int32_t exit_code;
	if ((status = read_all(fd, &exit_code, sizeof(exit_code))) < 0) goto out;

	uint32_t tlen;
	if ((status = read_all(fd, &tlen, sizeof(tlen))) < 0) goto out;
	if (tlen >= sizeof(rsp->tmpfile)) { status = -EMSGSIZE; goto out; }
	if (tlen > 0) {
		if ((status = read_all(fd, rsp->tmpfile, tlen)) < 0) goto out;
	}
	rsp->tmpfile[tlen] = '\0';
	rsp->exit_code = exit_code;
	status = 0;

out:
	close(fd);
	return status;
}

/* ------------------------------------------------------------------ */
/* execve rewriting                                                   */
/* ------------------------------------------------------------------ */

/* Write a NULL-terminated argv=["cat", <tmpfile>, NULL] into the
 * tracee's memory and point SYSARG_2 at it.  Rewrite SYSARG_1 to
 * "/bin/cat".  */
static int rewrite_as_cat(Tracee *tracee, Reg filename_reg, Reg argv_reg,
			  const char *tmpfile)
{
	static const char kCatPath[] = "/bin/cat";
	static const char kCat[] = "cat";

	int status = set_sysarg_data(tracee, kCatPath, sizeof(kCatPath), filename_reg);
	if (status < 0) return status;

	size_t tlen = strlen(tmpfile) + 1;
	word_t cat_addr = alloc_mem(tracee, sizeof(kCat));
	if (cat_addr == 0) return -EFAULT;
	if ((status = write_data(tracee, cat_addr, kCat, sizeof(kCat))) < 0) return status;

	word_t tmp_addr = alloc_mem(tracee, tlen);
	if (tmp_addr == 0) return -EFAULT;
	if ((status = write_data(tracee, tmp_addr, tmpfile, tlen)) < 0) return status;

	word_t argv_addr = alloc_mem(tracee, sizeof(word_t) * 3);
	if (argv_addr == 0) return -EFAULT;

	word_t slot0 = cat_addr;
	word_t slot1 = tmp_addr;
	word_t slot2 = 0;
	if ((status = write_data(tracee, argv_addr + 0 * sizeof(word_t), &slot0, sizeof(word_t))) < 0) return status;
	if ((status = write_data(tracee, argv_addr + 1 * sizeof(word_t), &slot1, sizeof(word_t))) < 0) return status;
	if ((status = write_data(tracee, argv_addr + 2 * sizeof(word_t), &slot2, sizeof(word_t))) < 0) return status;

	poke_reg(tracee, argv_reg, argv_addr);
	return 0;
}

static void handle_execve_enter(Tracee *tracee, NativeOffloadConfig *cfg,
				Reg filename_reg, Reg argv_reg, Reg envp_reg)
{
	if (cfg == NULL || cfg->socket_name == NULL) return;

	char path[PATH_MAX];
	word_t src = peek_reg(tracee, CURRENT, filename_reg);
	if (src == 0) return;
	if (read_string(tracee, path, src, sizeof(path)) < 0) return;

	const char *name = basename_of(path);
	if (native_offload_lookup(name) == NULL) return;

	NOFF_DBG("execve intercepted pid=%d path='%s' name='%s'",
		 tracee->pid, path, name);

	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) return;

	char **argv = NULL;
	char **envp = NULL;
	int argc = read_stringv(tracee, peek_reg(tracee, CURRENT, argv_reg),
				ctx, &argv, NOFF_MAX_ARGS);
	if (argc < 0) {
		NOFF_DBG("read argv failed for '%s': %d", name, argc);
		note(tracee, WARNING, INTERNAL,
		     "native_offload: failed to read argv for '%s': %d", name, argc);
		goto done;
	}

	(void) read_stringv(tracee, peek_reg(tracee, CURRENT, envp_reg),
			    ctx, &envp, NOFF_MAX_ENVS);

	if (noff_debug_enabled()) {
		/* Print up to the first 8 argv entries so the log stays useful
		 * without exploding for commands with huge argv. */
		fprintf(stderr, "[native_offload] argv[%d]:", argc);
		int n = argc < 8 ? argc : 8;
		for (int i = 0; i < n; i++)
			fprintf(stderr, " '%s'", argv[i]);
		if (argc > n) fprintf(stderr, " ... (+%d more)", argc - n);
		fprintf(stderr, "\n");
	}

	OffloadResponse rsp = {0};
	int status = do_offload(tracee, cfg->socket_name, argv, envp,
				tracee->fs->cwd, &rsp);
	if (status < 0) {
		NOFF_DBG("do_offload failed name='%s' status=%d (%s)",
			 name, status, strerror(-status));
		note(tracee, WARNING, INTERNAL,
		     "native_offload: offload of '%s' failed: %d", name, status);
		goto done;
	}

	/* Debug only. This used to be a note(INFO) as well, and INFO is printed
	 * at proot's default verbosity: one "proot info: native_offload:
	 * offloaded ..." line per offloaded command, written to proot's own
	 * stderr - which the guest cannot redirect or grep away - so it landed
	 * in every agent command's output and cost tokens. Failures above and
	 * below stay WARNINGs. */
	NOFF_DBG("offloaded '%s' -> tmpfile='%s' exit=%d",
		 name, rsp.tmpfile, (int) rsp.exit_code);

	status = rewrite_as_cat(tracee, filename_reg, argv_reg, rsp.tmpfile);
	if (status < 0) {
		NOFF_DBG("rewrite_as_cat failed: %d (%s)", status, strerror(-status));
		note(tracee, WARNING, INTERNAL,
		     "native_offload: rewrite_as_cat failed: %d", status);
	} else {
		NOFF_DBG("rewrote execve as /bin/cat %s", rsp.tmpfile);
	}

done:
	talloc_free(ctx);
}

/* ------------------------------------------------------------------ */
/* Extension callback                                                 */
/* ------------------------------------------------------------------ */

int native_offload_callback(Extension *extension, ExtensionEvent event,
			    intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		NativeOffloadConfig *cfg = talloc_zero(extension, NativeOffloadConfig);
		if (cfg == NULL) return -ENOMEM;

		const char *socket = NATIVE_OFFLOAD_DEFAULT_SOCKET;
		int status = parse_cli_arg(extension, (const char *) data1, &socket);
		if (status < 0) return status;

		if (offload_socket_name == NULL && socket != NULL)
			offload_socket_name = talloc_strdup(NULL, socket);

		cfg->socket_name = offload_socket_name;
		extension->config = cfg;
		extension->filtered_sysnums = filtered_sysnums;

		if (noff_debug_enabled()) {
			int count = 0;
			for (HandlerEntry *e = handlers; e != NULL; e = e->next) count++;
			NOFF_DBG("initialized socket='%s' handlers=%d debug=on",
				 cfg->socket_name ? cfg->socket_name : "(none)", count);
		}
		/* No note(INFO) here: see the "offloaded" site - the startup line
		 * showed up at the top of every agent command's output. The
		 * NOFF_DBG above covers it when MINIS_NOFF_DEBUG is set. */
		return 0;
	}

	case INHERIT_PARENT:
		return 0;

	case SYSCALL_ENTER_START: {
		Tracee *tracee = TRACEE(extension);
		NativeOffloadConfig *cfg = extension->config;
		switch (get_sysnum(tracee, CURRENT)) {
		case PR_execve:
			handle_execve_enter(tracee, cfg, SYSARG_1, SYSARG_2, SYSARG_3);
			break;
		case PR_execveat:
			handle_execve_enter(tracee, cfg, SYSARG_2, SYSARG_3, SYSARG_4);
			break;
		default:
			break;
		}
		return 0;
	}

	default:
		return 0;
	}
}
