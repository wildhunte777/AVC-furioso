/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * avc_guard.c — KernelPatch Module (KPM) for SukiSU
 *
 * Target:  Linux 4.14 arm64 (MT6893 / chopin_kvm)
 * Purpose: Comprehensive AVC audit and SELinux policy query guard
 *
 * Layers:
 *   L1: hook_wrap audit_log_start → block AVC type 1400/1107
 *   L2: fp_hook read/pread64/readv → sanitize log buffers
 *   L3: fp_hook write/writev → intercept selinuxfs policy queries
 *
 * Built against: SukiSU-Ultra/SukiSU_KernelPatch_patch
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <common.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>

/* KPM metadata */
KPM_NAME("avc_guard");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ai-assisted");
KPM_DESCRIPTION("Comprehensive AVC and SELinux policy query guard");

/* Fallbacks */
#ifndef GFP_KERNEL
#define GFP_KERNEL ((unsigned int)0xcc0u)
#endif
#ifndef AUDIT_AVC
#define AUDIT_AVC        1400
#endif
#ifndef AUDIT_USER_AVC
#define AUDIT_USER_AVC   1107
#endif

/* kfunc declarations */
struct audit_buffer;
struct audit_context;
struct file;
struct path;

struct audit_buffer *kfunc_def(audit_log_start)(struct audit_context *ctx,
                                                unsigned int gfp_mask,
                                                int type);
struct file *kfunc_def(fget)(unsigned int fd);
void kfunc_def(fput)(struct file *file);
char *kfunc_def(d_path)(const struct path *path, char *buf, int buflen);
unsigned long kfunc_def(copy_from_user)(void *to, const void __user *from,
                                        unsigned long n);
unsigned long kfunc_def(copy_to_user)(void __user *to, const void *from,
                                      unsigned long n);
void *kfunc_def(kmalloc)(size_t size, unsigned int flags);
void kfunc_def(kfree)(const void *ptr);

/* iovec for readv/writev */
struct kpm_iovec {
    void __user *iov_base;
    size_t iov_len;
};

#define KPM_UIO_MAXIOV 1024
#define SANITIZE_MAX_LEN 4096
#define QUERY_BUF_MAX 512

/* ═══════════════════════════════════════════════════════════════════
 *  Dirty context / keyword / path tables
 *  ═══════════════════════════════════════════════════════════════════ */

/* SELinux contexts that detectors query to discover root */
static const char *dirty_contexts[] = {
    "u:r:ksu", "u:r:su", "u:r:magisk", "u:r:lsposed", "u:r:zygisk",
    "u:r:apatch", "u:r:sukisu", "u:r:supersu", "u:r:root",
    "u:object_r:magisk", "u:object_r:ksu", "u:object_r:lsposed",
    "u:object_r:zygisk", "u:object_r:apatch", "u:object_r:sukisu",
    "u:object_r:supersu",
    NULL
};

/* Keywords appearing in AVC logs and kernel messages */
static const char *sensitive_keywords[] = {
    "avc: denied",
    "u:r:ksu", "u:r:su", "u:r:magisk", "u:r:lsposed", "u:r:zygisk",
    "u:r:apatch", "u:r:sukisu", "u:r:supersu", "u:r:root",
    "u:object_r:magisk", "u:object_r:ksu", "u:object_r:lsposed",
    "u:object_r:zygisk", "u:object_r:apatch", "u:object_r:sukisu",
    "magisk", "lsposed", "zygisk", "apatch", "sukisu", "supersu",
    "kernelsu", "kpm", "kernelpatch", "kpimg", "kptools",
    "magiskd", "magiskpolicy", "supolicy", "ksud", "apd", "kpatchd",
    "lspd", "zygisksu", "susfs", "tricky_store", "nohello",
    "fusefixer", "hidethanox", "hma_oss", "chunqiuziyuan", "春秋",
    "selinux: denied",
    NULL
};

/* Log source file paths */
static const char *log_source_paths[] = {
    "/proc/kmsg", "/dev/kmsg", "/dev/main", "/dev/event-log-tags",
    "/sys/kernel/debug/tracing/trace",
    "/sys/kernel/debug/tracing/trace_pipe",
    "/dev/socket/logdw", "/dev/socket/logdr",
    NULL
};

static const char *log_source_basenames[] = {
    "kmsg", "main", "trace", "trace_pipe", "event-log-tags",
    "logdw", "logdr",
    NULL
};

/* SELinux policy query file paths */
static const char *selinux_query_paths[] = {
    "/sys/fs/selinux/access",
    "/sys/fs/selinux/context",
    "/sys/fs/selinux/valid",
    "/proc/self/attr/current",
    "/proc/thread-self/attr/current",
    "/proc/self/attr/prev",
    "/proc/self/attr/exec",
    "/proc/self/attr/fscreate",
    NULL
};

static const char *selinux_query_basenames[] = {
    "access", "context", "valid", "current", "prev", "exec", "fscreate",
    NULL
};

/* File path keywords that reveal root environment */
static const char *sensitive_paths[] = {
    "/data/adb", "/data/adb/ksu", "/data/adb/modules",
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    NULL
};

/* ═══════════════════════════════════════════════════════════════════
 *  Module state
 *  ═══════════════════════════════════════════════════════════════════ */
static bool g_l1_ok = false;
static bool g_l2_read_ok = false;
static bool g_l2_pread64_ok = false;
static bool g_l2_readv_ok = false;
static bool g_l3_write_ok = false;
static bool g_l3_writev_ok = false;

/* ═══════════════════════════════════════════════════════════════════
 *  Common helpers
 *  ═══════════════════════════════════════════════════════════════════ */

static const char *kstrnstr(const char *s, const char *needle, size_t len)
{
    size_t nl = strlen(needle);
    const char *end = s + len;
    if (nl == 0) return s;
    if (nl > len) return NULL;
    for (; s + nl <= end; s++) {
        if (s[0] == needle[0] && !memcmp(s, needle, nl))
            return s;
    }
    return NULL;
}

static const char *kbasename(const char *path)
{
    const char *p = path, *last = path;
    while (*p) {
        if (*p == '/') last = p + 1;
        p++;
    }
    return last;
}

static bool is_log_source_fd(int fd)
{
    struct file *file;
    char *path_ptr;
    char buf[256];
    const char *base;
    int i;
    bool hit = false;

    if (!fget || !fput || !d_path) return false;
    file = fget(fd);
    if (!file) return false;

    path_ptr = d_path(&file->f_path, buf, sizeof(buf));
    if (path_ptr) {
        for (i = 0; log_source_paths[i]; i++) {
            if (kstrnstr(path_ptr, log_source_paths[i], sizeof(buf))) {
                hit = true; goto out;
            }
        }
        base = kbasename(path_ptr);
        for (i = 0; log_source_basenames[i]; i++) {
            if (!strcmp(base, log_source_basenames[i])) {
                hit = true; goto out;
            }
        }
    }
out:
    fput(file);
    return hit;
}

static bool is_selinux_query_fd(int fd)
{
    struct file *file;
    char *path_ptr;
    char buf[256];
    const char *base;
    int i;
    bool hit = false;

    if (!fget || !fput || !d_path) return false;
    file = fget(fd);
    if (!file) return false;

    path_ptr = d_path(&file->f_path, buf, sizeof(buf));
    if (path_ptr) {
        for (i = 0; selinux_query_paths[i]; i++) {
            if (kstrnstr(path_ptr, selinux_query_paths[i], sizeof(buf))) {
                hit = true; goto out;
            }
        }
        base = kbasename(path_ptr);
        for (i = 0; selinux_query_basenames[i]; i++) {
            if (!strcmp(base, selinux_query_basenames[i])) {
                hit = true; goto out;
            }
        }
    }
out:
    fput(file);
    return hit;
}

static bool contains_dirty_context(const char *buf, size_t len)
{
    int i;
    for (i = 0; dirty_contexts[i]; i++) {
        if (kstrnstr(buf, dirty_contexts[i], len))
            return true;
    }
    return false;
}

static bool contains_sensitive(const char *buf, size_t len)
{
    int i;
    for (i = 0; sensitive_keywords[i]; i++) {
        if (kstrnstr(buf, sensitive_keywords[i], len))
            return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Layer 2: sanitize user-space buffer
 *  ═══════════════════════════════════════════════════════════════════ */

static void sanitize_buffer(char __user *user_buf, ssize_t len)
{
    char *kbuf;
    char *p, *end;
    bool dirty = false;
    unsigned long not_copied;
    size_t copy_len;

    if (len <= 0 || len > SANITIZE_MAX_LEN) return;
    if (!kmalloc || !kfree || !copy_from_user || !copy_to_user) return;

    kbuf = kmalloc(len + 1, GFP_KERNEL);
    if (!kbuf) return;

    not_copied = copy_from_user(kbuf, user_buf, len);
    if (not_copied) { kfree(kbuf); return; }
    kbuf[len] = '\0';

    if (!contains_sensitive(kbuf, len)) { kfree(kbuf); return; }

    p = kbuf; end = kbuf + len;
    while (p < end) {
        char *line_end = strchr(p, '\n');
        size_t line_len = line_end ? (size_t)(line_end - p) + 1 : (size_t)(end - p);

        if (contains_sensitive(p, line_len)) {
            if (line_end) {
                memset(p, ' ', line_len - 1);
                p[line_len - 1] = '\n';
            } else {
                memset(p, ' ', line_len);
            }
            dirty = true;
        }
        if (!line_end) break;
        p = line_end + 1;
    }

    if (dirty) {
        not_copied = copy_to_user(user_buf, kbuf, len);
        if (not_copied) {
            logkw("avc_guard: copy_to_user partial %lu/%ld\n",
                  not_copied, (long)len);
        }
    }
    kfree(kbuf);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Layer 1: audit_log_start hook
 *  ═══════════════════════════════════════════════════════════════════ */

static void before_audit_log_start(hook_fargs3_t *args, void *udata)
{
    int type = (int)args->arg2;  /* inline hook: direct arg access */
    if (type == AUDIT_AVC || type == AUDIT_USER_AVC) {
        args->skip_origin = 1;
        args->ret = (uint64_t)NULL;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Layer 2: read / pread64 / readv hooks
 *  ═══════════════════════════════════════════════════════════════════ */

static void after_read(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)syscall_argn(args, 0);
    char __user *buf = (char __user *)syscall_argn(args, 1);
    if (ret > 0 && is_log_source_fd(fd))
        sanitize_buffer(buf, ret);
}

static void after_pread64(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)syscall_argn(args, 0);
    char __user *buf = (char __user *)syscall_argn(args, 1);
    if (ret > 0 && is_log_source_fd(fd))
        sanitize_buffer(buf, ret);
}

static void after_readv(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)syscall_argn(args, 0);
    struct kpm_iovec __user *uiov = (struct kpm_iovec __user *)syscall_argn(args, 1);
    int iovcnt = (int)syscall_argn(args, 2);
    struct kpm_iovec kiov;
    int i;

    if (ret <= 0 || !is_log_source_fd(fd)) return;
    if (!uiov || iovcnt <= 0) return;

    for (i = 0; i < iovcnt && i < KPM_UIO_MAXIOV; i++) {
        if (copy_from_user(&kiov, &uiov[i], sizeof(kiov))) continue;
        if (kiov.iov_base && kiov.iov_len > 0)
            sanitize_buffer(kiov.iov_base, (ssize_t)kiov.iov_len);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Layer 3: write / writev hooks
 *  ═══════════════════════════════════════════════════════════════════ */

static void before_write(hook_fargs3_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    const char __user *ubuf = (const char __user *)syscall_argn(args, 1);
    size_t count = (size_t)syscall_argn(args, 2);
    char kbuf[QUERY_BUF_MAX];
    size_t copy_len;
    unsigned long not_copied;

    if (fd <= 2 || !ubuf || count < 5) return;
    if (!is_selinux_query_fd(fd)) return;
    if (!copy_from_user) return;

    copy_len = (count < QUERY_BUF_MAX - 1) ? count : QUERY_BUF_MAX - 1;
    not_copied = copy_from_user(kbuf, ubuf, copy_len);
    if (not_copied) return;
    kbuf[copy_len] = '\0';

    if (contains_dirty_context(kbuf, copy_len)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)count;  /* pretend success, no-op */
        logkd("avc_guard: L3 blocked write fd=%d cnt=%zu\n", fd, count);
    }
}

static void before_writev(hook_fargs3_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    struct kpm_iovec __user *uiov = (struct kpm_iovec __user *)syscall_argn(args, 1);
    int iovcnt = (int)syscall_argn(args, 2);
    struct kpm_iovec kiov;
    char kbuf[QUERY_BUF_MAX];
    size_t copy_len;
    unsigned long not_copied;
    int i;

    if (fd <= 2 || !uiov || iovcnt <= 0) return;
    if (!is_selinux_query_fd(fd)) return;
    if (!copy_from_user) return;

    for (i = 0; i < iovcnt && i < KPM_UIO_MAXIOV; i++) {
        if (copy_from_user(&kiov, &uiov[i], sizeof(kiov))) continue;
        if (!kiov.iov_base || kiov.iov_len < 5) continue;

        copy_len = (kiov.iov_len < QUERY_BUF_MAX - 1) ? kiov.iov_len : QUERY_BUF_MAX - 1;
        not_copied = copy_from_user(kbuf, kiov.iov_base, copy_len);
        if (not_copied) continue;
        kbuf[copy_len] = '\0';

        if (contains_dirty_context(kbuf, copy_len)) {
            args->skip_origin = 1;
            args->ret = (uint64_t)syscall_argn(args, 2);  /* pretend all written */
            logkd("avc_guard: L3 blocked writev fd=%d iov=%d\n", fd, i);
            return;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Init / Control0 / Exit
 *  ═══════════════════════════════════════════════════════════════════ */

static long avc_guard_init(const char *args, const char *event,
                           void *__user reserved)
{
    hook_err_t err;

    logkd("avc_guard: v2.0.0 init (kpver=%x kver=%x)\n", kpver, kver);

    /* Resolve kfuncs */
    if (!audit_log_start)
        audit_log_start = (void *)kallsyms_lookup_name("audit_log_start");
    if (!fget) fget = (void *)kallsyms_lookup_name("fget");
    if (!fput) fput = (void *)kallsyms_lookup_name("fput");
    if (!d_path) d_path = (void *)kallsyms_lookup_name("d_path");
    if (!copy_from_user)
        copy_from_user = (void *)kallsyms_lookup_name("copy_from_user");
    if (!copy_to_user)
        copy_to_user = (void *)kallsyms_lookup_name("copy_to_user");
    if (!kmalloc) kmalloc = (void *)kallsyms_lookup_name("kmalloc");
    if (!kfree) kfree = (void *)kallsyms_lookup_name("kfree");

    /* L1: audit_log_start */
    if (audit_log_start) {
        err = hook_wrap3(audit_log_start, before_audit_log_start, NULL, 0);
        if (err == HOOK_NO_ERR) {
            g_l1_ok = true;
            logkd("avc_guard: L1 hooked audit_log_start@%p\n", audit_log_start);
        } else {
            logkw("avc_guard: L1 hook failed err=%d\n", err);
        }
    } else {
        logkw("avc_guard: L1 audit_log_start not found\n");
    }

    /* L2: read syscalls */
    err = fp_hook_syscalln(__NR_read, 3, NULL, after_read, 0);
    if (err == HOOK_NO_ERR) { g_l2_read_ok = true; logkd("avc_guard: L2 read hooked\n"); }
    else logkw("avc_guard: L2 read hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_pread64, 3, NULL, after_pread64, 0);
    if (err == HOOK_NO_ERR) { g_l2_pread64_ok = true; logkd("avc_guard: L2 pread64 hooked\n"); }
    else logkw("avc_guard: L2 pread64 hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_readv, 3, NULL, after_readv, 0);
    if (err == HOOK_NO_ERR) { g_l2_readv_ok = true; logkd("avc_guard: L2 readv hooked\n"); }
    else logkw("avc_guard: L2 readv hook failed err=%d\n", err);

    /* L3: write syscalls */
    err = fp_hook_syscalln(__NR_write, 3, before_write, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l3_write_ok = true; logkd("avc_guard: L3 write hooked\n"); }
    else logkw("avc_guard: L3 write hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_writev, 3, before_writev, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l3_writev_ok = true; logkd("avc_guard: L3 writev hooked\n"); }
    else logkw("avc_guard: L3 writev hook failed err=%d\n", err);

    logkd("avc_guard: init done L1=%s L2r=%s L2p=%s L2v=%s L3w=%s L3v=%s\n",
          g_l1_ok ? "OK" : "FAIL",
          g_l2_read_ok ? "OK" : "FAIL",
          g_l2_pread64_ok ? "OK" : "FAIL",
          g_l2_readv_ok ? "OK" : "FAIL",
          g_l3_write_ok ? "OK" : "FAIL",
          g_l3_writev_ok ? "OK" : "FAIL");

    return 0;
}

static long avc_guard_control0(const char *args, char *__user out_msg,
                               int outlen)
{
    char msg[256];
    int len;
    size_t copy_len;

    len = snprintf(msg, sizeof(msg),
                   "avc_guard v2.0.0 status:\n"
                   "  L1 audit_log_start : %s\n"
                   "  L2 read            : %s\n"
                   "  L2 pread64         : %s\n"
                   "  L2 readv           : %s\n"
                   "  L3 write           : %s\n"
                   "  L3 writev          : %s\n",
                   g_l1_ok ? "OK" : "FAIL",
                   g_l2_read_ok ? "OK" : "FAIL",
                   g_l2_pread64_ok ? "OK" : "FAIL",
                   g_l2_readv_ok ? "OK" : "FAIL",
                   g_l3_write_ok ? "OK" : "FAIL",
                   g_l3_writev_ok ? "OK" : "FAIL");

    if (out_msg && outlen > 0) {
        copy_len = (size_t)(len + 1) < (size_t)outlen ? (size_t)(len + 1) : (size_t)outlen;
        compat_copy_to_user(out_msg, msg, copy_len);
    }
    return 0;
}

static long avc_guard_exit(void *__user reserved)
{
    logkd("avc_guard: exiting\n");

    if (g_l1_ok && audit_log_start)
        hook_unwrap(audit_log_start, before_audit_log_start, NULL);

    if (g_l2_read_ok)
        fp_unhook_syscalln(__NR_read, NULL, after_read);
    if (g_l2_pread64_ok)
        fp_unhook_syscalln(__NR_pread64, NULL, after_pread64);
    if (g_l2_readv_ok)
        fp_unhook_syscalln(__NR_readv, NULL, after_readv);

    if (g_l3_write_ok)
        fp_unhook_syscalln(__NR_write, before_write, NULL);
    if (g_l3_writev_ok)
        fp_unhook_syscalln(__NR_writev, before_writev, NULL);

    return 0;
}

KPM_INIT(avc_guard_init);
KPM_CTL0(avc_guard_control0);
KPM_EXIT(avc_guard_exit);
