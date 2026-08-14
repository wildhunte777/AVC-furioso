/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * avc_guard.c — KernelPatch Module (KPM) for SukiSU
 *
 * Target: Linux 4.14 arm64 (MT6893 / chopin_kvm)
 * Purpose: Comprehensive AVC audit and SELinux policy query guard
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <syscall.h>          /* KernelPatch syscall.h: fp_hook_syscalln, etc. */
/* compat_copy_to_user not exported in this KernelPatch branch; declare manually */
long compat_copy_to_user(void __user *to, const void *from, unsigned long n);
#include <kallsyms.h>
#include <linux/slab.h>
#include <preset.h>
#include <linux/string.h>   /* strlen, strcmp, memcmp, strchr, memset */

/* ============================================================================
 * KernelPatch stripped headers forward-declare struct path / struct file.
 * Provide minimal ABI-compatible definitions for Linux 4.14 arm64.
 * ============================================================================ */

struct vfsmount;
struct dentry;

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    char __f_u_pad[16]; /* union f_u: rcu_head is largest at 16 bytes */
    struct path f_path;
};

/* KernelPatch headers lack stdio prototypes; declare manually */
int snprintf(char *buf, size_t size, const char *fmt, ...);

/* KernelPatch headers lack string prototypes; declare manually */
unsigned long strlen(const char *s);
int strcmp(const char *s1, const char *s2);
int memcmp(const void *s1, const void *s2, size_t n);
char *strchr(const char *s, int c);
void *memset(void *s, int c, size_t n);

/* Fallbacks */
#ifndef GFP_KERNEL
#define GFP_KERNEL ((unsigned int)0xcc0u)
#endif
#ifndef AUDIT_AVC
#define AUDIT_AVC 1400
#endif
#ifndef AUDIT_USER_AVC
#define AUDIT_USER_AVC 1107
#endif
#ifndef ENODATA
#define ENODATA 61
#endif

/* Syscall numbers for Linux 4.14 arm64 (asm-generic/unistd.h) */
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_write
#define __NR_write 64
#endif
#ifndef __NR_readv
#define __NR_readv 65
#endif
#ifndef __NR_writev
#define __NR_writev 66
#endif
#ifndef __NR_pread64
#define __NR_pread64 67
#endif
#ifndef __NR_pwrite64
#define __NR_pwrite64 68
#endif
#ifndef __NR_preadv
#define __NR_preadv 69
#endif
#ifndef __NR_pwritev
#define __NR_pwritev 70
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg 211
#endif
#ifndef __NR_getxattr
#define __NR_getxattr 8
#endif
#ifndef __NR_lgetxattr
#define __NR_lgetxattr 9
#endif
#ifndef __NR_fgetxattr
#define __NR_fgetxattr 10
#endif

/* ============================================================================
 * Function pointer types for runtime-resolved kernel symbols
 * ============================================================================ */

struct audit_buffer;
struct audit_context;

typedef struct audit_buffer *(*audit_log_start_t)(struct audit_context *ctx,
                                                   unsigned int gfp_mask,
                                                   int type);
typedef struct file *(*fget_t)(unsigned int fd);
typedef void (*fput_t)(struct file *file);
typedef char *(*d_path_t)(const struct path *path, char *buf, int buflen);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from,
                                          unsigned long n);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from,
                                        unsigned long n);
typedef void *(*kmalloc_t)(size_t size, unsigned int flags);
typedef void (*kfree_t)(const void *ptr);

/* ============================================================================
 * Runtime-resolved function pointers (resolved in avc_guard_init)
 * ============================================================================ */
static audit_log_start_t fn_audit_log_start = NULL;
static fget_t fn_fget = NULL;
static fput_t fn_fput = NULL;
static d_path_t fn_d_path = NULL;
static copy_from_user_t fn_copy_from_user = NULL;
static copy_to_user_t fn_copy_to_user = NULL;
static kmalloc_t fn_kmalloc = NULL;
static kfree_t fn_kfree = NULL;

/* iovec */
struct kpm_iovec {
    void __user *iov_base;
    size_t iov_len;
};

/* msghdr for recvmsg (arm64 layout) */
struct kpm_msghdr {
    void __user *msg_name;
    int msg_namelen;
    int __pad0;
    struct kpm_iovec __user *msg_iov;
    unsigned long msg_iovlen;
    void __user *msg_control;
    unsigned long msg_controllen;
    unsigned int msg_flags;
};

#define KPM_UIO_MAXIOV 1024
#define SANITIZE_MAX_LEN 4096
#define QUERY_BUF_MAX 512

/* ============================================================================
 * Dirty context / keyword / path tables
 * ============================================================================ */

static const char *dirty_contexts[] = {
    "u:r:ksu", "u:r:su", "u:r:magisk", "u:r:lsposed", "u:r:zygisk",
    "u:r:apatch", "u:r:sukisu", "u:r:supersu", "u:r:root",
    "u:object_r:magisk", "u:object_r:ksu", "u:object_r:lsposed",
    "u:object_r:zygisk", "u:object_r:apatch", "u:object_r:sukisu",
    "u:object_r:supersu",
    NULL
};

static const char *sensitive_keywords[] = {
    "avc: denied",
    "u:r:ksu", "u:r:su", "u:r:magisk", "u:r:lsposed", "u:r:zygisk",
    "u:r:apatch", "u:r:sukisu", "u:r:supersu", "u:r:root",
    "u:object_r:magisk", "u:object_r:ksu", "u:object_r:lsposed",
    "u:object_r:zygisk", "u:object_r:apatch", "u:object_r:sukisu",
    "magisk", "lsposed", "zygisk", "apatch", "sukisu", "supersu",
    "kernelsu", "kernelpatch", "kpimg", "kptools",
    "magiskd", "magiskpolicy", "supolicy", "ksud", "apd", "kpatchd",
    "lspd", "zygisksu", "susfs", "tricky_store", "nohello",
    "fusefixer", "hidethanox", "hma_oss", "chunqiuziyuan",
    "selinux: denied",
    NULL
};

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

static const char *adb_paths[] = {
    "/data/adb",
    "/data/adb/ksu",
    "/data/adb/modules",
    "/system/bin/su",
    "/system/xbin/su",
    NULL
};

/* ============================================================================
 * Module state
 * ============================================================================ */
static bool g_l1_ok = false;
static bool g_l2_read_ok = false;
static bool g_l2_pread64_ok = false;
static bool g_l2_readv_ok = false;
static bool g_l2_preadv_ok = false;
static bool g_l2_recvmsg_ok = false;
static bool g_l3_write_ok = false;
static bool g_l3_writev_ok = false;
static bool g_l3_pwritev_ok = false;
static bool g_l4_getxattr_ok = false;
static bool g_l4_lgetxattr_ok = false;
static bool g_l4_fgetxattr_ok = false;

/* ============================================================================
 * Common helpers
 * ============================================================================ */

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

    if (!fn_fget || !fn_fput || !fn_d_path) return false;
    file = fn_fget(fd);
    if (!file) return false;

    path_ptr = fn_d_path(&file->f_path, buf, sizeof(buf));
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
    fn_fput(file);
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

    if (!fn_fget || !fn_fput || !fn_d_path) return false;
    file = fn_fget(fd);
    if (!file) return false;

    path_ptr = fn_d_path(&file->f_path, buf, sizeof(buf));
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
    fn_fput(file);
    return hit;
}

static bool is_sensitive_adb_path(const char *path)
{
    int i;
    for (i = 0; adb_paths[i]; i++) {
        if (kstrnstr(path, adb_paths[i], 256))
            return true;
    }
    return false;
}

/* 不用全局数组，直接在函数内用局部静态或字符串比较链 */
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

/* ============================================================================
 * Layer 2: sanitize user-space buffer
 * ============================================================================ */

static void sanitize_buffer(char __user *user_buf, ssize_t len)
{
    char *kbuf;
    char *p, *end;
    bool dirty = false;
    unsigned long not_copied;

    if (len <= 0 || len > SANITIZE_MAX_LEN) return;
    if (!fn_kmalloc || !fn_kfree || !fn_copy_from_user || !fn_copy_to_user) return;

    kbuf = fn_kmalloc(len + 1, GFP_KERNEL);
    if (!kbuf) return;

    not_copied = fn_copy_from_user(kbuf, user_buf, len);
    if (not_copied) { fn_kfree(kbuf); return; }
    kbuf[len] = '\0';

    if (!contains_sensitive(kbuf, len)) { fn_kfree(kbuf); return; }

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
        not_copied = fn_copy_to_user(user_buf, kbuf, len);
        if (not_copied) {
            logkw("avc_guard: copy_to_user partial %lu/%ld\n",
                  not_copied, (long)len);
        }
    }
    fn_kfree(kbuf);
}

/* ============================================================================
 * Layer 1: audit_log_start hook
 * ============================================================================ */

static void before_audit_log_start(hook_fargs3_t *args, void *udata)
{
    int type = (int)args->arg2;
    if (type == AUDIT_AVC || type == AUDIT_USER_AVC) {
        args->skip_origin = 1;
        args->ret = (uint64_t)NULL;
    }
}

/* ============================================================================
 * Layer 2: read / pread64 / readv / preadv / recvmsg hooks
 * ============================================================================ */

static void after_read(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)args->arg0;
    char __user *buf = (char __user *)args->arg1;
    if (ret > 0 && is_log_source_fd(fd))
        sanitize_buffer(buf, ret);
}

static void after_pread64(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)args->arg0;
    char __user *buf = (char __user *)args->arg1;
    if (ret > 0 && is_log_source_fd(fd))
        sanitize_buffer(buf, ret);
}

static void after_readv(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    int fd = (int)args->arg0;
    struct kpm_iovec __user *uiov = (struct kpm_iovec __user *)args->arg1;
    int iovcnt = (int)args->arg2;
    struct kpm_iovec kiov;
    int i;

    if (ret <= 0 || !is_log_source_fd(fd)) return;
    if (!uiov || iovcnt <= 0) return;
    if (!fn_copy_from_user) return;

    for (i = 0; i < iovcnt && i < KPM_UIO_MAXIOV; i++) {
        if (fn_copy_from_user(&kiov, &uiov[i], sizeof(kiov))) continue;
        if (kiov.iov_base && kiov.iov_len > 0)
            sanitize_buffer(kiov.iov_base, (ssize_t)kiov.iov_len);
    }
}

static void after_recvmsg(hook_fargs3_t *args, void *udata)
{
    ssize_t ret = (ssize_t)args->ret;
    struct kpm_msghdr __user *umsg;
    struct kpm_msghdr kmsg;
    struct kpm_iovec kiov;
    int i;

    if (ret <= 0) return;
    if (!fn_copy_from_user) return;

    umsg = (struct kpm_msghdr __user *)args->arg1;
    if (!umsg) return;

    if (fn_copy_from_user(&kmsg, umsg, sizeof(kmsg))) return;
    if (!kmsg.msg_iov || kmsg.msg_iovlen == 0) return;

    for (i = 0; i < (int)kmsg.msg_iovlen && i < KPM_UIO_MAXIOV; i++) {
        if (fn_copy_from_user(&kiov, &kmsg.msg_iov[i], sizeof(kiov))) continue;
        if (!kiov.iov_base || kiov.iov_len == 0) continue;

        char quick[256];
        size_t quick_len = kiov.iov_len < sizeof(quick) ? kiov.iov_len : sizeof(quick);
        if (fn_copy_from_user(quick, kiov.iov_base, quick_len)) continue;
        if (contains_sensitive(quick, quick_len))
            sanitize_buffer(kiov.iov_base, (ssize_t)kiov.iov_len);
    }
}

/* ============================================================================
 * Layer 3: write / writev / pwritev hooks
 * ============================================================================ */

static void before_write(hook_fargs3_t *args, void *udata)
{
    int fd = (int)args->arg0;
    const char __user *ubuf = (const char __user *)args->arg1;
    size_t count = (size_t)args->arg2;
    char kbuf[QUERY_BUF_MAX];
    size_t copy_len;
    unsigned long not_copied;

    if (fd <= 2 || !ubuf || count < 5) return;
    if (!is_selinux_query_fd(fd)) return;
    if (!fn_copy_from_user) return;

    copy_len = (count < QUERY_BUF_MAX - 1) ? count : QUERY_BUF_MAX - 1;
    not_copied = fn_copy_from_user(kbuf, ubuf, copy_len);
    if (not_copied) return;
    kbuf[copy_len] = '\0';

    if (contains_dirty_context(kbuf, copy_len)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)count;
    }
}

static void before_writev(hook_fargs3_t *args, void *udata)
{
    int fd = (int)args->arg0;
    struct kpm_iovec __user *uiov = (struct kpm_iovec __user *)args->arg1;
    int iovcnt = (int)args->arg2;
    struct kpm_iovec kiov;
    char kbuf[QUERY_BUF_MAX];
    size_t copy_len;
    unsigned long not_copied;
    size_t total = 0;
    bool blocked = false;
    int i;

    if (fd <= 2 || !uiov || iovcnt <= 0) return;
    if (!is_selinux_query_fd(fd)) return;
    if (!fn_copy_from_user) return;

    for (i = 0; i < iovcnt && i < KPM_UIO_MAXIOV; i++) {
        if (fn_copy_from_user(&kiov, &uiov[i], sizeof(kiov))) continue;
        if (kiov.iov_base && kiov.iov_len > 0)
            total += kiov.iov_len;

        if (!blocked && kiov.iov_base && kiov.iov_len >= 5) {
            copy_len = (kiov.iov_len < QUERY_BUF_MAX - 1) ? kiov.iov_len : QUERY_BUF_MAX - 1;
            not_copied = fn_copy_from_user(kbuf, kiov.iov_base, copy_len);
            if (not_copied) continue;
            kbuf[copy_len] = '\0';
            if (contains_dirty_context(kbuf, copy_len))
                blocked = true;
        }
    }

    if (blocked) {
        args->skip_origin = 1;
        args->ret = (uint64_t)total;
    }
}

/* ============================================================================
 * Layer 4: getxattr / lgetxattr / fgetxattr hooks
 * ============================================================================ */

static void before_getxattr(hook_fargs4_t *args, void *udata)
{
    const char __user *upath = (const char __user *)args->arg0;
    const char __user *uname = (const char __user *)args->arg1;
    char name_buf[32] = {0};
    char path_buf[256] = {0};

    if (!upath || !uname || !fn_copy_from_user) return;

    if (fn_copy_from_user(name_buf, uname, sizeof(name_buf) - 1) != 0) return;
    if (strcmp(name_buf, "security.selinux") != 0) return;

    if (fn_copy_from_user(path_buf, upath, sizeof(path_buf) - 1) != 0) return;
    if (!is_sensitive_adb_path(path_buf)) return;

    args->skip_origin = 1;
    args->ret = (uint64_t)-ENODATA;
}

static void before_lgetxattr(hook_fargs4_t *args, void *udata)
{
    const char __user *upath = (const char __user *)args->arg0;
    const char __user *uname = (const char __user *)args->arg1;
    char name_buf[32] = {0};
    char path_buf[256] = {0};

    if (!upath || !uname || !fn_copy_from_user) return;

    if (fn_copy_from_user(name_buf, uname, sizeof(name_buf) - 1) != 0) return;
    if (strcmp(name_buf, "security.selinux") != 0) return;

    if (fn_copy_from_user(path_buf, upath, sizeof(path_buf) - 1) != 0) return;
    if (!is_sensitive_adb_path(path_buf)) return;

    args->skip_origin = 1;
    args->ret = (uint64_t)-ENODATA;
}

static void before_fgetxattr(hook_fargs4_t *args, void *udata)
{
    int fd = (int)args->arg0;
    const char __user *uname = (const char __user *)args->arg1;
    char name_buf[32] = {0};
    char path_buf[256];
    char *path_ptr;
    struct file *file;

    if (fd <= 2 || !uname || !fn_copy_from_user || !fn_fget || !fn_fput || !fn_d_path)
        return;

    if (fn_copy_from_user(name_buf, uname, sizeof(name_buf) - 1) != 0) return;
    if (strcmp(name_buf, "security.selinux") != 0) return;

    file = fn_fget(fd);
    if (!file) return;
    path_ptr = fn_d_path(&file->f_path, path_buf, sizeof(path_buf));
    fn_fput(file);

    if (path_ptr && is_sensitive_adb_path(path_ptr)) {
        args->skip_origin = 1;
        args->ret = (uint64_t)-ENODATA;
    }
}

/* ============================================================================
 * Init / Control0 / Exit
 * ============================================================================ */

static long avc_guard_init(const char *args, const char *event,
                           void *__user reserved)
{
    hook_err_t err;

    logkd("avc_guard: v2.2.1 init\n");

    /* Resolve all kernel symbols at runtime — zero external relocations */
    fn_audit_log_start = (audit_log_start_t)kallsyms_lookup_name("audit_log_start");
    fn_fget = (fget_t)kallsyms_lookup_name("fget");
    fn_fput = (fput_t)kallsyms_lookup_name("fput");
    fn_d_path = (d_path_t)kallsyms_lookup_name("d_path");
    fn_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    fn_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    fn_kmalloc = (kmalloc_t)kallsyms_lookup_name("kmalloc");
    fn_kfree = (kfree_t)kallsyms_lookup_name("kfree");

    /* L1 */
    if (fn_audit_log_start) {
        err = hook_wrap3(fn_audit_log_start, before_audit_log_start, NULL, 0);
        if (err == HOOK_NO_ERR) {
            g_l1_ok = true;
            logkd("avc_guard: L1 hooked audit_log_start@%p\n", fn_audit_log_start);
        } else {
            logkw("avc_guard: L1 hook failed err=%d\n", err);
        }
    } else {
        logkw("avc_guard: L1 audit_log_start not found\n");
    }

    /* L2 */
    err = fp_hook_syscalln(__NR_read, 3, NULL, after_read, 0);
    if (err == HOOK_NO_ERR) { g_l2_read_ok = true; logkd("avc_guard: L2 read hooked\n"); }
    else logkw("avc_guard: L2 read hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_pread64, 3, NULL, after_pread64, 0);
    if (err == HOOK_NO_ERR) { g_l2_pread64_ok = true; logkd("avc_guard: L2 pread64 hooked\n"); }
    else logkw("avc_guard: L2 pread64 hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_readv, 3, NULL, after_readv, 0);
    if (err == HOOK_NO_ERR) { g_l2_readv_ok = true; logkd("avc_guard: L2 readv hooked\n"); }
    else logkw("avc_guard: L2 readv hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_preadv, 4, NULL, after_readv, 0);
    if (err == HOOK_NO_ERR) { g_l2_preadv_ok = true; logkd("avc_guard: L2 preadv hooked\n"); }
    else logkw("avc_guard: L2 preadv hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_recvmsg, 3, NULL, after_recvmsg, 0);
    if (err == HOOK_NO_ERR) { g_l2_recvmsg_ok = true; logkd("avc_guard: L2 recvmsg hooked\n"); }
    else logkw("avc_guard: L2 recvmsg hook failed err=%d\n", err);

    /* L3 */
    err = fp_hook_syscalln(__NR_write, 3, before_write, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l3_write_ok = true; logkd("avc_guard: L3 write hooked\n"); }
    else logkw("avc_guard: L3 write hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_writev, 3, before_writev, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l3_writev_ok = true; logkd("avc_guard: L3 writev hooked\n"); }
    else logkw("avc_guard: L3 writev hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_pwritev, 4, before_writev, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l3_pwritev_ok = true; logkd("avc_guard: L3 pwritev hooked\n"); }
    else logkw("avc_guard: L3 pwritev hook failed err=%d\n", err);

    /* L4 */
    err = fp_hook_syscalln(__NR_getxattr, 4, before_getxattr, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l4_getxattr_ok = true; logkd("avc_guard: L4 getxattr hooked\n"); }
    else logkw("avc_guard: L4 getxattr hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_lgetxattr, 4, before_lgetxattr, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l4_lgetxattr_ok = true; logkd("avc_guard: L4 lgetxattr hooked\n"); }
    else logkw("avc_guard: L4 lgetxattr hook failed err=%d\n", err);

    err = fp_hook_syscalln(__NR_fgetxattr, 4, before_fgetxattr, NULL, 0);
    if (err == HOOK_NO_ERR) { g_l4_fgetxattr_ok = true; logkd("avc_guard: L4 fgetxattr hooked\n"); }
    else logkw("avc_guard: L4 fgetxattr hook failed err=%d\n", err);

    logkd("avc_guard: init done L1=%s L2r=%s L2p=%s L2v=%s L2pv=%s L2m=%s L3w=%s L3v=%s L3pv=%s L4g=%s L4l=%s L4f=%s\n",
          g_l1_ok ? "OK" : "FAIL",
          g_l2_read_ok ? "OK" : "FAIL",
          g_l2_pread64_ok ? "OK" : "FAIL",
          g_l2_readv_ok ? "OK" : "FAIL",
          g_l2_preadv_ok ? "OK" : "FAIL",
          g_l2_recvmsg_ok ? "OK" : "FAIL",
          g_l3_write_ok ? "OK" : "FAIL",
          g_l3_writev_ok ? "OK" : "FAIL",
          g_l3_pwritev_ok ? "OK" : "FAIL",
          g_l4_getxattr_ok ? "OK" : "FAIL",
          g_l4_lgetxattr_ok ? "OK" : "FAIL",
          g_l4_fgetxattr_ok ? "OK" : "FAIL");

    return 0;
}

static long avc_guard_control0(const char *args, char *__user out_msg,
                               int outlen)
{
    char msg[384];
    int len;
    size_t copy_len;

    len = snprintf(msg, sizeof(msg),
        "avc_guard v2.2.1 status:\n"
        " L1 audit_log_start : %s\n"
        " L2 read            : %s\n"
        " L2 pread64         : %s\n"
        " L2 readv           : %s\n"
        " L2 preadv          : %s\n"
        " L2 recvmsg         : %s\n"
        " L3 write           : %s\n"
        " L3 writev          : %s\n"
        " L3 pwritev         : %s\n"
        " L4 getxattr        : %s\n"
        " L4 lgetxattr       : %s\n"
        " L4 fgetxattr       : %s\n",
        g_l1_ok ? "OK" : "FAIL",
        g_l2_read_ok ? "OK" : "FAIL",
        g_l2_pread64_ok ? "OK" : "FAIL",
        g_l2_readv_ok ? "OK" : "FAIL",
        g_l2_preadv_ok ? "OK" : "FAIL",
        g_l2_recvmsg_ok ? "OK" : "FAIL",
        g_l3_write_ok ? "OK" : "FAIL",
        g_l3_writev_ok ? "OK" : "FAIL",
        g_l3_pwritev_ok ? "OK" : "FAIL",
        g_l4_getxattr_ok ? "OK" : "FAIL",
        g_l4_lgetxattr_ok ? "OK" : "FAIL",
        g_l4_fgetxattr_ok ? "OK" : "FAIL");

    if (out_msg && outlen > 0) {
        copy_len = (size_t)(len + 1) < (size_t)outlen ? (size_t)(len + 1) : (size_t)outlen;
        compat_copy_to_user(out_msg, msg, copy_len);
    }
    return 0;
}

static long avc_guard_exit(void *__user reserved)
{
    logkd("avc_guard: exiting\n");

    if (g_l1_ok && fn_audit_log_start)
        hook_unwrap(fn_audit_log_start, before_audit_log_start, NULL);

    if (g_l2_read_ok)
        fp_unhook_syscalln(__NR_read, NULL, after_read);
    if (g_l2_pread64_ok)
        fp_unhook_syscalln(__NR_pread64, NULL, after_pread64);
    if (g_l2_readv_ok)
        fp_unhook_syscalln(__NR_readv, NULL, after_readv);
    if (g_l2_preadv_ok)
        fp_unhook_syscalln(__NR_preadv, NULL, after_readv);
    if (g_l2_recvmsg_ok)
        fp_unhook_syscalln(__NR_recvmsg, NULL, after_recvmsg);

    if (g_l3_write_ok)
        fp_unhook_syscalln(__NR_write, before_write, NULL);
    if (g_l3_writev_ok)
        fp_unhook_syscalln(__NR_writev, before_writev, NULL);
    if (g_l3_pwritev_ok)
        fp_unhook_syscalln(__NR_pwritev, before_writev, NULL);

    if (g_l4_getxattr_ok)
        fp_unhook_syscalln(__NR_getxattr, before_getxattr, NULL);
    if (g_l4_lgetxattr_ok)
        fp_unhook_syscalln(__NR_lgetxattr, before_lgetxattr, NULL);
    if (g_l4_fgetxattr_ok)
        fp_unhook_syscalln(__NR_fgetxattr, before_fgetxattr, NULL);

    return 0;
}

KPM_NAME("avc_guard");
KPM_VERSION("2.2.1");
KPM_AUTHOR("ai-assisted");
KPM_LICENSE("GPL-2.0-or-later");
KPM_DESCRIPTION("SELinux/AVC audit log sanitization for SukiSU");

KPM_INIT(avc_guard_init);
KPM_CTL0(avc_guard_control0);
KPM_EXIT(avc_guard_exit);
