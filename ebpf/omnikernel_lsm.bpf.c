// SPDX-License-Identifier: GPL-2.0
//
// OmniKernel eBPF LSM programs
//
// Requirements: Linux >= 5.13, CONFIG_BPF_LSM=y, BTF-enabled kernel.
//
// Two hooks are provided:
//   lsm/file_open          — monitors and optionally enforces file access
//   lsm/bprm_check_security — monitors and optionally enforces execution
//
// Events are written to the `security_events` ring buffer and consumed by the
// Rust daemon.  The `whitelist` map is populated at startup from
// SecurityPolicy::allowed_paths.
//
// `enforcement_mode`:
//   0 (default) — audit only; all access is permitted; events are emitted.
//   1           — enforce;   access not in the whitelist is denied (EPERM).
//
// The Rust daemon can flip enforcement_mode at runtime via a BPF global.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH_LEN    256
#define RINGBUF_SIZE    (1 << 20)   /* 1 MiB */
#define EPERM           1

/* ── Maps ────────────────────────────────────────────────────────────────── */

/**
 * Path whitelist — populated by the Rust daemon at startup.
 * Key  : NUL-padded path string (256 bytes, exact match).
 * Value: 1 = allowed.
 *
 * Note: the eBPF verifier requires exact-length map keys, so path matching
 * is exact.  Prefix-matching is handled in userspace by the event consumer.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         char[MAX_PATH_LEN]);
    __type(value,       __u8);
} whitelist SEC(".maps");

/**
 * Security event ring buffer — consumed asynchronously by the Rust daemon.
 * Each entry is a fixed-size `struct security_event` (272 bytes).
 */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} security_events SEC(".maps");

/* ── Globals (writable from userspace via BPF skeleton / map-of-globals) ── */

/**
 * 0 = audit only (default, safe for initial rollout)
 * 1 = enforce    (deny access not in the whitelist)
 */
volatile const __u32 enforcement_mode = 0;

/* ── Event struct ────────────────────────────────────────────────────────── */

/**
 * Layout must match the Rust `process_event` parser in security/ebpf.rs:
 *   offset  0 : u32  pid       (4 bytes)
 *   offset  4 : u32  uid       (4 bytes)
 *   offset  8 : u8   operation (1 byte) — 0=file_open, 1=exec
 *   offset  9 : u8   pad[3]   (3 bytes)
 *   offset 12 : char path[256] (256 bytes)
 *   offset 268: i32  verdict   (4 bytes) — 0=allow, -EPERM=deny
 *   total     : 272 bytes
 */
struct security_event {
    __u32 pid;
    __u32 uid;
    __u8  operation;
    __u8  pad[3];
    char  path[MAX_PATH_LEN];
    __s32 verdict;
};

/* ── Helper ──────────────────────────────────────────────────────────────── */

/**
 * Resolve the kernel path to a string, check the whitelist, emit a ring-buffer
 * event, and return 0 (allow) or -EPERM (deny) depending on enforcement_mode.
 */
static __always_inline int
audit_and_enforce(struct path *fpath, __u8 op)
{
    char buf[MAX_PATH_LEN] = {};
    __u8 *val;
    __s32 verdict = 0;

    /* bpf_d_path resolves dentry→full path; returns < 0 on failure.
     * Only available in LSM context (kernel >= 5.9).                    */
    long rc = bpf_d_path(fpath, buf, sizeof(buf));
    if (rc < 0)
        return 0;   /* allow when path cannot be resolved */

    val = bpf_map_lookup_elem(&whitelist, buf);
    if (!val && enforcement_mode)
        verdict = -EPERM;

    /* Always emit to ring buffer regardless of verdict (audit + enforce). */
    struct security_event *evt =
        bpf_ringbuf_reserve(&security_events, sizeof(*evt), 0);
    if (evt) {
        evt->pid       = bpf_get_current_pid_tgid() >> 32;
        evt->uid       = bpf_get_current_uid_gid() & 0xffffffffU;
        evt->operation = op;
        evt->pad[0]    = 0;
        evt->pad[1]    = 0;
        evt->pad[2]    = 0;
        evt->verdict   = verdict;
        __builtin_memcpy(evt->path, buf, MAX_PATH_LEN);
        bpf_ringbuf_submit(evt, 0);
    }

    return verdict;
}

/* ── LSM hooks ───────────────────────────────────────────────────────────── */

SEC("lsm/file_open")
int BPF_PROG(omnikernel_file_open, struct file *file, int mask)
{
    return audit_and_enforce(&file->f_path, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(omnikernel_exec, struct linux_binprm *bprm)
{
    struct file *f = BPF_CORE_READ(bprm, file);
    if (!f)
        return 0;
    return audit_and_enforce(&f->f_path, 1);
}

