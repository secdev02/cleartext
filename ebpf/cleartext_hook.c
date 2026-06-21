/*
 * cleartext_hook.c — eBPF uprobe program for intercepting SSL_write / SSL_read
 *
 * SSL_write:  emits on ENTRY — buffer and length are known at call time.
 * SSL_read:   emits on RETURN — actual byte count only known after the call.
 *
 * This split means SSL_write capture works even when uretprobes fail
 * (a known aarch64 kernel quirk with certain function prologues).
 *
 * Large event struct (4 KB payload) lives in a BPF_PERCPU_ARRAY to stay
 * within the 512-byte eBPF stack limit.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE  4096
#define MAX_COMM_LEN  16

struct tls_event_t {
    u32  pid;
    u32  tid;
    char comm[MAX_COMM_LEN];
    u64  timestamp_ns;
    u32  data_len;
    u8   is_write;
    u8   buf[MAX_BUF_SIZE];
};

BPF_PERF_OUTPUT(tls_events);
BPF_PERCPU_ARRAY(event_scratch, struct tls_event_t, 1);

/* Stash read-buffer pointer between SSL_read entry and return */
struct pending_t {
    u64  buf_addr;
    u32  buf_len;
};
BPF_HASH(pending_map, u64, struct pending_t);

/* ── emit helper ─────────────────────────────────────────────────────────── */
static __always_inline void emit(struct pt_regs *ctx,
                                 void *buf_ptr, u32 len, u8 is_write)
{
    u32 zero = 0;
    struct tls_event_t *ev = event_scratch.lookup(&zero);
    if (!ev) return;

    u64 id = bpf_get_current_pid_tgid();
    ev->pid          = (u32)(id >> 32);
    ev->tid          = (u32)id;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->is_write     = is_write;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    u32 copy_len = len < MAX_BUF_SIZE ? len : MAX_BUF_SIZE;
    ev->data_len = copy_len;
    bpf_probe_read_user(ev->buf, copy_len, buf_ptr);

    tls_events.perf_submit(ctx, ev, sizeof(*ev));
}

/* ══ SSL_write — emit at ENTRY (buf + len known here) ══════════════════════ */
int uprobe__SSL_write(struct pt_regs *ctx)
{
    void *buf = (void *)PT_REGS_PARM2(ctx);
    u32   len = (u32)  PT_REGS_PARM3(ctx);
    emit(ctx, buf, len, 1);
    return 0;
}
/* uretprobe kept so Python can attach it when the kernel supports it,
   but it's a no-op — the entry probe already captured everything. */
int uretprobe__SSL_write(struct pt_regs *ctx) { return 0; }

/* ══ SSL_write_ex — emit at ENTRY ══════════════════════════════════════════ */
int uprobe__SSL_write_ex(struct pt_regs *ctx)
{
    void *buf = (void *)PT_REGS_PARM2(ctx);
    u32   len = (u32)  PT_REGS_PARM3(ctx);
    emit(ctx, buf, len, 1);
    return 0;
}
int uretprobe__SSL_write_ex(struct pt_regs *ctx) { return 0; }

/* ══ SSL_read — stash at entry, emit at RETURN with actual byte count ══════ */
int uprobe__SSL_read(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p;
    p.buf_addr = (u64)(uintptr_t)PT_REGS_PARM2(ctx);
    p.buf_len  = (u32)PT_REGS_PARM3(ctx);
    pending_map.update(&id, &p);
    return 0;
}
int uretprobe__SSL_read(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_map.lookup(&id);
    if (!p) return 0;
    int ret = PT_REGS_RC(ctx);
    if (ret > 0)
        emit(ctx, (void *)(uintptr_t)p->buf_addr, (u32)ret, 0);
    pending_map.delete(&id);
    return 0;
}

/* ══ SSL_read_ex ════════════════════════════════════════════════════════════ */
int uprobe__SSL_read_ex(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p;
    p.buf_addr = (u64)(uintptr_t)PT_REGS_PARM2(ctx);
    p.buf_len  = (u32)PT_REGS_PARM3(ctx);
    pending_map.update(&id, &p);
    return 0;
}
int uretprobe__SSL_read_ex(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_map.lookup(&id);
    if (!p) return 0;
    int ret = PT_REGS_RC(ctx);
    if (ret > 0)
        emit(ctx, (void *)(uintptr_t)p->buf_addr, (u32)ret, 0);
    pending_map.delete(&id);
    return 0;
}
