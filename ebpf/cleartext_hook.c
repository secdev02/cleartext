/*
 * cleartext_hook.c — eBPF uprobe program for intercepting SSL_write / SSL_read
 *
 * Attaches uprobes to SSL_write and SSL_read in libssl.so (OpenSSL / BoringSSL).
 * Captures plaintext before encryption (write) and after decryption (read).
 *
 * Build / load via the Python loader (cleartext.py), which uses BCC.
 *
 * Kernel requirements: Linux 4.14+, CONFIG_BPF_SYSCALL=y, CONFIG_UPROBE_EVENTS=y
 *
 * Design note: tls_event_t contains a 4096-byte payload buffer which exceeds
 * the eBPF stack limit (512 bytes). It lives in a BPF_PERCPU_ARRAY instead,
 * which avoids both the stack overflow and any memset on the stack.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ── tunables ───────────────────────────────────────────────────────────── */
#define MAX_BUF_SIZE   4096
#define MAX_COMM_LEN   16

/* ── event structure (kept off-stack in percpu array) ───────────────────── */
struct tls_event_t {
    u32  pid;
    u32  tid;
    char comm[MAX_COMM_LEN];
    u64  timestamp_ns;
    u32  data_len;
    u8   is_write;
    u8   buf[MAX_BUF_SIZE];
};

/* ── maps ────────────────────────────────────────────────────────────────── */
BPF_PERF_OUTPUT(tls_events);

/* Single-slot percpu scratch buffer — avoids 4 KB on the eBPF stack */
BPF_PERCPU_ARRAY(event_scratch, struct tls_event_t, 1);

/* Stash buf pointer + length between entry and return probes */
struct pending_t {
    u64  buf_addr;
    u32  buf_len;
};
BPF_HASH(pending_map, u64, struct pending_t);

/* ── entry probe helper ──────────────────────────────────────────────────── */
static __always_inline void record_entry(struct pt_regs *ctx,
                                         void *buf, int len)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p;
    p.buf_addr = (u64)(uintptr_t)buf;
    p.buf_len  = (u32)len;
    pending_map.update(&id, &p);
}

/* ── return probe helper ─────────────────────────────────────────────────── */
static __always_inline void emit_return(struct pt_regs *ctx, u8 is_write)
{
    u64 id = bpf_get_current_pid_tgid();

    struct pending_t *p = pending_map.lookup(&id);
    if (!p) return;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        pending_map.delete(&id);
        return;
    }

    /* Grab percpu scratch slot — always index 0 */
    u32 zero = 0;
    struct tls_event_t *ev = event_scratch.lookup(&zero);
    if (!ev) {
        pending_map.delete(&id);
        return;
    }

    ev->pid          = (u32)(id >> 32);
    ev->tid          = (u32)id;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->is_write     = is_write;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    u32 copy_len = is_write ? p->buf_len : (u32)ret;
    if (copy_len > MAX_BUF_SIZE) copy_len = MAX_BUF_SIZE;
    ev->data_len = copy_len;

    bpf_probe_read_user(ev->buf, copy_len, (void *)(uintptr_t)p->buf_addr);

    tls_events.perf_submit(ctx, ev, sizeof(*ev));
    pending_map.delete(&id);
}

/* ══ SSL_write ══════════════════════════════════════════════════════════════ */
int uprobe__SSL_write(struct pt_regs *ctx)
{
    record_entry(ctx, (void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx));
    return 0;
}
int uretprobe__SSL_write(struct pt_regs *ctx)
{
    emit_return(ctx, 1);
    return 0;
}

/* ══ SSL_read ═══════════════════════════════════════════════════════════════ */
int uprobe__SSL_read(struct pt_regs *ctx)
{
    record_entry(ctx, (void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx));
    return 0;
}
int uretprobe__SSL_read(struct pt_regs *ctx)
{
    emit_return(ctx, 0);
    return 0;
}

/* ══ SSL_write_ex (OpenSSL 1.1.1+) ═════════════════════════════════════════ */
int uprobe__SSL_write_ex(struct pt_regs *ctx)
{
    record_entry(ctx, (void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx));
    return 0;
}
int uretprobe__SSL_write_ex(struct pt_regs *ctx)
{
    emit_return(ctx, 1);
    return 0;
}

/* ══ SSL_read_ex (OpenSSL 1.1.1+) ══════════════════════════════════════════ */
int uprobe__SSL_read_ex(struct pt_regs *ctx)
{
    record_entry(ctx, (void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx));
    return 0;
}
int uretprobe__SSL_read_ex(struct pt_regs *ctx)
{
    emit_return(ctx, 0);
    return 0;
}
