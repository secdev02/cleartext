/*
 * cleartext_hook.c — eBPF uprobe program for intercepting SSL_write / SSL_read
 *
 * Attaches uprobes to SSL_write and SSL_read in libssl.so (OpenSSL / BoringSSL).
 * Captures plaintext before encryption (write) and after decryption (read).
 *
 * Build / load via the Python loader (cleartext.py), which uses BCC.
 *
 * Kernel requirements: Linux 4.14+, CONFIG_BPF_SYSCALL=y, CONFIG_UPROBE_EVENTS=y
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ── tunables ───────────────────────────────────────────────────────────── */
#define MAX_BUF_SIZE   4096   /* max bytes captured per event               */
#define MAX_COMM_LEN   16     /* length of task->comm                        */

/* ── shared event structure sent to user-space via perf ring-buffer ─────── */
struct tls_event_t {
    u32  pid;
    u32  tid;
    char comm[MAX_COMM_LEN];
    u64  timestamp_ns;
    u32  data_len;            /* actual bytes in buf (capped at MAX_BUF_SIZE) */
    u8   is_write;            /* 1 = SSL_write, 0 = SSL_read                 */
    u8   buf[MAX_BUF_SIZE];
};

/* ── perf output map ─────────────────────────────────────────────────────── */
BPF_PERF_OUTPUT(tls_events);

/* ── scratch map: stash (buf, len) between entry and return probes ───────── */
struct pending_t {
    u64  buf_addr;   /* user-space pointer to plaintext buffer               */
    u32  buf_len;    /* requested length                                      */
};
BPF_HASH(pending_map, u64, struct pending_t);   /* key = pid_tgid            */

/* ── helper: record (buf_ptr, len) at function entry ────────────────────── */
static __always_inline void record_entry(struct pt_regs *ctx,
                                         void *buf, int len)
{
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.buf_addr = (u64)(uintptr_t)buf;
    p.buf_len  = (u32)len;
    pending_map.update(&id, &p);
}

/* ── helper: emit event on function return ───────────────────────────────── */
static __always_inline void emit_return(struct pt_regs *ctx, u8 is_write)
{
    u64 id = bpf_get_current_pid_tgid();

    struct pending_t *p = pending_map.lookup(&id);
    if (!p) return;

    /* For SSL_read the return value is the actual bytes read; use that. */
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        pending_map.delete(&id);
        return;
    }

    struct tls_event_t ev_stack = {};
    ev_stack.pid          = (u32)(id >> 32);
    ev_stack.tid          = (u32)id;
    ev_stack.timestamp_ns = bpf_ktime_get_ns();
    ev_stack.is_write     = is_write;

    bpf_get_current_comm(ev_stack.comm, sizeof(ev_stack.comm));

    /* Determine how many bytes to copy */
    u32 copy_len = is_write ? p->buf_len : (u32)ret;
    if (copy_len > MAX_BUF_SIZE) copy_len = MAX_BUF_SIZE;
    ev_stack.data_len = copy_len;

    /* bpf_probe_read_user: read plaintext from user-space buffer */
    bpf_probe_read_user(ev_stack.buf, copy_len, (void *)(uintptr_t)p->buf_addr);

    tls_events.perf_submit(ctx, &ev_stack, sizeof(ev_stack));
    pending_map.delete(&id);
}

/* ════════════════════════════════════════════════════════════════════════════
 * SSL_write(SSL *ssl, const void *buf, int num)
 *                arg0        arg1           arg2
 * ════════════════════════════════════════════════════════════════════════════ */
int uprobe__SSL_write(struct pt_regs *ctx)
{
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int   len = (int)  PT_REGS_PARM3(ctx);
    record_entry(ctx, buf, len);
    return 0;
}

int uretprobe__SSL_write(struct pt_regs *ctx)
{
    emit_return(ctx, /*is_write=*/1);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * SSL_read(SSL *ssl, void *buf, int num)
 *               arg0    arg1       arg2
 * ════════════════════════════════════════════════════════════════════════════ */
int uprobe__SSL_read(struct pt_regs *ctx)
{
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int   len = (int)  PT_REGS_PARM3(ctx);
    record_entry(ctx, buf, len);
    return 0;
}

int uretprobe__SSL_read(struct pt_regs *ctx)
{
    emit_return(ctx, /*is_write=*/0);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
 *  (OpenSSL 1.1.1+)
 * ════════════════════════════════════════════════════════════════════════════ */
int uprobe__SSL_write_ex(struct pt_regs *ctx)
{
    void  *buf = (void *) PT_REGS_PARM2(ctx);
    size_t len = (size_t) PT_REGS_PARM3(ctx);
    record_entry(ctx, buf, (int)len);
    return 0;
}

int uretprobe__SSL_write_ex(struct pt_regs *ctx)
{
    emit_return(ctx, /*is_write=*/1);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
 * ════════════════════════════════════════════════════════════════════════════ */
int uprobe__SSL_read_ex(struct pt_regs *ctx)
{
    void  *buf = (void *) PT_REGS_PARM2(ctx);
    size_t len = (size_t) PT_REGS_PARM3(ctx);
    record_entry(ctx, buf, (int)len);
    return 0;
}

int uretprobe__SSL_read_ex(struct pt_regs *ctx)
{
    emit_return(ctx, /*is_write=*/0);
    return 0;
}
