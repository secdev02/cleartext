# cleartext

> eBPF uprobe TLS interceptor — read plaintext before the cipher touches it.

```
   ___  _                  _____         _
  / __\| |  ___  __ _  _ _/__   \ ___ __| |_
 / /   | | / _ \/ _` || '__|/ /\// _ \\ __|
/ /___ | ||  __| (_| || |  / /  |  __/\__ \
\____/ |_| \___|\__,_||_|  \/    \___||___/
```

cleartext attaches `uprobe`s to `SSL_write` and `SSL_read` inside `libssl.so`
(OpenSSL 1.1.1 / 3.x, BoringSSL), capturing plaintext **before encryption** and
**after decryption** — no keys, no MITM, no certificate pinning issues.

---

## How it works

```
Application
    │
    ▼  SSL_write(ssl, buf, len)    ← uprobe fires HERE (buf = plaintext)
┌─────────────┐
│  libssl.so  │  TLS 1.3 encrypt
└─────────────┘
    │
    ▼  UDP → QUIC frames → network
```

Data flows via a `BPF_PERF_OUTPUT` ring-buffer to userspace, capped at 4 096
bytes per event to stay within eBPF stack limits.

---

## Files

```
cleartext/
├── ebpf/
│   └── cleartext_hook.c     eBPF C program (BCC-style, auto-compiled)
├── scripts/
│   ├── tls_trace.bt         bpftrace one-liner (no BCC needed)
│   └── parse_capture.py     Inspect / filter captured JSON-lines files
├── cleartext.py             Main loader (Python + BCC)
└── README.md
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Linux kernel ≥ 4.14 | uprobe + perf ring-buffer support |
| Root / `CAP_BPF` | Required for eBPF |
| `python3-bpfcc` | `sudo apt install python3-bpfcc bpfcc-tools` |
| `libssl.so` | OpenSSL or BoringSSL |
| `bpftrace` ≥ 0.12 | Only for the `.bt` alternative |

---

## Quick Start

### Option A — Python / BCC (full featured)

```bash
# Install deps (once)
sudo apt install python3-bpfcc bpfcc-tools

# Capture all TLS traffic system-wide
sudo python3 cleartext.py

# Capture only a specific PID
sudo python3 cleartext.py -p 1234

# Filter by process name, save to file, show hex dumps
sudo python3 cleartext.py -n curl -o capture.jsonl -x

# Custom libssl path (e.g. BoringSSL bundled in Chrome)
sudo python3 cleartext.py -l /opt/google/chrome/libssl.so

# Quiet mode — write to file only, no terminal output
sudo python3 cleartext.py -q -o capture.jsonl
```

### Option B — bpftrace (lightweight, no BCC)

```bash
sudo bpftrace scripts/tls_trace.bt
```

Edit the `uprobe:` path in the script if your `libssl.so` lives elsewhere.

---

## Analysing a Capture

```bash
# Full pretty-print
python3 scripts/parse_capture.py capture.jsonl

# Only HTTP writes containing "Authorization"
python3 scripts/parse_capture.py capture.jsonl --direction write --grep "Authorization"

# Summary stats only
python3 scripts/parse_capture.py capture.jsonl --stats

# Filter by PID with hex dump
python3 scripts/parse_capture.py capture.jsonl --pid 1234 --hex
```

---

## eBPF Hooks

| Symbol | Trigger | Captured |
|---|---|---|
| `SSL_write` | entry + uretprobe | `arg1` buf, `arg2` len |
| `SSL_write_ex` | entry + uretprobe | OpenSSL 1.1.1+ variant |
| `SSL_read` | entry + uretprobe | buf after decrypt, `retval` bytes |
| `SSL_read_ex` | entry + uretprobe | OpenSSL 1.1.1+ variant |

---

## Troubleshooting

**"Cannot find libssl.so"**
```bash
sudo python3 cleartext.py -l $(ldconfig -p | grep libssl | head -1 | awk '{print $NF}')
```

**"Failed to attach SSL_write"** — library may be stripped:
```bash
nm -D /path/to/libssl.so | grep SSL_write
```

**Chrome / Firefox use bundled BoringSSL:**
```bash
cat /proc/$(pgrep -n chrome)/maps | grep ssl
# then: sudo python3 cleartext.py -l <that path>
```

---

## Legal / Ethics

Use only on systems and traffic you own or have explicit written permission to inspect.
Intercepting traffic without authorisation is illegal in most jurisdictions.
