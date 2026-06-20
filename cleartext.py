#!/usr/bin/env python3
"""
cleartext — eBPF TLS plaintext interceptor

Attaches uprobes to SSL_write / SSL_read in libssl.so (OpenSSL or BoringSSL),
captures plaintext data in-flight, and streams events to stdout or a JSON log file.

Usage:
    sudo python3 cleartext.py [options]

Options:
    -p PID         Only capture traffic from this PID
    -n NAME        Filter by process name (substring match)
    -l LIBSSL      Path to libssl.so  (auto-detected if omitted)
    -o FILE        Write captured events as JSON lines to FILE
    -x             Also print hex dump of each payload
    -q             Quiet mode: only write to output file, no stdout
    --max-bytes N  Truncate displayed payload to N bytes  [default: 512]
"""

import argparse
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── BCC import (provided by python3-bpfcc) ────────────────────────────────
try:
    from bcc import BPF
except ImportError:
    sys.exit(
        "[!] python3-bpfcc not found.\n"
        "    Install:  sudo apt install python3-bpfcc bpfcc-tools"
    )

# ── ANSI colour helpers ───────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def colour(text: str, code: str) -> str:
    return code + text + RESET if sys.stdout.isatty() else text

# ── Locate libssl.so ──────────────────────────────────────────────────────
LIBSSL_CANDIDATES = [
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1",
    "/usr/local/lib/libssl.so.3",
    "/usr/local/lib/libssl.so.1.1",
]

def find_libssl() -> str:
    """Return path to libssl.so, searching well-known locations and ldconfig."""
    for path in LIBSSL_CANDIDATES:
        if Path(path).exists():
            return path
    # Fallback: ask ldconfig
    try:
        out = subprocess.check_output(["ldconfig", "-p"], text=True)
        for line in out.splitlines():
            if "libssl.so" in line and "=>" in line:
                return line.split("=>")[-1].strip()
    except Exception:
        pass
    sys.exit("[!] Cannot find libssl.so. Pass -l <path> explicitly.")

# ── Check symbols present in the library ──────────────────────────────────
def probe_symbols(libssl: str) -> list[str]:
    """Return list of SSL_* symbols present in the library."""
    want = ["SSL_write", "SSL_read", "SSL_write_ex", "SSL_read_ex"]
    found: list[str] = []
    try:
        out = subprocess.check_output(["nm", "-D", libssl], text=True, stderr=subprocess.DEVNULL)
        for sym in want:
            if re.search(r'\b' + sym + r'\b', out):
                found.append(sym)
    except Exception:
        # nm not available — assume all present
        found = want
    return found

# ── eBPF C source (embedded) ───────────────────────────────────────────────
EBPF_SOURCE_PATH = Path(__file__).parent / "ebpf" / "cleartext_hook.c"

def load_ebpf_source() -> str:
    if EBPF_SOURCE_PATH.exists():
        return EBPF_SOURCE_PATH.read_text()
    sys.exit("[!] eBPF source not found: " + str(EBPF_SOURCE_PATH))

# ── ctypes mirror of tls_event_t ──────────────────────────────────────────
MAX_BUF_SIZE = 4096

class TlsEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("comm",         ctypes.c_char * 16),
        ("timestamp_ns", ctypes.c_uint64),
        ("data_len",     ctypes.c_uint32),
        ("is_write",     ctypes.c_uint8),
        ("buf",          ctypes.c_uint8 * MAX_BUF_SIZE),
    ]

# ── Hex dump helper ────────────────────────────────────────────────────────
def hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part  = " ".join("{:02x}".format(b) for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("  {:04x}  {:<{}}  {}".format(i, hex_part, width * 3, ascii_part))
    return "\n".join(lines)

# ── Pretty-print a single event ────────────────────────────────────────────
def print_event(ev: TlsEvent, args: argparse.Namespace) -> None:
    direction = "WRITE →" if ev.is_write else "READ  ←"
    dir_colour = GREEN if ev.is_write else CYAN
    ts = datetime.fromtimestamp(ev.timestamp_ns / 1e9, tz=timezone.utc)
    ts_str = ts.strftime("%H:%M:%S.%f")[:-3]

    payload = bytes(ev.buf[: ev.data_len])
    display = payload[: args.max_bytes]

    print(colour("─" * 72, DIM))
    print(
        colour(ts_str, DIM),
        colour(direction, dir_colour + BOLD),
        colour(ev.comm.decode(errors="replace"), YELLOW),
        colour("pid=" + str(ev.pid), DIM),
        colour(str(ev.data_len) + " bytes", BOLD),
    )
    # Try UTF-8 first; fall back to hex
    try:
        text = display.decode("utf-8")
        print(colour("  [utf-8]", DIM))
        for line in text.splitlines()[:20]:
            print("  " + line)
    except UnicodeDecodeError:
        print(colour("  [binary]", DIM))
        if args.hex:
            print(hexdump(display))
        else:
            print("  " + display.hex(" "))
    if ev.data_len > args.max_bytes:
        print(colour("  … ({} bytes truncated)".format(ev.data_len - args.max_bytes), DIM))

# ── JSON event serialiser ─────────────────────────────────────────────────
def event_to_dict(ev: TlsEvent) -> dict:
    payload = bytes(ev.buf[: ev.data_len])
    try:
        text: str | None = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        "timestamp_ns":  ev.timestamp_ns,
        "timestamp_iso": datetime.fromtimestamp(
            ev.timestamp_ns / 1e9, tz=timezone.utc
        ).isoformat(),
        "pid":       ev.pid,
        "tid":       ev.tid,
        "comm":      ev.comm.decode(errors="replace"),
        "direction": "write" if ev.is_write else "read",
        "data_len":  ev.data_len,
        "hex":       payload.hex(),
        "text":      text,
    }

# ── Main ───────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Intercept TLS plaintext via eBPF uprobes on SSL_write/SSL_read",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("-p", "--pid",       type=int,  help="Filter by PID")
    ap.add_argument("-n", "--name",      type=str,  help="Filter by process name substring")
    ap.add_argument("-l", "--libssl",    type=str,  help="Path to libssl.so")
    ap.add_argument("-o", "--output",    type=str,  help="JSON-lines output file")
    ap.add_argument("-x", "--hex",       action="store_true", help="Print hex dump")
    ap.add_argument("-q", "--quiet",     action="store_true", help="Suppress stdout")
    ap.add_argument("--max-bytes",       type=int,  default=512,
                    dest="max_bytes",               help="Max payload bytes to display")
    return ap.parse_args()


BANNER = r"""
   ___  _                  _____         _
  / __\| |  ___  __ _  _ _/__   \ ___ __| |_
 / /   | | / _ \/ _` || '__|/ /\// _ \\ __|
/ /___ | ||  __| (_| || |  / /  |  __/\__ \
\____/ |_| \___|\__,_||_|  \/    \___||___/

  eBPF TLS plaintext interceptor  |  SSL_write / SSL_read uprobes
"""

def main() -> None:
    args = parse_args()

    if not args.quiet:
        print(colour(BANNER, CYAN))

    if os.geteuid() != 0:
        sys.exit("[!] Root privileges required (re-run with sudo).")

    libssl = args.libssl or find_libssl()
    print(colour("[*] Using libssl: " + libssl, CYAN))

    symbols = probe_symbols(libssl)
    print(colour("[*] Symbols found: " + ", ".join(symbols), CYAN))
    if not symbols:
        sys.exit("[!] No SSL_write/SSL_read symbols found in " + libssl)

    # ── Load and compile eBPF program ─────────────────────────────────────
    src = load_ebpf_source()
    print(colour("[*] Compiling eBPF program …", CYAN))
    try:
        bpf = BPF(text=src)
    except Exception as exc:
        sys.exit("[!] BPF compilation failed:\n" + str(exc))

    # ── Attach uprobes for each symbol found ──────────────────────────────
    sym_map = {
        "SSL_write":    ("uprobe__SSL_write",    "uretprobe__SSL_write"),
        "SSL_read":     ("uprobe__SSL_read",     "uretprobe__SSL_read"),
        "SSL_write_ex": ("uprobe__SSL_write_ex", "uretprobe__SSL_write_ex"),
        "SSL_read_ex":  ("uprobe__SSL_read_ex",  "uretprobe__SSL_read_ex"),
    }

    attached: list[str] = []
    for sym, (entry_fn, ret_fn) in sym_map.items():
        if sym not in symbols:
            continue
        try:
            bpf.attach_uprobe(  name=libssl, sym=sym, fn_name=entry_fn, pid=args.pid or -1)
            bpf.attach_uretprobe(name=libssl, sym=sym, fn_name=ret_fn,  pid=args.pid or -1)
            attached.append(sym)
        except Exception as exc:
            print(colour("[!] Failed to attach " + sym + ": " + str(exc), RED))

    if not attached:
        sys.exit("[!] No probes attached — aborting.")

    print(colour("[+] Attached probes: " + ", ".join(attached), GREEN))
    if args.pid:
        print(colour("    Filtering on PID " + str(args.pid), DIM))
    if args.name:
        print(colour("    Filtering on name '" + args.name + "'", DIM))
    print(colour("[*] Capturing TLS traffic — press Ctrl-C to stop.\n", CYAN))

    # ── Open optional output file ──────────────────────────────────────────
    outfile = open(args.output, "w") if args.output else None
    event_count = 0

    # ── Perf ring-buffer callback ──────────────────────────────────────────
    def handle_event(cpu, data, size):
        nonlocal event_count
        ev = ctypes.cast(data, ctypes.POINTER(TlsEvent)).contents

        # Optional name filter
        if args.name and args.name not in ev.comm.decode(errors="replace"):
            return

        event_count += 1

        if not args.quiet:
            print_event(ev, args)

        if outfile:
            outfile.write(json.dumps(event_to_dict(ev)) + "\n")
            outfile.flush()

    bpf["tls_events"].open_perf_buffer(handle_event, page_cnt=256)

    # ── Graceful shutdown ──────────────────────────────────────────────────
    running = True
    def _sigint(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, _sigint)

    start = time.monotonic()
    try:
        while running:
            bpf.perf_buffer_poll(timeout=200)
    finally:
        elapsed = time.monotonic() - start
        if outfile:
            outfile.close()
        print(colour(
            "\n[*] Stopped after {:.1f}s — {:,} events captured.".format(elapsed, event_count),
            YELLOW,
        ))
        if args.output:
            print(colour("    Saved to " + args.output, GREEN))


if __name__ == "__main__":
    main()
