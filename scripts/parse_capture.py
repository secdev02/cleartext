#!/usr/bin/env python3
"""
parse_capture.py — Read a JSON-lines capture file produced by tls_intercept.py
and pretty-print a summary with optional filtering.

Usage:
    python3 parse_capture.py capture.jsonl
    python3 parse_capture.py capture.jsonl --grep "Authorization"
    python3 parse_capture.py capture.jsonl --pid 1234 --direction write
"""

import argparse
import json
import sys
from datetime import datetime

RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def colour(text, code):
    return code + text + RESET if sys.stdout.isatty() else text

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part   = " ".join("{:02x}".format(b) for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("  {:04x}  {:<{}}  {}".format(i, hex_part, width * 3, ascii_part))
    return "\n".join(lines)

def parse_args():
    ap = argparse.ArgumentParser(description="Inspect tls_intercept.py captures")
    ap.add_argument("file", help="JSON-lines capture file")
    ap.add_argument("--pid",       type=int, help="Filter by PID")
    ap.add_argument("--comm",      type=str, help="Filter by process name substring")
    ap.add_argument("--direction", choices=["read", "write"], help="Filter direction")
    ap.add_argument("--grep",      type=str, help="Filter events whose text contains GREP")
    ap.add_argument("--hex",       action="store_true", help="Print hex dump")
    ap.add_argument("--stats",     action="store_true", help="Show statistics only")
    ap.add_argument("--max-bytes", type=int, default=512, dest="max_bytes")
    return ap.parse_args()

def main():
    args = parse_args()

    stats = {"total": 0, "write": 0, "read": 0, "bytes_write": 0, "bytes_read": 0,
             "pids": set(), "comms": set()}

    try:
        fh = open(args.file)
    except FileNotFoundError:
        sys.exit("[!] File not found: " + args.file)

    for lineno, raw in enumerate(fh, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(colour("[!] Line {}: bad JSON — {}".format(lineno, exc), RED))
            continue

        # ── Apply filters ─────────────────────────────────────────────────
        if args.pid and ev.get("pid") != args.pid:
            continue
        if args.comm and args.comm not in ev.get("comm", ""):
            continue
        if args.direction and ev.get("direction") != args.direction:
            continue
        if args.grep:
            text = ev.get("text") or ""
            if args.grep not in text:
                continue

        # ── Accumulate stats ──────────────────────────────────────────────
        stats["total"] += 1
        direction = ev.get("direction", "?")
        data_len  = ev.get("data_len", 0)
        if direction == "write":
            stats["write"] += 1
            stats["bytes_write"] += data_len
        else:
            stats["read"] += 1
            stats["bytes_read"] += data_len
        stats["pids"].add(ev.get("pid"))
        stats["comms"].add(ev.get("comm"))

        if args.stats:
            continue

        # ── Pretty-print ──────────────────────────────────────────────────
        dir_col = GREEN if direction == "write" else CYAN
        ts = ev.get("timestamp_iso", "?")
        print(colour("─" * 72, DIM))
        print(
            colour(ts, DIM),
            colour(("WRITE →" if direction == "write" else "READ  ←"), dir_col + BOLD),
            colour(ev.get("comm", "?"), YELLOW),
            colour("pid=" + str(ev.get("pid", "?")), DIM),
            colour(str(data_len) + " bytes", BOLD),
        )

        text = ev.get("text")
        payload_hex = ev.get("hex", "")
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
        display = payload_bytes[: args.max_bytes]

        if text is not None:
            for line in text[: args.max_bytes].splitlines()[:20]:
                print("  " + line)
        else:
            if args.hex:
                print(hexdump(display))
            else:
                print("  " + display.hex(" "))

        if data_len > args.max_bytes:
            print(colour("  … ({} bytes truncated)".format(data_len - args.max_bytes), DIM))

    fh.close()

    # ── Summary stats ─────────────────────────────────────────────────────
    print(colour("\n═" * 72, DIM))
    print(colour("SUMMARY", BOLD))
    print("  Total events : {:,}".format(stats["total"]))
    print("  Writes       : {:,}  ({:,} bytes)".format(stats["write"], stats["bytes_write"]))
    print("  Reads        : {:,}  ({:,} bytes)".format(stats["read"],  stats["bytes_read"]))
    print("  Processes    : " + ", ".join(sorted(stats["comms"])))
    print("  PIDs         : " + ", ".join(str(p) for p in sorted(stats["pids"])))

if __name__ == "__main__":
    main()
