#!/usr/bin/env python3
"""
test_cleartext.py — Generate HTTPS traffic and view captured TLS events.

Run in two terminals:

  Terminal 1 (capture):  sudo python3 cleartext.py -o /tmp/cleartext_test.jsonl -q
  Terminal 2 (test):     python3 test_cleartext.py

Or run standalone to just watch /tmp/cleartext_test.jsonl if it already exists.
"""

import json
import os
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.error

# ── config ────────────────────────────────────────────────────────────────
CAPTURE_FILE = "/tmp/cleartext_test.jsonl"
TEST_URLS = [
    "https://httpbin.org/get",
    "https://httpbin.org/headers",
    "https://example.com",
]
REQUEST_INTERVAL = 1.5   # seconds between requests
MAX_DISPLAY_BYTES = 600

# ── colour ────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def c(text, code):
    return code + str(text) + RESET if sys.stdout.isatty() else str(text)

# ── traffic generator (runs in background thread) ─────────────────────────
def generate_traffic(stop_event):
    print(c("\n[traffic] Starting HTTPS requests …", CYAN))
    i = 0
    while not stop_event.is_set():
        url = TEST_URLS[i % len(TEST_URLS)]
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read()
                print(c("[traffic] GET " + url + " → " + str(resp.status) + " (" + str(len(body)) + " bytes)", DIM))
        except Exception as exc:
            print(c("[traffic] " + url + " failed: " + str(exc), YELLOW))
        i += 1
        stop_event.wait(REQUEST_INTERVAL)

# ── event display ─────────────────────────────────────────────────────────
def display_event(ev: dict, index: int):
    direction = ev.get("direction", "?")
    dir_label = "WRITE →" if direction == "write" else "READ  ←"
    dir_col   = GREEN if direction == "write" else CYAN

    ts  = ev.get("timestamp_iso", "?")[11:23]   # HH:MM:SS.mmm
    pid = ev.get("pid", "?")
    comm = ev.get("comm", "?")
    data_len = ev.get("data_len", 0)

    print(c("─" * 70, DIM))
    print(
        c("#" + str(index).ljust(4), DIM),
        c(ts, DIM),
        c(dir_label, dir_col + BOLD),
        c(comm, YELLOW),
        c("pid=" + str(pid), DIM),
        c(str(data_len) + " bytes", BOLD),
    )

    text = ev.get("text")
    hex_data = ev.get("hex", "")

    if text:
        lines = text[:MAX_DISPLAY_BYTES].splitlines()
        for line in lines[:25]:
            print("  " + line)
        if data_len > MAX_DISPLAY_BYTES:
            print(c("  … (" + str(data_len - MAX_DISPLAY_BYTES) + " bytes not shown)", DIM))
    elif hex_data:
        raw = bytes.fromhex(hex_data[:MAX_DISPLAY_BYTES * 2])
        print("  " + raw.hex(" "))
    else:
        print(c("  (no payload)", DIM))

# ── tail the capture file ─────────────────────────────────────────────────
def tail_capture(stop_event):
    # Wait for file to appear
    waited = 0
    while not os.path.exists(CAPTURE_FILE):
        if waited == 0:
            print(c("\n[viewer] Waiting for " + CAPTURE_FILE + " …", YELLOW))
            print(c("         Start cleartext:  sudo python3 cleartext.py -o " + CAPTURE_FILE + " -q", DIM))
        time.sleep(0.5)
        waited += 1
        if waited > 20:
            print(c("[viewer] Timed out waiting for capture file.", RED))
            stop_event.set()
            return

    print(c("[viewer] Tailing " + CAPTURE_FILE, CYAN))
    event_count = 0

    with open(CAPTURE_FILE, "r") as fh:
        # Seek to end so we only see new events
        fh.seek(0, 2)
        while not stop_event.is_set():
            line = fh.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                event_count += 1
                display_event(ev, event_count)
            except json.JSONDecodeError:
                print(c("[viewer] Bad JSON: " + line[:80], RED))

    print(c("\n[viewer] Stopped. Total events seen: " + str(event_count), YELLOW))

# ── stats summary ──────────────────────────────────────────────────────────
def print_stats(capture_file):
    if not os.path.exists(capture_file):
        return
    total = writes = reads = bw = br = 0
    comms = set()
    with open(capture_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                total += 1
                comms.add(ev.get("comm", "?"))
                if ev.get("direction") == "write":
                    writes += 1
                    bw += ev.get("data_len", 0)
                else:
                    reads += 1
                    br += ev.get("data_len", 0)
            except Exception:
                pass
    print(c("\n" + "═" * 70, DIM))
    print(c("CAPTURE SUMMARY", BOLD))
    print("  Events  : " + str(total))
    print("  Writes  : " + str(writes) + "  (" + str(bw) + " bytes)")
    print("  Reads   : " + str(reads) + "  (" + str(br) + " bytes)")
    print("  Procs   : " + ", ".join(sorted(comms)))

# ── main ───────────────────────────────────────────────────────────────────
def main():
    print(c("""
  cleartext — test & viewer
  ─────────────────────────
  Make sure cleartext is already running:
    sudo python3 cleartext.py -o """ + CAPTURE_FILE + """ -q

  Press Ctrl-C to stop.
""", CYAN))

    stop = threading.Event()

    # Start traffic generator in background
    traffic_thread = threading.Thread(target=generate_traffic, args=(stop,), daemon=True)
    traffic_thread.start()

    # Tail the capture file (blocks until Ctrl-C)
    try:
        tail_capture(stop)
    except KeyboardInterrupt:
        print(c("\n[*] Stopping …", YELLOW))
        stop.set()

    traffic_thread.join(timeout=2)
    print_stats(CAPTURE_FILE)

if __name__ == "__main__":
    main()
