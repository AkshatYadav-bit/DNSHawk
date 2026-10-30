#!/usr/bin/env python3
"""
DNSHawk live-demo: benign DNS traffic.
Sends rapid, repeated queries for records configured in the local Technitium zones.
Resolver: 192.168.111.1 (VMware VMnet8). Does not change Kali's system DNS.
Requires: dig (dnsutils).
"""
import random
import shutil
import subprocess
import sys
import time

RESOLVER = "192.168.111.1"
ROUNDS = 5
DELAY_SECONDS = 0.03

HOSTS = [
    "web.lab.test", "mail.lab.test", "api.lab.test", "db.lab.test",
    "files.lab.test", "portal.corp.test", "intranet.corp.test",
    "wiki.corp.test", "git.corp.test", "monitor.corp.test",
    "frontend.dev.test", "backend.dev.test", "registry.dev.test",
    "metrics.dev.test", "staging.dev.test", "printer.office.test",
    "meeting.office.test", "storage.office.test", "backup.office.test",
    "voip.office.test",
]

def main():
    if not shutil.which("dig"):
        print("ERROR: 'dig' was not found. Install it with: sudo apt install dnsutils")
        sys.exit(1)

    queries = HOSTS * ROUNDS
    random.shuffle(queries)
    print(f"DNSHawk BENIGN DEMO | resolver={RESOLVER}")
    print(f"Sending {len(queries)} queries to configured local-zone records.")
    print("Start DNSHawk live capture on Windows VMnet8 before continuing.")
    input("Press Enter to start...")
    start = time.time()
    ok = 0

    for i, hostname in enumerate(queries, 1):
        try:
            result = subprocess.run(
                ["dig", f"@{RESOLVER}", hostname, "A", "+time=1", "+tries=1",
                 "+noall", "+comments", "+answer"],
                capture_output=True, text=True, timeout=2
            )
            answer = next(
                (line.split()[-1] for line in result.stdout.splitlines()
                 if "\tA\t" in line or " A " in line), "NO ANSWER"
            )
            if "status: NOERROR" in result.stdout and answer != "NO ANSWER":
                ok += 1
            print(f"[{i:03}/{len(queries)}] {hostname:<25} {answer}")
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"[{i:03}/{len(queries)}] {hostname:<25} ERROR: {exc}")
        time.sleep(DELAY_SECONDS)

    elapsed = time.time() - start
    print(f"\nFinished: {ok}/{len(queries)} returned A answers in {elapsed:.1f}s.")
    print("Expected profile: repeated known names; this is a controlled benign baseline.")

if __name__ == "__main__":
    main()
