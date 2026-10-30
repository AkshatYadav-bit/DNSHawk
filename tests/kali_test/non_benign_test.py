#!/usr/bin/env python3
"""
DNSHawk live-demo: synthetic tunneling-like DNS traffic.
Sends rapid queries with long, high-entropy, unique labels to local zones.
This simulates suspicious-looking DNS patterns; it is NOT a real DNS tunnel
and does not transmit files or exfiltrate data.
Resolver: 192.168.111.1 (VMware VMnet8). Does not change Kali's system DNS.
Requires: dig (dnsutils).
"""
import random
import string
import shutil
import subprocess
import sys
import time

RESOLVER = "192.168.111.1"
QUERY_COUNT = 100
LABEL_LENGTH = 45
DELAY_SECONDS = 0.03
ZONES = ["lab.test", "corp.test", "dev.test", "office.test"]
ALPHABET = string.ascii_lowercase + "234567"

def make_label(length=LABEL_LENGTH):
    # Random lowercase/base32-like label: long, unique, and high entropy.
    return "".join(random.SystemRandom().choice(ALPHABET) for _ in range(length))

def main():
    if not shutil.which("dig"):
        print("ERROR: 'dig' was not found. Install it with: sudo apt install dnsutils")
        sys.exit(1)

    queries = [f"{make_label()}.{random.choice(ZONES)}" for _ in range(QUERY_COUNT)]
    print(f"DNSHawk NON-BENIGN DEMO | resolver={RESOLVER}")
    print(f"Sending {len(queries)} unique, long-label queries rapidly.")
    print("These are synthetic tunneling-like labels, not an actual tunnel.")
    print("Start DNSHawk live capture on Windows VMnet8 before continuing.")
    input("Press Enter to start...")
    start = time.time()
    responses = {}

    for i, hostname in enumerate(queries, 1):
        try:
            result = subprocess.run(
                ["dig", f"@{RESOLVER}", hostname, "A", "+time=1", "+tries=1",
                 "+noall", "+comments"],
                capture_output=True, text=True, timeout=2
            )
            status = "UNKNOWN"
            for line in result.stdout.splitlines():
                if "status:" in line:
                    status = line.split("status:", 1)[1].split(",", 1)[0].strip()
                    break
            responses[status] = responses.get(status, 0) + 1
            print(f"[{i:03}/{QUERY_COUNT}] {hostname} -> {status}")
        except (subprocess.TimeoutExpired, OSError) as exc:
            responses["ERROR"] = responses.get("ERROR", 0) + 1
            print(f"[{i:03}/{QUERY_COUNT}] {hostname} -> ERROR: {exc}")
        time.sleep(DELAY_SECONDS)

    elapsed = time.time() - start
    print(f"\nFinished in {elapsed:.1f}s. Response summary: {responses}")
    print("Expected profile: unique long labels, often NXDOMAIN; detection depends on your model/rules.")

if __name__ == "__main__":
    main()
