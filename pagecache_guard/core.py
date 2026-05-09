"""O_DIRECT integrity check and checksum cache."""

import os
import ctypes
import hashlib
import time
import threading

from .config import libc, O_RDONLY, O_DIRECT, BLOCK_SIZE


class ChecksumCache:
    """TTL-based cache to skip repeated O_DIRECT reads for high-frequency files."""

    def __init__(self, ttl=5.0):
        self.ttl = ttl
        self._store = {}  # path → (sha256_hex, monotonic_ts)
        self._lock = threading.Lock()

    def get(self, path):
        """Return cached digest if still valid, else None."""
        with self._lock:
            entry = self._store.get(path)
            if entry and (time.monotonic() - entry[1]) < self.ttl:
                return entry[0]
            return None

    def put(self, path, digest):
        with self._lock:
            self._store[path] = (digest, time.monotonic())

    def invalidate(self, path):
        with self._lock:
            self._store.pop(path, None)


def odirect_read(filepath, size):
    """Read *size* bytes from *filepath* via O_DIRECT (bypasses page cache).

    Returns bytes or None on failure.
    """
    aligned = ((size + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
    ptr = ctypes.c_void_p()
    if libc.posix_memalign(ctypes.byref(ptr), BLOCK_SIZE, aligned) != 0:
        return None

    try:
        dfd = os.open(filepath, O_RDONLY | O_DIRECT)
    except OSError:
        libc.free(ptr)
        return None

    total = 0
    while total < aligned:
        chunk = min(BLOCK_SIZE * 64, aligned - total)
        dst = ctypes.c_void_p(ptr.value + total)
        n = libc.pread(dfd, dst, chunk, total)
        if n <= 0:
            break
        total += n

    os.close(dfd)
    data = ctypes.string_at(ptr, total)
    libc.free(ptr)
    return data


def _find_first_diff(cache_data, disk_data, fsize):
    """Return offset of first differing byte, or None if identical."""
    cmp_len = min(len(cache_data), len(disk_data), fsize)
    for off in range(0, cmp_len, BLOCK_SIZE):
        end = min(off + BLOCK_SIZE, cmp_len)
        if cache_data[off:end] != disk_data[off:end]:
            for i in range(off, end):
                if cache_data[i] != disk_data[i]:
                    return i
    return None


def check_integrity(filepath, event_fd, logger):
    """Compare page cache (via event fd) vs disk (O_DIRECT).

    Returns (intact: bool, diff_offset: int | None).
    """
    try:
        fsize = os.fstat(event_fd).st_size
    except OSError:
        return True, None
    if fsize == 0:
        return True, None

    aligned = ((fsize + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE

    os.lseek(event_fd, 0, os.SEEK_SET)
    try:
        cache_data = os.read(event_fd, aligned)
    except OSError as exc:
        logger.warning("Cache read failed for %s: %s", filepath, exc)
        return True, None

    disk_data = odirect_read(filepath, fsize)
    if disk_data is None:
        logger.warning("O_DIRECT read failed for %s", filepath)
        return True, None

    diff = _find_first_diff(cache_data, disk_data, fsize)
    if diff is not None:
        return False, diff
    return True, None


def check_integrity_standalone(filepath, logger):
    """Compare normal read (page cache) vs O_DIRECT — no event fd needed.

    Used by the periodic scanner and inode watcher.
    """
    try:
        fsize = os.stat(filepath).st_size
    except OSError:
        return True, None
    if fsize == 0:
        return True, None

    try:
        with open(filepath, "rb") as f:
            cache_data = f.read(fsize)
    except OSError as exc:
        logger.warning("Normal read failed for %s: %s", filepath, exc)
        return True, None

    disk_data = odirect_read(filepath, fsize)
    if disk_data is None:
        logger.warning("O_DIRECT read failed for %s", filepath)
        return True, None

    diff = _find_first_diff(cache_data, disk_data, fsize)
    if diff is not None:
        return False, diff
    return True, None


def compute_disk_checksum(filepath):
    """SHA-256 of file content read via O_DIRECT (disk truth)."""
    try:
        fsize = os.stat(filepath).st_size
    except OSError:
        return None
    data = odirect_read(filepath, fsize)
    if data is None:
        return None
    return hashlib.sha256(data[:fsize]).hexdigest()
