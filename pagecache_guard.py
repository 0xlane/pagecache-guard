#!/usr/bin/env python3
# Author: reinject
"""
Page Cache Integrity Guard — fanotify + O_DIRECT Detection for Copy Fail

Monitors SUID/SGID binary execution and blocks tampered binaries by
comparing page cache content against disk content via O_DIRECT.

This tool detects page cache corruption caused by CVE-2026-31431 (Copy Fail)
and similar vulnerabilities (Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195)
at execution time, preventing privilege escalation via tampered SUID binaries.

Kernel Compatibility:
  - Linux >= 5.0: FAN_OPEN_EXEC_PERM (recommended, precise execution interception)
  - RHEL/CentOS 8 (4.18.0): FAN_OPEN_EXEC_PERM via RHEL backport (verified)
  - Linux >= 2.6.37: Automatic fallback to FAN_OPEN_PERM (intercepts all opens,
    filters SUID files in userspace — higher overhead but functionally equivalent)

Other Requirements:
  - Root privileges (CAP_SYS_ADMIN for fanotify permission events)
  - Filesystem supporting O_DIRECT (ext4, XFS, Btrfs)

Usage:
  sudo python3 pagecache_guard.py [options] [paths...]

Examples:
  sudo python3 pagecache_guard.py /usr /bin /sbin
  sudo python3 pagecache_guard.py --dry-run /usr
  sudo python3 pagecache_guard.py --rescan-interval 300 /usr /bin

Detection Scope:
  This tool protects against SUID/SGID privilege escalation only. It does NOT
  cover container escape scenarios (e.g., tampering cron scripts or shell configs).
  For broader coverage, combine with periodic O_DIRECT full-scan of critical files.
"""
import os
import sys
import stat
import struct
import ctypes
import ctypes.util
import argparse
import signal
import time
import logging
import logging.handlers

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

FAN_CLASS_CONTENT    = 0x04
FAN_CLOEXEC          = 0x01
FAN_OPEN_EXEC_PERM   = 0x00040000
FAN_OPEN_PERM        = 0x00010000
FAN_MARK_ADD         = 0x01
FAN_MARK_MOUNT       = 0x10
AT_FDCWD             = -100
FAN_ALLOW            = 0x01
FAN_DENY             = 0x02
O_RDONLY             = 0
O_LARGEFILE          = 0o100000
O_DIRECT             = 0o40000
BLOCK_SIZE           = 4096

EVENT_FMT  = "IbbHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)

running = True
use_exec_perm = True


def signal_handler(signum, frame):
    global running
    running = False


# ---------------------------------------------------------------------------
# SUID/SGID Scanner
# ---------------------------------------------------------------------------
def scan_suid_files(paths, logger):
    """Walk directories and collect all SUID/SGID regular files."""
    suid_set = set()
    for base in paths:
        if not os.path.exists(base):
            logger.warning("Path does not exist: %s", base)
            continue
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.lstat(fpath)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    suid_set.add(fpath)
    return suid_set


# ---------------------------------------------------------------------------
# UID lookup
# ---------------------------------------------------------------------------
def get_exec_uid(pid):
    """Read the real UID of a process from /proc/<pid>/status."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return -1


# ---------------------------------------------------------------------------
# O_DIRECT integrity check
# ---------------------------------------------------------------------------
def check_integrity(filepath, event_fd, logger):
    """Compare full file content: page cache (via event fd) vs disk (O_DIRECT).

    Returns (intact: bool, diff_offset: int or None).
    """
    try:
        fsize = os.fstat(event_fd).st_size
    except OSError:
        return True, None
    if fsize == 0:
        return True, None

    aligned_size = ((fsize + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE

    os.lseek(event_fd, 0, os.SEEK_SET)
    try:
        cache_data = os.read(event_fd, aligned_size)
    except OSError as exc:
        logger.warning("Cache read failed for %s: %s", filepath, exc)
        return True, None

    ptr = ctypes.c_void_p()
    if libc.posix_memalign(ctypes.byref(ptr), BLOCK_SIZE, aligned_size) != 0:
        logger.warning("posix_memalign failed for %s", filepath)
        return True, None

    try:
        dfd = os.open(filepath, O_RDONLY | O_DIRECT)
    except OSError as exc:
        libc.free(ptr)
        logger.warning("O_DIRECT open failed for %s: %s", filepath, exc)
        return True, None

    total_read = 0
    while total_read < aligned_size:
        chunk = min(BLOCK_SIZE * 64, aligned_size - total_read)
        dst = ctypes.c_void_p(ptr.value + total_read)
        n = libc.pread(dfd, dst, chunk, total_read)
        if n <= 0:
            break
        total_read += n

    os.close(dfd)
    disk_data = ctypes.string_at(ptr, total_read)
    libc.free(ptr)

    cmp_len = min(len(cache_data), len(disk_data), fsize)
    for off in range(0, cmp_len, BLOCK_SIZE):
        end = min(off + BLOCK_SIZE, cmp_len)
        if cache_data[off:end] != disk_data[off:end]:
            for i in range(off, end):
                if cache_data[i] != disk_data[i]:
                    return False, i
    return True, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Page Cache Integrity Guard for SUID/SGID binaries"
    )
    parser.add_argument(
        "paths", nargs="*", default=["/usr", "/bin", "/sbin"],
        help="Directories to monitor (default: /usr /bin /sbin)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Log alerts but do not block execution"
    )
    parser.add_argument(
        "--rescan-interval", type=int, default=0, metavar="SECONDS",
        help="Periodically re-scan for new SUID/SGID files (0=disabled)"
    )
    parser.add_argument(
        "--syslog", action="store_true",
        help="Send alerts to syslog"
    )
    parser.add_argument(
        "--log-file", type=str, default=None, metavar="PATH",
        help="Write log to file"
    )
    parser.add_argument(
        "--check-root", action="store_true",
        help="Also check executions by root (default: skip root)"
    )
    args = parser.parse_args()

    logger = logging.getLogger("pagecache_guard")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    console_h = logging.StreamHandler(sys.stdout)
    console_h.setFormatter(fmt)
    logger.addHandler(console_h)

    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler(address="/dev/log")
        syslog_h.setFormatter(logging.Formatter("pagecache_guard: %(message)s"))
        logger.addHandler(syslog_h)

    if args.log_file:
        file_h = logging.FileHandler(args.log_file)
        file_h.setFormatter(fmt)
        logger.addHandler(file_h)

    monitor_paths = []
    seen_devs = set()
    for p in args.paths:
        rp = os.path.realpath(p)
        if not os.path.isdir(rp):
            logger.warning("Not a directory, skipping: %s", p)
            continue
        try:
            dev = os.stat(rp).st_dev
        except OSError:
            continue
        if dev not in seen_devs:
            seen_devs.add(dev)
            monitor_paths.append(rp)
        else:
            monitor_paths.append(rp)

    if not monitor_paths:
        logger.error("No valid directories to monitor")
        sys.exit(1)

    logger.info("Scanning for SUID/SGID files in: %s", ", ".join(monitor_paths))
    suid_files = scan_suid_files(monitor_paths, logger)
    logger.info("Found %d SUID/SGID files", len(suid_files))
    for f in sorted(suid_files):
        logger.info("  SUID/SGID: %s", f)

    global use_exec_perm
    fan_fd = libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
                                O_RDONLY | O_LARGEFILE)
    if fan_fd < 0:
        logger.error("fanotify_init failed (errno=%d). Need root privileges "
                      "and kernel >= 2.6.37.", ctypes.get_errno())
        sys.exit(1)

    marked_devs = set()
    for mp in monitor_paths:
        try:
            dev = os.stat(mp).st_dev
        except OSError:
            continue
        if dev in marked_devs:
            continue

        ret = libc.fanotify_mark(
            fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_OPEN_EXEC_PERM, AT_FDCWD, mp.encode()
        )
        if ret == 0:
            marked_devs.add(dev)
            logger.info("Monitoring mount (FAN_OPEN_EXEC_PERM): %s", mp)
            continue

        use_exec_perm = False
        ret = libc.fanotify_mark(
            fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_OPEN_PERM, AT_FDCWD, mp.encode()
        )
        if ret == 0:
            marked_devs.add(dev)
            logger.info("Monitoring mount (FAN_OPEN_PERM fallback): %s", mp)
        else:
            logger.error("fanotify_mark failed for %s (errno=%d)",
                         mp, ctypes.get_errno())

    if not marked_devs:
        logger.error("Failed to mark any mount point")
        os.close(fan_fd)
        sys.exit(1)

    if not use_exec_perm:
        logger.warning("FAN_OPEN_EXEC_PERM not available, using FAN_OPEN_PERM "
                        "fallback (higher overhead)")

    mode_str = "DRY-RUN" if args.dry_run else "ENFORCE"
    logger.info("Guard active [%s] (event_size=%d, check_root=%s)",
                mode_str, EVENT_SIZE, args.check_root)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    stats = {"checked": 0, "blocked": 0, "skipped_root": 0,
             "skipped_non_suid": 0, "errors": 0}
    last_rescan = time.monotonic()

    try:
        while running:
            if args.rescan_interval > 0:
                now = time.monotonic()
                if now - last_rescan >= args.rescan_interval:
                    new_set = scan_suid_files(monitor_paths, logger)
                    added = new_set - suid_files
                    removed = suid_files - new_set
                    if added:
                        logger.info("Re-scan: %d new SUID/SGID files", len(added))
                        for f in sorted(added):
                            logger.info("  + %s", f)
                    if removed:
                        logger.info("Re-scan: %d SUID/SGID files removed",
                                    len(removed))
                    suid_files = new_set
                    last_rescan = now

            try:
                buf = os.read(fan_fd, EVENT_SIZE * 32)
            except OSError:
                if not running:
                    break
                continue

            off = 0
            while off + EVENT_SIZE <= len(buf):
                evlen, ver, _, mlen, mask, efd, pid = struct.unpack_from(
                    EVENT_FMT, buf, off
                )
                off += evlen

                if efd < 0:
                    continue

                response = FAN_ALLOW

                perm_mask = (FAN_OPEN_EXEC_PERM if use_exec_perm
                             else FAN_OPEN_PERM)
                if mask & perm_mask:
                    path = None
                    try:
                        path = os.readlink(f"/proc/self/fd/{efd}")
                    except OSError:
                        pass

                    if path and path in suid_files:
                        exec_uid = get_exec_uid(pid)
                        if exec_uid == 0 and not args.check_root:
                            stats["skipped_root"] += 1
                        else:
                            stats["checked"] += 1
                            try:
                                intact, diff_off = check_integrity(
                                    path, efd, logger)
                            except Exception as exc:
                                logger.warning("Check error pid=%d %s: %s",
                                               pid, path, exc)
                                stats["errors"] += 1
                                intact = True
                                diff_off = None

                            if not intact:
                                stats["blocked"] += 1
                                if not args.dry_run:
                                    response = FAN_DENY
                                logger.warning(
                                    "[ALERT] %s pid=%d uid=%d %s "
                                    "(page cache tampered at offset %s)",
                                    "BLOCKED" if not args.dry_run
                                    else "DETECTED",
                                    pid, exec_uid, path, diff_off
                                )
                            else:
                                logger.debug("OK pid=%d uid=%d %s",
                                             pid, exec_uid, path)
                    else:
                        stats["skipped_non_suid"] += 1

                resp = struct.pack("iI", efd, response)
                try:
                    os.write(fan_fd, resp)
                except OSError:
                    pass
                try:
                    os.close(efd)
                except OSError:
                    pass

    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)

    logger.info("Shutting down. Stats: checked=%d blocked=%d "
                "skipped_root=%d skipped_non_suid=%d errors=%d",
                stats["checked"], stats["blocked"],
                stats["skipped_root"], stats["skipped_non_suid"],
                stats["errors"])
    os.close(fan_fd)


if __name__ == "__main__":
    main()
