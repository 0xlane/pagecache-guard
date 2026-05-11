"""fanotify setup, mount marks, and the enhanced event loop.

Decision logic per event:
  1. SUID/SGID binary → O_DIRECT check (existing)
  2. Non-SUID but parent is a watched daemon → O_DIRECT check (Phase 1a)
  3. Inode-marked critical file opened → O_DIRECT check (Phase 1b)
  4. None of the above → FAN_ALLOW immediately
"""

import os
import stat
import struct
import ctypes
import time
import logging

from .config import (
    libc, FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_OPEN_EXEC_PERM,
    FAN_OPEN_PERM, FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_MOUNT,
    FAN_MARK_IGNORED_MASK, FAN_MARK_FILESYSTEM, AT_FDCWD,
    FAN_ALLOW, FAN_DENY, O_RDONLY, O_LARGEFILE,
    EVENT_FMT, EVENT_SIZE,
)
from .core import check_integrity
from .process_tree import get_exec_uid, find_watched_ancestor

logger = logging.getLogger("pagecache_guard")


def scan_suid_files(paths):
    """Walk *paths* and collect all SUID/SGID regular files."""
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


class FanotifyHandler:
    """Owns the fanotify fd, mount marks, and the blocking event loop."""

    def __init__(self, monitor_paths, suid_files, watched_files_set,
                 watched_daemons, ptree_depth, cache_ttl,
                 dry_run=False, check_root=False):
        self.monitor_paths = monitor_paths
        self.suid_files = suid_files
        self.watched_files_set = watched_files_set
        self.watched_daemons = watched_daemons
        self.ptree_depth = ptree_depth
        self.dry_run = dry_run
        self.check_root = check_root
        self.use_exec_perm = True
        self.fan_fd = -1
        self._guard_pid = os.getpid()
        self._inode_check_cache = {}
        self._inode_cache_ttl = max(cache_ttl, 2.0)
        self.stats = {
            "checked": 0, "blocked": 0, "skipped_root": 0,
            "skipped_non_target": 0, "errors": 0,
            "daemon_checks": 0, "inode_checks": 0,
            "inode_cache_hits": 0,
        }

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def init_fanotify(self):
        """Create the fanotify fd and add filesystem/mount marks.

        Tries FAN_MARK_FILESYSTEM first (works across mount namespaces,
        required when running inside systemd with ProtectHome= etc.).
        Falls back to FAN_MARK_MOUNT if the kernel doesn't support it.
        """
        self.fan_fd = libc.fanotify_init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE)
        if self.fan_fd < 0:
            logger.error("fanotify_init failed (errno=%d). "
                         "Need root and kernel >= 2.6.37.",
                         ctypes.get_errno())
            return False

        marked_devs = set()
        for mp in self.monitor_paths:
            try:
                dev = os.stat(mp).st_dev
            except OSError:
                continue
            if dev in marked_devs:
                continue

            marked = False
            for mark_flag, mark_label in [
                (FAN_MARK_FILESYSTEM, "filesystem"),
                (FAN_MARK_MOUNT, "mount"),
            ]:
                ret = libc.fanotify_mark(
                    self.fan_fd, FAN_MARK_ADD | mark_flag,
                    FAN_OPEN_EXEC_PERM, AT_FDCWD, mp.encode())
                if ret == 0:
                    marked_devs.add(dev)
                    logger.info("Monitoring %s (FAN_OPEN_EXEC_PERM): %s",
                                mark_label, mp)
                    marked = True
                    break

            if marked:
                continue

            self.use_exec_perm = False
            for mark_flag, mark_label in [
                (FAN_MARK_FILESYSTEM, "filesystem"),
                (FAN_MARK_MOUNT, "mount"),
            ]:
                ret = libc.fanotify_mark(
                    self.fan_fd, FAN_MARK_ADD | mark_flag,
                    FAN_OPEN_PERM, AT_FDCWD, mp.encode())
                if ret == 0:
                    marked_devs.add(dev)
                    logger.info("Monitoring %s (FAN_OPEN_PERM fallback): %s",
                                mark_label, mp)
                    marked = True
                    break

            if not marked:
                logger.error("fanotify_mark failed for %s (errno=%d)",
                             mp, ctypes.get_errno())

        if not marked_devs:
            logger.error("Failed to mark any mount point")
            return False

        if not self.use_exec_perm:
            logger.warning("FAN_OPEN_EXEC_PERM not available, "
                           "using FAN_OPEN_PERM fallback (higher overhead)")
        return True

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------

    def run(self, running_flag):
        """Block and process fanotify events until *running_flag()* is False."""
        try:
            while running_flag():
                try:
                    buf = os.read(self.fan_fd, EVENT_SIZE * 32)
                except OSError:
                    if not running_flag():
                        break
                    continue

                off = 0
                while off + EVENT_SIZE <= len(buf):
                    evlen, _ver, _rsvd, _mlen, mask, efd, pid = \
                        struct.unpack_from(EVENT_FMT, buf, off)
                    off += evlen
                    if efd < 0:
                        continue

                    response = FAN_ALLOW
                    try:
                        response = self._handle_event(mask, efd, pid)
                    except Exception as exc:
                        logger.warning("Event handler error pid=%d: %s",
                                       pid, exc)
                        self.stats["errors"] += 1
                    finally:
                        resp = struct.pack("iI", efd, response)
                        try:
                            os.write(self.fan_fd, resp)
                        except OSError:
                            pass
                        try:
                            os.close(efd)
                        except OSError:
                            pass
        except Exception as exc:
            logger.error("Fatal error in event loop: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Per-event decision
    # ------------------------------------------------------------------

    def _handle_event(self, mask, efd, pid):
        # Kernel 4.18 (RHEL 8) does not exempt the fanotify reader thread
        # from FAN_OPEN_PERM events on inode marks.  When check_integrity()
        # opens an inode-marked file via O_DIRECT, it would trigger a self-
        # event and deadlock.  Skip events from our own process.
        if pid == self._guard_pid:
            return FAN_ALLOW

        is_exec = (bool(mask & FAN_OPEN_EXEC_PERM) if self.use_exec_perm
                   else bool(mask & FAN_OPEN_PERM))

        path = None
        try:
            path = os.readlink(f"/proc/self/fd/{efd}")
        except OSError:
            return FAN_ALLOW
        if not path:
            return FAN_ALLOW

        is_suid = path in self.suid_files
        is_watched = path in self.watched_files_set
        check_reason = None

        # Rule 1: SUID/SGID binary at exec time
        if is_suid and is_exec:
            check_reason = "suid"

        # Rule 2: daemon-spawned executable (cron / systemd / atd)
        if check_reason is None and is_exec and self.watched_daemons:
            ancestor = find_watched_ancestor(
                pid, self.watched_daemons, self.ptree_depth)
            if ancestor:
                check_reason = f"daemon:{ancestor}"
                self.stats["daemon_checks"] += 1

        # Rule 3: inode-marked critical file opened
        if check_reason is None and is_watched:
            now = time.monotonic()
            last = self._inode_check_cache.get(path)
            if last is not None and (now - last) < self._inode_cache_ttl:
                self.stats["inode_cache_hits"] += 1
                return FAN_ALLOW
            check_reason = "inode_watch"
            self.stats["inode_checks"] += 1

        if check_reason is None:
            self.stats["skipped_non_target"] += 1
            return FAN_ALLOW

        # UID filter — skip root for SUID checks unless --check-root
        if check_reason == "suid" and not self.check_root:
            uid = get_exec_uid(pid)
            if uid == 0:
                self.stats["skipped_root"] += 1
                return FAN_ALLOW

        # Integrity comparison
        #
        # For inode-marked files, O_DIRECT read would re-open the file and
        # trigger another FAN_OPEN_PERM that we can't respond to (single-
        # threaded event loop), causing a deadlock that blocks ALL file
        # opens on the mount.  Temporarily suppress events on this inode
        # via FAN_MARK_IGNORED_MASK before opening with O_DIRECT.
        suppress_inode = (check_reason == "inode_watch")
        if suppress_inode:
            libc.fanotify_mark(self.fan_fd,
                               FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                               FAN_OPEN_PERM, efd, None)

        self.stats["checked"] += 1
        try:
            intact, diff_off = check_integrity(path, efd, logger)
        except Exception as exc:
            logger.warning("Check error pid=%d %s: %s", pid, path, exc)
            self.stats["errors"] += 1
            return FAN_ALLOW
        finally:
            if suppress_inode:
                libc.fanotify_mark(self.fan_fd,
                                   FAN_MARK_REMOVE | FAN_MARK_IGNORED_MASK,
                                   FAN_OPEN_PERM, efd, None)

        if not intact:
            self.stats["blocked"] += 1
            self._inode_check_cache.pop(path, None)
            uid = get_exec_uid(pid)
            action = "BLOCKED" if not self.dry_run else "DETECTED"
            logger.warning(
                "[ALERT] %s pid=%d uid=%d %s reason=%s "
                "(page cache tampered at offset %s)",
                action, pid, uid, path, check_reason, diff_off)
            if not self.dry_run:
                return FAN_DENY
        elif check_reason == "inode_watch":
            self._inode_check_cache[path] = time.monotonic()
        return FAN_ALLOW

    # ------------------------------------------------------------------
    # Drain pending events (used during setup phase)
    # ------------------------------------------------------------------

    def flush_pending(self):
        """Read and auto-allow all pending permission events.

        Must be called periodically during inode-mark setup to prevent
        other processes from blocking on FAN_OPEN_PERM events while the
        event loop is not yet running.
        """
        import select
        while True:
            ready, _, _ = select.select([self.fan_fd], [], [], 0)
            if not ready:
                break
            try:
                buf = os.read(self.fan_fd, EVENT_SIZE * 32)
            except OSError:
                break
            off = 0
            while off + EVENT_SIZE <= len(buf):
                evlen, _v, _r, _m, _mask, efd, _pid = \
                    struct.unpack_from(EVENT_FMT, buf, off)
                off += evlen
                if efd >= 0:
                    resp = struct.pack("iI", efd, FAN_ALLOW)
                    try:
                        os.write(self.fan_fd, resp)
                    except OSError:
                        pass
                    try:
                        os.close(efd)
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        if self.fan_fd >= 0:
            os.close(self.fan_fd)
            self.fan_fd = -1
