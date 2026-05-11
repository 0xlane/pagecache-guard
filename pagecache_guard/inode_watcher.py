"""FAN_OPEN_PERM inode mark management for non-executable critical files.

Marks individual inodes (e.g. /etc/passwd, PAM modules, /etc/ld.so.preload)
so that every open() triggers an integrity check.
"""

import os
import glob
import logging

from .config import libc, FAN_MARK_ADD, FAN_OPEN_PERM

logger = logging.getLogger("pagecache_guard")


def discover_pam_modules(pam_dir):
    """Auto-discover pam_*.so modules in *pam_dir*."""
    modules = set()
    for d in (pam_dir, "/lib/x86_64-linux-gnu/security", "/lib/security"):
        found = glob.glob(os.path.join(d, "pam_*.so"))
        if found:
            modules.update(found)
            if d == pam_dir:
                break
    return sorted(modules)


def setup_inode_marks(fan_fd, watch_files, watch_pam_dir=None,
                      flush_fn=None):
    """Set up FAN_OPEN_PERM inode marks on critical files.

    *flush_fn*, if provided, is called after every batch of marks to
    drain pending permission events.  This prevents other processes
    (sshd, crond, etc.) from blocking on already-marked files while
    the main event loop has not started yet.

    Returns a set of successfully marked paths.
    """
    marked = set()
    targets = list(watch_files or [])

    if watch_pam_dir:
        pam_modules = discover_pam_modules(watch_pam_dir)
        targets.extend(pam_modules)
        if pam_modules:
            logger.info("Auto-discovered %d PAM modules in %s",
                        len(pam_modules), watch_pam_dir)

    batch = 0
    marked_inodes = set()
    for path in targets:
        if not os.path.exists(path):
            logger.warning("Watch file does not exist, skipping: %s", path)
            continue

        try:
            ino = os.stat(path).st_ino
        except OSError as exc:
            logger.warning("Cannot stat for inode mark: %s (%s)", path, exc)
            continue

        if ino in marked_inodes:
            logger.debug("  Skipping hardlink (inode %d already marked): %s",
                         ino, path)
            marked.add(os.path.realpath(path))
            continue

        if flush_fn:
            flush_fn()

        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            logger.warning("Cannot open for inode mark: %s (%s)", path, exc)
            continue

        ret = libc.fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM,
                                 fd, None)
        os.close(fd)

        if ret == 0:
            marked.add(os.path.realpath(path))
            marked_inodes.add(ino)
            logger.info("  Inode mark (FAN_OPEN_PERM): %s", path)
            batch += 1
        else:
            logger.warning("fanotify_mark inode failed for %s", path)

        if flush_fn and batch % 5 == 0:
            flush_fn()

    if flush_fn:
        flush_fn()

    return marked
