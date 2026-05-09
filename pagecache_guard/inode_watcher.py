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


def setup_inode_marks(fan_fd, watch_files, watch_pam_dir=None):
    """Set up FAN_OPEN_PERM inode marks on critical files.

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

    for path in targets:
        if not os.path.exists(path):
            logger.warning("Watch file does not exist, skipping: %s", path)
            continue

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
            logger.info("  Inode mark (FAN_OPEN_PERM): %s", path)
        else:
            logger.warning("fanotify_mark inode failed for %s", path)

    return marked
