"""Background thread for periodic O_DIRECT scan of already-mapped shared libs.

Shared libraries that are already mmap'd by running processes cannot be
intercepted by fanotify — they need polling-based detection (alert only).
"""

import os
import threading
import logging

from .core import check_integrity_standalone

logger = logging.getLogger("pagecache_guard")


class PeriodicScanner:
    """Periodically compares page cache vs disk for watched shared libraries."""

    def __init__(self, watch_libs, interval=5.0, dry_run=False):
        self.watch_libs = list(watch_libs)
        self.interval = interval
        self.dry_run = dry_run
        self._stop = threading.Event()
        self._thread = None
        self.stats = {"scans": 0, "alerts": 0}

    def start(self):
        if not self.watch_libs:
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="periodic-scanner")
        self._thread.start()
        logger.info("Periodic scanner started: %d libs, interval=%ds",
                     len(self.watch_libs), self.interval)
        for lib in self.watch_libs:
            logger.info("  Watching lib: %s", lib)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 1)

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            self.stats["scans"] += 1
            for lib in self.watch_libs:
                if not os.path.exists(lib):
                    continue
                intact, diff_off = check_integrity_standalone(lib, logger)
                if not intact:
                    self.stats["alerts"] += 1
                    logger.warning(
                        "[ALERT] DETECTED (periodic scan) %s "
                        "(page cache tampered at offset %s) — "
                        "cannot block (already mapped)",
                        lib, diff_off)
