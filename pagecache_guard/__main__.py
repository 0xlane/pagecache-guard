"""CLI entry point — ``python3 -m pagecache_guard [options] [paths...]``."""

import os
import sys
import signal
import time
import argparse
import logging
import logging.handlers

from .fanotify_handler import FanotifyHandler, scan_suid_files
from .inode_watcher import setup_inode_marks
from .periodic_scanner import PeriodicScanner
from .config import DEFAULT_PTREE_DEPTH

running = True


def _signal_handler(_signum, _frame):
    global running
    running = False


def main():
    parser = argparse.ArgumentParser(
        description="Page Cache Integrity Guard — "
                    "fanotify + O_DIRECT detection for page cache overwrites")
    parser.add_argument(
        "paths", nargs="*", default=["/usr", "/bin", "/sbin"],
        help="Directories to monitor (default: /usr /bin /sbin)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Log alerts but do not block execution")
    parser.add_argument(
        "--rescan-interval", type=int, default=0, metavar="SEC",
        help="Re-scan for new SUID/SGID files every SEC seconds (0=off)")
    parser.add_argument(
        "--syslog", action="store_true",
        help="Send alerts to syslog")
    parser.add_argument(
        "--log-file", type=str, default=None, metavar="PATH",
        help="Write log to file")
    parser.add_argument(
        "--check-root", action="store_true",
        help="Also check executions by root (default: skip)")

    # Phase 1a — daemon-executed file detection
    parser.add_argument(
        "--watch-daemon", type=str, default=None, metavar="LIST",
        help="Comma-separated daemon names for process-tree detection "
             "(e.g. crond,anacron,atd,systemd)")
    parser.add_argument(
        "--ptree-depth", type=int, default=DEFAULT_PTREE_DEPTH, metavar="N",
        help="Max depth for process-tree walk (default: %d)"
             % DEFAULT_PTREE_DEPTH)

    # Phase 1b — inode-marked critical files
    parser.add_argument(
        "--watch-file", nargs="*", default=[], metavar="PATH",
        help="Non-executable files to monitor via FAN_OPEN_PERM inode marks "
             "(e.g. /etc/passwd /etc/profile /etc/ld.so.preload)")
    parser.add_argument(
        "--watch-pam", type=str, default=None, metavar="DIR",
        help="Auto-discover and watch PAM modules in DIR "
             "(e.g. /lib64/security)")

    # Phase 2 — periodic shared-library scan
    parser.add_argument(
        "--watch-lib", nargs="*", default=[], metavar="PATH",
        help="Shared libraries to periodically scan for tampering")
    parser.add_argument(
        "--scan-interval", type=float, default=5.0, metavar="SEC",
        help="Periodic library scan interval in seconds (default: 5.0)")

    parser.add_argument(
        "--cache-ttl", type=float, default=5.0, metavar="SEC",
        help="Checksum cache TTL for high-frequency files (default: 5.0)")

    args = parser.parse_args()

    # ---- Logging ----
    logger = logging.getLogger("pagecache_guard")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    console_h = logging.StreamHandler(sys.stdout)
    console_h.setFormatter(fmt)
    logger.addHandler(console_h)

    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler(address="/dev/log")
        syslog_h.setFormatter(
            logging.Formatter("pagecache_guard: %(message)s"))
        logger.addHandler(syslog_h)

    if args.log_file:
        file_h = logging.FileHandler(args.log_file)
        file_h.setFormatter(fmt)
        logger.addHandler(file_h)

    # ---- Resolve monitor paths (deduplicate by device) ----
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

    if not monitor_paths:
        logger.error("No valid directories to monitor")
        sys.exit(1)

    # ---- SUID scan ----
    logger.info("Scanning for SUID/SGID files in: %s",
                ", ".join(monitor_paths))
    suid_files = scan_suid_files(monitor_paths)
    logger.info("Found %d SUID/SGID files", len(suid_files))
    for f in sorted(suid_files):
        logger.info("  SUID/SGID: %s", f)

    # ---- Daemon list ----
    watched_daemons = set()
    if args.watch_daemon:
        watched_daemons = {d.strip() for d in args.watch_daemon.split(",")
                          if d.strip()}
        logger.info("Watching daemon parents: %s",
                    ", ".join(sorted(watched_daemons)))

    # ---- Fanotify handler ----
    watched_files_set = set()
    handler = FanotifyHandler(
        monitor_paths=monitor_paths,
        suid_files=suid_files,
        watched_files_set=watched_files_set,
        watched_daemons=watched_daemons,
        ptree_depth=args.ptree_depth,
        cache_ttl=args.cache_ttl,
        dry_run=args.dry_run,
        check_root=args.check_root,
    )

    if not handler.init_fanotify():
        sys.exit(1)

    # ---- Inode marks (Phase 1b) ----
    if args.watch_file or args.watch_pam:
        marked = setup_inode_marks(handler.fan_fd,
                                   args.watch_file, args.watch_pam,
                                   flush_fn=handler.flush_pending)
        watched_files_set.update(marked)
        logger.info("Inode marks set for %d files", len(marked))

    # ---- Periodic scanner (Phase 2) ----
    scanner = PeriodicScanner(
        watch_libs=args.watch_lib,
        interval=args.scan_interval,
        dry_run=args.dry_run,
    )
    scanner.start()

    # ---- Announce ----
    mode_str = "DRY-RUN" if args.dry_run else "ENFORCE"
    features = ["SUID"]
    if watched_daemons:
        features.append("daemon-exec")
    if watched_files_set:
        features.append("inode-watch(%d)" % len(watched_files_set))
    if args.watch_lib:
        features.append("periodic-scan(%d)" % len(args.watch_lib))
    logger.info("Guard active [%s] features=[%s] check_root=%s",
                mode_str, ", ".join(features), args.check_root)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ---- Main loop ----
    last_rescan = time.monotonic()

    def is_running():
        nonlocal last_rescan
        if not running:
            return False
        if args.rescan_interval > 0:
            now = time.monotonic()
            if now - last_rescan >= args.rescan_interval:
                new_set = scan_suid_files(monitor_paths)
                added = new_set - handler.suid_files
                removed = handler.suid_files - new_set
                if added:
                    logger.info("Re-scan: +%d SUID/SGID files", len(added))
                    for f in sorted(added):
                        logger.info("  + %s", f)
                if removed:
                    logger.info("Re-scan: -%d SUID/SGID files", len(removed))
                handler.suid_files = new_set
                last_rescan = now
        return True

    handler.run(is_running)

    # ---- Shutdown ----
    scanner.stop()
    s = handler.stats
    logger.info(
        "Shutting down. Stats: checked=%d blocked=%d "
        "skipped_root=%d skipped_non_target=%d "
        "daemon_checks=%d inode_checks=%d errors=%d",
        s["checked"], s["blocked"], s["skipped_root"],
        s["skipped_non_target"], s["daemon_checks"],
        s["inode_checks"], s["errors"])
    if scanner.watch_libs:
        logger.info("Periodic scanner: scans=%d alerts=%d",
                     scanner.stats["scans"], scanner.stats["alerts"])
    handler.close()


if __name__ == "__main__":
    main()
