#!/usr/bin/env python3
# Author: reinject
"""
Page Cache Integrity Guard — backward-compatible entry point.

Delegates to the pagecache_guard package.  All new features (daemon-exec
detection, inode-watched files, periodic library scanning) are available
via the same CLI flags.

Usage:
  sudo python3 pagecache_guard.py [options] [paths...]
  sudo python3 -m pagecache_guard [options] [paths...]
"""

from pagecache_guard.__main__ import main

if __name__ == "__main__":
    main()
