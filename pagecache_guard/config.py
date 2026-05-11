"""Shared constants and libc handle."""

import ctypes
import ctypes.util
import struct

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# fanotify constants
FAN_CLASS_CONTENT    = 0x04
FAN_CLOEXEC          = 0x01
FAN_OPEN_EXEC_PERM   = 0x00040000
FAN_OPEN_PERM        = 0x00010000
FAN_MARK_ADD          = 0x01
FAN_MARK_REMOVE       = 0x02
FAN_MARK_MOUNT        = 0x10
FAN_MARK_IGNORED_MASK = 0x20
AT_FDCWD             = -100
FAN_ALLOW            = 0x01
FAN_DENY             = 0x02

# File I/O
O_RDONLY    = 0
O_LARGEFILE = 0o100000
O_DIRECT    = 0o40000
BLOCK_SIZE  = 4096

# fanotify event struct
EVENT_FMT  = "IbbHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)

# Default watched daemons for process-tree detection
DEFAULT_WATCHED_DAEMONS = {"crond", "anacron", "atd", "systemd"}

# Default process tree walk depth
DEFAULT_PTREE_DEPTH = 3
