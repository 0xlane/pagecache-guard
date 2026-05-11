"""Parent process identification for daemon-executed file detection.

Walks the /proc process tree upward to find a watched daemon ancestor
(e.g. crond, anacron, atd, systemd), enabling integrity checks for
daemon-executed files without parsing crontabs or scanning all execs.
"""

from .config import DEFAULT_WATCHED_DAEMONS, DEFAULT_PTREE_DEPTH


def get_ppid(pid):
    """Read parent PID from /proc/<pid>/status."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def get_comm(pid):
    """Read process command name from /proc/<pid>/comm."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def get_exec_uid(pid):
    """Read the real UID of *pid* from /proc."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return -1


def find_watched_ancestor(pid, watched_daemons=None, max_depth=None):
    """Walk the process tree upward from *pid*.

    Returns the daemon comm name if a watched ancestor is found within
    *max_depth* levels, or empty string otherwise.

    PID 1 (systemd/init) is only matched when it is the *immediate*
    parent of the executing process.  Without this restriction, every
    process on the system would match ``systemd`` as a watched daemon,
    causing a full O_DIRECT check on every single exec event and making
    the system unresponsive.
    """
    if watched_daemons is None:
        watched_daemons = DEFAULT_WATCHED_DAEMONS
    if max_depth is None:
        max_depth = DEFAULT_PTREE_DEPTH

    current = pid
    for _ in range(max_depth):
        ppid = get_ppid(current)
        if ppid <= 0:
            break
        if ppid == 1:
            if current == pid:
                comm = get_comm(ppid)
                if comm in watched_daemons:
                    return comm
            break
        comm = get_comm(ppid)
        if comm in watched_daemons:
            return comm
        current = ppid
    return ""
