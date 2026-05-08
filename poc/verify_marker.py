#!/usr/bin/env python3
# Author: reinject
"""
Verify if a page cache marker is visible in the current context.

Used to confirm cross-container page cache sharing: run poc_marker.py in
one container, then run this script in another container sharing the same
base image layer to verify the marker propagated.
"""
import os
import sys
import stat

target = sys.argv[1] if len(sys.argv) > 1 else '/etc/os-release'
marker = b'\xDE\xAD\xBE\xEF'

fd = os.open(target, os.O_RDONLY)
s = os.fstat(fd)
data = os.pread(fd, 16, 0)

print(f'File:   {target}')
print(f'Inode:  {s.st_ino}')
print(f'Device: {s.st_dev}')
print(f'First 16 bytes: {data.hex()}')
print(f'As text: {data}')

if data[:4] == marker:
    print('[+] MARKER FOUND: page cache is SHARED with attacker container!')
else:
    print('[-] Marker not found: page cache NOT shared')

os.close(fd)
