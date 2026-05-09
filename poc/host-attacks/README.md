# Copy Fail — Host-side Attack Path PoCs

Proof-of-concept scripts demonstrating various host-side exploitation paths using the CVE-2026-31431 (Copy Fail) page cache write primitive.

All scripts require a vulnerable Linux kernel (unpatched AF_ALG authencesn, 2017–2026) and are for **authorized security research only**.

## Files

| Script | Attack Path | Description |
|--------|-------------|-------------|
| `copyfail_core.py` | — | Shared module: `page_cache_write_4bytes()` and `page_cache_write()` |
| `exp_suid_elf.py` | SUID ELF overwrite | Replace SUID binary header with shellcode → root shell |
| `exp_passwd_uid.py` | `/etc/passwd` UID | Change user UID to 0 in page cache → instant root |
| `exp_pam_bypass.py` | PAM bypass | Patch `pam_unix.so` → any password accepted for `su root` |
| `exp_shared_lib.py` | Shared library | Live-patch `.so` in page cache → affects running processes |
| `exp_shared_lib_monitor.c` | (helper) | Monitor program to observe live-patching without restart |
| `exp_profile_inject.py` | `/etc/profile` | Inject command into login profile → runs on next SSH login |
| `exp_cron_script.py` | Cron script | Tamper cron-executed script → runs on next schedule trigger |
| `exp_preload_hijack.py` | `ld.so.preload` | Redirect preload path → evil library loaded by all processes |

## Usage

Place all files in the same directory on the target system, then:

```bash
# Example: /etc/passwd UID tampering
python3 exp_passwd_uid.py testuser123

# Example: /etc/profile command injection
python3 exp_profile_inject.py "id>>/tmp/pwned  #"

# Restore (for non-persistent modifications)
echo 3 > /proc/sys/vm/drop_caches
```

## Verified Attack Paths (7 feasible)

| # | Path | Trigger | Persistence | Universality |
|---|------|---------|-------------|--------------|
| 1 | `/etc/passwd` UID | `su - <user>` | Temporary (drop_caches clears) | All distros (0644) |
| 2 | PAM bypass | `su root` + any password | Semi-permanent (mmap refs) | Needs .so version match |
| 3 | Shared library patch | Immediate (running procs) | Semi-permanent (mmap refs) | Needs .so version match |
| 4 | `/etc/profile` inject | Next login shell | Temporary | All distros (0644) |
| 5 | Cron script tamper | Next cron trigger | Temporary | Needs readable cron script |
| 6 | `ld.so.preload` hijack | Any new process | Temporary | Needs file to pre-exist |
| 7 | SUID ELF overwrite | Execute SUID binary | Temporary | Needs ELF version match |

## Infeasible Paths

| Path | Reason |
|------|--------|
| SSH `authorized_keys` | Default 0600 — not readable by unprivileged users |
| `/etc/sudoers` | Default 0440 — not readable |
| `/etc/ssh/sshd_config` | Default 0600 — not readable |
| Kernel modules (.ko) | Compressed with .xz — modprobe decompresses before loading |
| Cron config files (/etc/cron.d/) | cronie uses inotify; page cache changes don't trigger re-read |
| systemd unit files | Unprivileged users cannot trigger `systemctl restart` |
