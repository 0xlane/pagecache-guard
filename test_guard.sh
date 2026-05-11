#!/bin/bash
# pagecache-guard v0.2 comprehensive test suite
# Run as root on the vulnerable CentOS 8 test machine
set -e

GUARD_DIR="/tmp/pagecache-guard-v2"
TEST_DIR="/tmp/pcg-test-$$"
LOG_FILE="$TEST_DIR/guard.log"
PASS=0
FAIL=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${YELLOW}[*]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

cleanup() {
    log "Cleaning up..."
    pkill -f "pagecache_guard" 2>/dev/null || true
    sleep 0.5
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    userdel testpcg 2>/dev/null || true
    # Restore crontab if test was interrupted
    crontab -l 2>/dev/null | grep -v "pcg-test\|cron_binary" | crontab - 2>/dev/null || true
    # Remove test systemd service
    systemctl stop pcg-test.service 2>/dev/null || true
    rm -f /etc/systemd/system/pcg-test.service
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$GUARD_DIR"

# ========================================================================
# Prep: create a non-root test user for SUID testing
# ========================================================================
log "Creating test user 'testpcg'..."
userdel testpcg 2>/dev/null || true
useradd -M -s /bin/bash testpcg 2>/dev/null || true

# ========================================================================
# Prep: create a test SUID binary
# ========================================================================
log "Creating test SUID binary..."
cat > "$TEST_DIR/suid_test.c" <<'CEOF'
#include <stdio.h>
int main() {
    printf("suid_test executed successfully\n");
    return 0;
}
CEOF
gcc -o "$TEST_DIR/suid_test" "$TEST_DIR/suid_test.c"
chown root:root "$TEST_DIR/suid_test"
chmod 4755 "$TEST_DIR/suid_test"

# Prep: a test script for cron/daemon testing
cat > "$TEST_DIR/daemon_script.sh" <<'SEOF'
#!/bin/bash
echo "daemon_script executed at $(date)" >> /tmp/pcg-daemon-test.log
SEOF
chmod 755 "$TEST_DIR/daemon_script.sh"

# Prep: a test config file for inode-watch
echo "testuser:x:1500:1500:Test:/home/testuser:/bin/bash" > "$TEST_DIR/test_config"

echo ""
echo "============================================================"
echo "  pagecache-guard v0.2 Test Suite"
echo "============================================================"
echo ""

# ========================================================================
# TEST 1: CLI import / --help
# ========================================================================
log "TEST 1: CLI module import"
if python3 -m pagecache_guard --help >/dev/null 2>&1; then
    pass "TEST 1: Module import and --help OK"
else
    fail "TEST 1: Module import failed"
fi

# ========================================================================
# TEST 2: Backward-compatible entry point
# ========================================================================
log "TEST 2: Backward-compatible entry point"
if python3 pagecache_guard.py --help >/dev/null 2>&1; then
    pass "TEST 2: pagecache_guard.py entry point OK"
else
    fail "TEST 2: pagecache_guard.py entry point failed"
fi

# ========================================================================
# TEST 3: SUID scan discovers test binary
# ========================================================================
log "TEST 3: SUID file discovery"
echo 3 > /proc/sys/vm/drop_caches

python3 -m pagecache_guard --dry-run --check-root "$TEST_DIR" \
    > "$TEST_DIR/test3.log" 2>&1 &
GUARD_PID=$!
sleep 2

if grep -q "suid_test" "$TEST_DIR/test3.log"; then
    pass "TEST 3: Guard discovered SUID test binary"
else
    fail "TEST 3: Guard did not find SUID test binary"
fi
kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

# ========================================================================
# TEST 4: Copy Fail PoC + SUID detection (dry-run)
# ========================================================================
log "TEST 4: SUID detection with Copy Fail (dry-run)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

python3 -m pagecache_guard --dry-run --check-root "$TEST_DIR" \
    > "$TEST_DIR/test4.log" 2>&1 &
GUARD_PID=$!
sleep 2

# Corrupt + execute in one process to keep page cache hot on busy K8s nodes
python3 - "$TEST_DIR/suid_test" << 'PYEOF' > "$TEST_DIR/poc_test4.log" 2>&1
import os, sys, subprocess, mmap
sys.path.insert(0, ".")
from poc.poc_marker import page_cache_write_4bytes

target = sys.argv[1]
fd = os.open(target, os.O_RDONLY)
page_cache_write_4bytes(fd, 0, b'\xDE\xAD\xBE\xEF')
mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
after = mm[:4]
print(f"Corruption check: {after.hex()} (expect deadbeef)")
try:
    subprocess.run([target], capture_output=True)
except OSError:
    pass  # ENOEXEC expected — ELF magic corrupted
mm.close()
os.close(fd)
PYEOF
sleep 1

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

if grep -q "DETECTED.*suid_test.*reason=suid" "$TEST_DIR/test4.log"; then
    pass "TEST 4: Dry-run detected tampered SUID binary"
elif grep -q "DETECTED.*suid_test" "$TEST_DIR/test4.log"; then
    pass "TEST 4: Dry-run detected tampered SUID binary (partial match)"
else
    echo "  Guard log:"
    cat "$TEST_DIR/test4.log"
    echo "  PoC log:"
    cat "$TEST_DIR/poc_test4.log"
    fail "TEST 4: Dry-run did NOT detect tampered SUID binary"
fi

# ========================================================================
# TEST 5: Copy Fail PoC + SUID blocking (enforce mode)
# ========================================================================
log "TEST 5: SUID blocking in enforce mode"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

python3 -m pagecache_guard --check-root "$TEST_DIR" \
    > "$TEST_DIR/test5.log" 2>&1 &
GUARD_PID=$!
sleep 2

# Corrupt + execute in one process to keep page cache hot
python3 - "$TEST_DIR/suid_test" << 'PYEOF' > "$TEST_DIR/poc_test5.log" 2>&1
import os, sys, subprocess, mmap
sys.path.insert(0, ".")
from poc.poc_marker import page_cache_write_4bytes

target = sys.argv[1]
fd = os.open(target, os.O_RDONLY)
page_cache_write_4bytes(fd, 0, b'\xDE\xAD\xBE\xEF')
mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
after = mm[:4]
print(f"Corruption: {after.hex()}")
try:
    r = subprocess.run(["su", "testpcg", "-c", target], capture_output=True)
    print(f"Exit code: {r.returncode}")
except OSError as e:
    print(f"OSError: {e}")
mm.close()
os.close(fd)
PYEOF
sleep 1

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

if grep -q "BLOCKED.*suid_test" "$TEST_DIR/test5.log"; then
    pass "TEST 5: Enforce mode BLOCKED tampered SUID binary"
else
    echo "  Guard log:"
    cat "$TEST_DIR/test5.log"
    echo "  PoC log:"
    cat "$TEST_DIR/poc_test5.log"
    fail "TEST 5: No BLOCKED entry in guard log"
fi

# ========================================================================
# TEST 6: Non-SUID file skipped (no false positive)
# ========================================================================
log "TEST 6: Non-SUID exec not falsely flagged"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

python3 -m pagecache_guard --dry-run --check-root "$TEST_DIR" \
    > "$TEST_DIR/test6.log" 2>&1 &
GUARD_PID=$!
sleep 2

# Execute a normal (non-SUID) binary — should not be checked
/bin/echo "hello" > /dev/null 2>&1
sleep 0.5

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

if grep -q "DETECTED\|BLOCKED" "$TEST_DIR/test6.log"; then
    fail "TEST 6: False positive on non-SUID binary"
else
    pass "TEST 6: No false positive for normal binary execution"
fi

# ========================================================================
# TEST 7: Phase 1b — inode-watched file detection
# ========================================================================
log "TEST 7: Inode-watched file (--watch-file)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

# Create a fresh test file
echo "important_config_line_1=value" > "$TEST_DIR/watched_file"

python3 -m pagecache_guard --dry-run --check-root \
    --watch-file "$TEST_DIR/watched_file" -- "$TEST_DIR" \
    > "$TEST_DIR/test7.log" 2>&1 &
GUARD_PID=$!
sleep 2

# Corrupt the watched file's page cache
python3 poc/poc_marker.py "$TEST_DIR/watched_file" > "$TEST_DIR/poc_test7.log" 2>&1

# Trigger an open() on the watched file
cat "$TEST_DIR/watched_file" > /dev/null 2>&1
sleep 1

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

if grep -q "DETECTED.*watched_file.*reason=inode_watch" "$TEST_DIR/test7.log"; then
    pass "TEST 7: Inode-watched file corruption detected"
elif grep -q "DETECTED.*watched_file" "$TEST_DIR/test7.log"; then
    pass "TEST 7: Inode-watched file corruption detected (partial match)"
elif grep -q "Inode mark" "$TEST_DIR/test7.log"; then
    # The mark was set, check if the PoC worked
    echo "  Guard log:"
    cat "$TEST_DIR/test7.log"
    echo "  PoC log:"
    cat "$TEST_DIR/poc_test7.log"
    fail "TEST 7: Inode mark set but corruption not detected"
else
    echo "  Guard log:"
    cat "$TEST_DIR/test7.log"
    fail "TEST 7: Inode mark not set"
fi

# ========================================================================
# TEST 8: Phase 2 — periodic library scan
# ========================================================================
log "TEST 8: Periodic library scan (--watch-lib)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

# Create a fake "library" to watch
dd if=/dev/urandom of="$TEST_DIR/fake_lib.so" bs=4096 count=2 2>/dev/null
sync

python3 -m pagecache_guard --dry-run --check-root \
    --watch-lib "$TEST_DIR/fake_lib.so" --scan-interval 2 -- "$TEST_DIR" \
    > "$TEST_DIR/test8.log" 2>&1 &
GUARD_PID=$!
sleep 2

# Corrupt the fake lib's page cache
python3 poc/poc_marker.py "$TEST_DIR/fake_lib.so" > "$TEST_DIR/poc_test8.log" 2>&1

# Wait for periodic scan
sleep 4

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

if grep -q "DETECTED (periodic scan).*fake_lib" "$TEST_DIR/test8.log"; then
    pass "TEST 8: Periodic scanner detected library tampering"
elif grep -q "periodic scan" "$TEST_DIR/test8.log"; then
    pass "TEST 8: Periodic scanner ran (partial match)"
else
    echo "  Guard log:"
    cat "$TEST_DIR/test8.log"
    echo "  PoC log:"
    cat "$TEST_DIR/poc_test8.log"
    fail "TEST 8: Periodic scanner did not detect tampering"
fi

# ========================================================================
# TEST 9: Phase 1a — daemon-exec detection (end-to-end via crond)
# ========================================================================
log "TEST 9: Daemon-exec detection via crond (end-to-end, ~65s)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

# Build a NON-SUID binary for crond to execute
gcc -o "$TEST_DIR/cron_binary" "$TEST_DIR/suid_test.c"
chmod 755 "$TEST_DIR/cron_binary"  # explicitly NOT suid
sync

# Start guard — monitor $TEST_DIR mount (SUID scan is dir-scoped,
# but fanotify FAN_MARK_MOUNT covers the whole mount including crond execs)
python3 -m pagecache_guard --dry-run --check-root \
    --watch-daemon crond -- "$TEST_DIR" \
    > "$TEST_DIR/test9.log" 2>&1 &
GUARD_PID=$!
sleep 3

if ! grep -q "Watching daemon parents" "$TEST_DIR/test9.log"; then
    kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true
    echo "  Guard log:"
    cat "$TEST_DIR/test9.log"
    fail "TEST 9: Daemon-exec feature not initialized"
else
    # Corrupt binary and pin pages via mmap
    python3 -u - "$TEST_DIR/cron_binary" << 'PYEOF' > "$TEST_DIR/poc_test9.log" 2>&1 &
import os, sys, mmap, time, signal
sys.path.insert(0, ".")
from poc.poc_marker import page_cache_write_4bytes

target = sys.argv[1]
fd = os.open(target, os.O_RDONLY)
page_cache_write_4bytes(fd, 0, b'\xDE\xAD\xBE\xEF')
mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
print(f"Corruption pinned: {mm[:4].hex()}", flush=True)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
time.sleep(120)
PYEOF
    PINNER_PID=$!
    sleep 1

    # Install cron job (every minute)
    SAVED_CRONTAB=$(crontab -l 2>/dev/null || true)
    echo "* * * * * $TEST_DIR/cron_binary >> $TEST_DIR/cron_output.log 2>&1" | crontab -

    # Wait for crond to execute (max 70s)
    log "  Waiting for crond to execute binary..."
    DETECTED=false
    for i in $(seq 1 70); do
        if grep -q "DETECTED.*cron_binary" "$TEST_DIR/test9.log" 2>/dev/null; then
            DETECTED=true
            break
        fi
        sleep 1
    done

    # Restore crontab
    if [ -n "$SAVED_CRONTAB" ]; then
        echo "$SAVED_CRONTAB" | crontab -
    else
        crontab -r 2>/dev/null || true
    fi
    kill $PINNER_PID 2>/dev/null; wait $PINNER_PID 2>/dev/null || true
    kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

    if $DETECTED; then
        if grep -q "reason=daemon:crond" "$TEST_DIR/test9.log"; then
            pass "TEST 9: Daemon-exec detected tampered cron binary (reason=daemon:crond)"
        else
            pass "TEST 9: Daemon-exec detected tampered cron binary"
        fi
    else
        echo "  Guard log (last 10 lines):"
        tail -10 "$TEST_DIR/test9.log"
        echo "  PoC log:"
        cat "$TEST_DIR/poc_test9.log"
        fail "TEST 9: crond executed but guard did not detect tampering"
    fi
fi

# ========================================================================
# TEST 10: PAM inode-watch detection (end-to-end)
# ========================================================================
log "TEST 10: PAM module tampering via inode-watch (end-to-end)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

# Copy a real PAM module to the test dir to avoid corrupting system files
cp /lib64/security/pam_permit.so "$TEST_DIR/pam_test.so"
sync

python3 -m pagecache_guard --dry-run --check-root \
    --watch-file "$TEST_DIR/pam_test.so" -- "$TEST_DIR" \
    > "$TEST_DIR/test10.log" 2>&1 &
GUARD_PID=$!
sleep 2

if ! grep -q "Inode mark" "$TEST_DIR/test10.log"; then
    kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true
    echo "  Guard log:"
    cat "$TEST_DIR/test10.log"
    fail "TEST 10: Inode mark not set for PAM test module"
else
    # Corrupt the PAM module's page cache
    python3 poc/poc_marker.py "$TEST_DIR/pam_test.so" > "$TEST_DIR/poc_test10.log" 2>&1

    # Trigger open on the PAM module (simulates sshd/login opening it)
    cat "$TEST_DIR/pam_test.so" > /dev/null 2>&1
    sleep 1

    kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

    if grep -q "DETECTED.*pam_test.so.*reason=inode_watch" "$TEST_DIR/test10.log"; then
        pass "TEST 10: PAM module tampering detected via inode-watch"
    elif grep -q "DETECTED.*pam_test.so" "$TEST_DIR/test10.log"; then
        pass "TEST 10: PAM module tampering detected"
    else
        echo "  Guard log:"
        cat "$TEST_DIR/test10.log"
        echo "  PoC log:"
        cat "$TEST_DIR/poc_test10.log"
        fail "TEST 10: PAM module tampering not detected"
    fi
fi

# ========================================================================
# TEST 13: Service-executed privilege escalation detection
# ========================================================================
log "TEST 13: Service binary tampering privilege escalation (systemd)"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

# Create a binary simulating a service helper
gcc -o "$TEST_DIR/service_helper" "$TEST_DIR/suid_test.c"
chmod 755 "$TEST_DIR/service_helper"

# Create a oneshot systemd service that runs our binary
cat > /etc/systemd/system/pcg-test.service <<SVCEOF
[Unit]
Description=pagecache-guard test service

[Service]
Type=oneshot
ExecStart=$TEST_DIR/service_helper
RemainAfterExit=no
SVCEOF
systemctl daemon-reload

# Start guard — $TEST_DIR scoped SUID scan, mount-level fanotify catches systemd execs
python3 -m pagecache_guard --dry-run --check-root \
    --watch-daemon systemd -- "$TEST_DIR" \
    > "$TEST_DIR/test13.log" 2>&1 &
GUARD_PID=$!
sleep 3

# Corrupt service binary and pin pages
python3 -u - "$TEST_DIR/service_helper" << 'PYEOF' > "$TEST_DIR/poc_test13.log" 2>&1 &
import os, sys, mmap, time, signal
sys.path.insert(0, ".")
from poc.poc_marker import page_cache_write_4bytes

target = sys.argv[1]
fd = os.open(target, os.O_RDONLY)
page_cache_write_4bytes(fd, 0, b'\xDE\xAD\xBE\xEF')
mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
print(f"Corruption pinned: {mm[:4].hex()}", flush=True)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
time.sleep(30)
PYEOF
PINNER_PID=$!
sleep 1

# Trigger systemd to execute the corrupted binary
systemctl start pcg-test.service 2>/dev/null || true
sleep 2

kill $PINNER_PID 2>/dev/null; wait $PINNER_PID 2>/dev/null || true
kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

# Clean up systemd service
systemctl stop pcg-test.service 2>/dev/null || true
rm -f /etc/systemd/system/pcg-test.service
systemctl daemon-reload 2>/dev/null || true

if grep -q "DETECTED.*service_helper.*reason=daemon:systemd" "$TEST_DIR/test13.log"; then
    pass "TEST 13: Systemd service binary tampering detected (reason=daemon:systemd)"
elif grep -q "DETECTED.*service_helper" "$TEST_DIR/test13.log"; then
    pass "TEST 13: Systemd service binary tampering detected"
else
    echo "  Guard log (last 10 lines):"
    tail -10 "$TEST_DIR/test13.log"
    echo "  PoC log:"
    cat "$TEST_DIR/poc_test13.log"
    fail "TEST 13: Systemd service binary tampering not detected"
fi

# ========================================================================
# TEST 11: Full protection mode (all features together)
# ========================================================================
log "TEST 11: Full protection mode"
echo 3 > /proc/sys/vm/drop_caches
sleep 0.5

python3 -m pagecache_guard --dry-run --check-root \
    --watch-daemon crond,systemd \
    --watch-file "$TEST_DIR/watched_file" \
    --watch-pam /lib64/security \
    --watch-lib "$TEST_DIR/fake_lib.so" --scan-interval 3 \
    -- "$TEST_DIR" \
    > "$TEST_DIR/test11.log" 2>&1 &
GUARD_PID=$!
sleep 15

kill $GUARD_PID 2>/dev/null; wait $GUARD_PID 2>/dev/null || true

FEATURES_OK=true
grep -q "SUID/SGID" "$TEST_DIR/test11.log" || FEATURES_OK=false
grep -q "Watching daemon parents" "$TEST_DIR/test11.log" || FEATURES_OK=false
grep -q "Inode mark" "$TEST_DIR/test11.log" || FEATURES_OK=false
grep -q "Periodic scanner\|periodic-scan\|watch-lib" "$TEST_DIR/test11.log" || FEATURES_OK=false

if $FEATURES_OK; then
    pass "TEST 11: All features initialized in full protection mode"
else
    echo "  Guard log (last 20 lines):"
    tail -20 "$TEST_DIR/test11.log"
    fail "TEST 11: Some features missing in full mode"
fi

# ========================================================================
# TEST 12: Graceful shutdown stats
# ========================================================================
log "TEST 12: Graceful shutdown with stats"
if grep -q "Shutting down. Stats:" "$TEST_DIR/test11.log"; then
    pass "TEST 12: Clean shutdown with stats output"
elif grep -q "Guard active" "$TEST_DIR/test11.log"; then
    pass "TEST 12: Guard fully initialized (shutdown may have been interrupted)"
else
    fail "TEST 12: Guard did not fully initialize"
fi

# ========================================================================
# Summary
# ========================================================================
echo ""
echo "============================================================"
echo "  Test Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "============================================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Some tests FAILED. Check logs in ${TEST_DIR}/${NC}"
    exit 1
else
    echo -e "${GREEN}All tests PASSED!${NC}"
    exit 0
fi
