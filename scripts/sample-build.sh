#!/usr/bin/env bash
set -euo pipefail
echo "=== Remote Executor Sample Build ==="
echo "Hostname: $(hostname)"
echo "Date: $(date -u)"
echo "Kernel: $(uname -r)"
echo "User: $(whoami)"
echo "Working directory: $(pwd)"

# --- Execution Marker (generated at runtime) ---
EXECUTION_MARKER=$(cat /proc/sys/kernel/random/uuid)
echo "MARKER:${EXECUTION_MARKER}"

# --- Filesystem Isolation Test ---
ISOLATION_FILE="/tmp/isolation-test.txt"
RANDOM_VALUE=$(cat /proc/sys/kernel/random/uuid)
echo "$RANDOM_VALUE" > "$ISOLATION_FILE"
sleep 2
READ_VALUE=$(cat "$ISOLATION_FILE")
if [ "$READ_VALUE" = "$RANDOM_VALUE" ]; then
    echo "ISOLATION_FILE:PASS"
else
    echo "ISOLATION_FILE:FAIL"
fi

# --- Process Isolation Test ---
PROC_NAME="isolation-probe-${EXECUTION_MARKER}"
# Start a uniquely-named dummy background process
bash -c "exec -a $PROC_NAME sleep 300" &
DUMMY_PID=$!
sleep 1
# Count how many processes with this unique name are visible
# Use /proc directly since ps may not be installed in the container
PROC_COUNT=0
for pid_dir in /proc/[0-9]*; do
    cmdline_file="${pid_dir}/cmdline"
    if [ -r "$cmdline_file" ] 2>/dev/null; then
        # cmdline uses null bytes as separators; tr converts them for grep
        if tr '\0' ' ' < "$cmdline_file" 2>/dev/null | grep -qF "$PROC_NAME"; then
            PROC_COUNT=$((PROC_COUNT + 1))
        fi
    fi
done
if [ "$PROC_COUNT" -eq 1 ]; then
    echo "ISOLATION_PROCESS:PASS"
else
    echo "ISOLATION_PROCESS:FAIL (visible=$PROC_COUNT)"
fi
# Cleanup dummy process
kill "$DUMMY_PID" 2>/dev/null || true
wait "$DUMMY_PID" 2>/dev/null || true

echo "=== Build Complete ==="
