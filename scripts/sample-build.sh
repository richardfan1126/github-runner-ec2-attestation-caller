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

# --- Long output with sleeps for polling test ---
PHASES=("INITIALIZING" "COMPILING" "LINKING" "OPTIMIZING" "PACKAGING" "VALIDATING" "FINALIZING")

for phase in "${PHASES[@]}"; do
    echo ""
    echo "========================================"
    echo "  PHASE: ${phase}"
    echo "========================================"
    for i in $(seq 1 15); do
        echo "[${phase}] Step ${i}/15 - Processing module-${i}-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
        echo "[${phase}] Step ${i}/15 - Resolving dependencies for component-${i}"
        echo "[${phase}] Step ${i}/15 - Verifying checksum: sha256-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
        echo "[${phase}] Step ${i}/15 - Artifact registry lookup complete"
        echo "[${phase}] Step ${i}/15 - Status: OK"
    done
    echo "[${phase}] Phase complete."
    sleep 3
done

# --- Filesystem Isolation Test ---
echo ""
echo "========================================"
echo "  ISOLATION TESTS"
echo "========================================"
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
bash -c "exec -a $PROC_NAME sleep 300" &
DUMMY_PID=$!
sleep 1
PROC_COUNT=0
for pid_dir in /proc/[0-9]*; do
    cmdline_file="${pid_dir}/cmdline"
    if [ -r "$cmdline_file" ] 2>/dev/null; then
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
kill "$DUMMY_PID" 2>/dev/null || true
wait "$DUMMY_PID" 2>/dev/null || true

# --- Final long tail output ---
echo ""
echo "========================================"
echo "  POST-BUILD REPORT"
echo "========================================"
for i in $(seq 1 50); do
    echo "Report line ${i}/50: artifact-${i} digest=$(cat /proc/sys/kernel/random/uuid) size=$((RANDOM % 9999 + 100))KB status=VERIFIED"
done
sleep 2

echo ""
echo "=== Build Complete ==="
