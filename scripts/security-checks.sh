#!/usr/bin/env bash
set -uo pipefail
# NOTE: -e is intentionally omitted — the script must continue after
# individual check failures so every check runs and reports its result.

SCRIPT_VERSION="1.0"
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

report_result() {
    local category="$1" check_name="$2" status="$3" detail="$4"
    echo "SECURITY_CHECK:${category}:${check_name}:${status}:${detail}"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        # SKIP and ERROR count toward TOTAL but not PASSED or FAILED
    esac
}

check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

echo "SECURITY_HEADER:version=${SCRIPT_VERSION}:hostname=$(hostname):date=$(date -u +%Y-%m-%dT%H:%M:%SZ):kernel=$(uname -r)"

# ---------------------------------------------------------------------------
# Category: Network Isolation
# ---------------------------------------------------------------------------

check_network_isolation() {
    # DNS resolution — should fail in an isolated container
    if ! check_tool nslookup; then
        report_result "network" "dns_resolution" "SKIP" "nslookup not available"
    else
        if timeout 3 nslookup example.com >/dev/null 2>&1; then
            report_result "network" "dns_resolution" "FAIL" "DNS resolution succeeded"
        else
            report_result "network" "dns_resolution" "PASS" "DNS resolution failed as expected"
        fi
    fi

    # TCP connection — should fail in an isolated container
    if timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/443' >/dev/null 2>&1; then
        report_result "network" "tcp_connection" "FAIL" "TCP connection to 1.1.1.1:443 succeeded"
    else
        report_result "network" "tcp_connection" "PASS" "TCP connection failed as expected"
    fi

    # Network interfaces — only loopback should be present
    if ! check_tool ip; then
        report_result "network" "interfaces" "SKIP" "ip command not available"
    else
        local extra_ifaces
        extra_ifaces=$(ip -o link show 2>&1 | grep -v '^1: lo' || true)
        if [ -z "$extra_ifaces" ]; then
            report_result "network" "interfaces" "PASS" "Only loopback interface present"
        else
            report_result "network" "interfaces" "FAIL" "Additional interfaces found: ${extra_ifaces}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Category: Filesystem Isolation
# ---------------------------------------------------------------------------

check_filesystem_isolation() {
    # Root filesystem should be read-only
    local root_output
    root_output=$(touch /root-write-test 2>&1)
    if [ $? -ne 0 ]; then
        report_result "filesystem" "root_readonly" "PASS" "Root filesystem is read-only"
    else
        rm -f /root-write-test 2>/dev/null
        report_result "filesystem" "root_readonly" "FAIL" "Root filesystem is writable"
    fi

    # /tmp should be writable
    if touch /tmp/write-test 2>/dev/null && rm /tmp/write-test 2>/dev/null; then
        report_result "filesystem" "tmp_writable" "PASS" "/tmp is writable"
    else
        report_result "filesystem" "tmp_writable" "FAIL" "/tmp is not writable"
    fi

    # /workspace should be read-only
    local ws_output
    ws_output=$(touch /workspace/write-test 2>&1)
    if [ $? -ne 0 ]; then
        report_result "filesystem" "workspace_readonly" "PASS" "/workspace is read-only"
    else
        rm -f /workspace/write-test 2>/dev/null
        report_result "filesystem" "workspace_readonly" "FAIL" "/workspace is writable"
    fi

    # /tmp tmpfs size limit should be ≤ 64 MB
    if ! check_tool df; then
        report_result "filesystem" "tmp_size_limit" "SKIP" "df not available"
    else
        local tmp_size
        tmp_size=$(df -m /tmp 2>/dev/null | awk 'NR==2{print $2}')
        if [ -z "$tmp_size" ]; then
            report_result "filesystem" "tmp_size_limit" "ERROR" "Could not determine /tmp size"
        elif [ "$tmp_size" -le 64 ] 2>/dev/null; then
            report_result "filesystem" "tmp_size_limit" "PASS" "/tmp size is ${tmp_size} MB (limit 64 MB)"
        else
            report_result "filesystem" "tmp_size_limit" "FAIL" "/tmp size is ${tmp_size} MB, exceeds 64 MB limit"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Category: Capabilities and Privileges
# ---------------------------------------------------------------------------

check_capabilities() {
    # Running as nobody user (UID 65534)
    local uid
    uid=$(id -u 2>/dev/null)
    if [ "$uid" = "65534" ]; then
        report_result "capabilities" "user_nobody" "PASS" "Running as nobody (UID 65534)"
    else
        report_result "capabilities" "user_nobody" "FAIL" "Running as UID ${uid}, expected 65534"
    fi

    # All capability sets should be zero
    local cap_lines non_zero_caps
    cap_lines=$(grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status 2>/dev/null || true)
    if [ -z "$cap_lines" ]; then
        report_result "capabilities" "all_caps_zero" "ERROR" "Could not read capability sets from /proc/self/status"
    else
        non_zero_caps=$(echo "$cap_lines" | grep -v '0000000000000000' || true)
        if [ -z "$non_zero_caps" ]; then
            report_result "capabilities" "all_caps_zero" "PASS" "All capability sets are zero"
        else
            report_result "capabilities" "all_caps_zero" "FAIL" "Non-zero capabilities found: ${non_zero_caps}"
        fi
    fi

    # Privileged operation should be denied
    # Create a temp file first so chown has a target
    touch /tmp/cap-test 2>/dev/null || true
    if chown root /tmp/cap-test >/dev/null 2>&1; then
        report_result "capabilities" "privileged_op_denied" "FAIL" "chown root succeeded"
    else
        report_result "capabilities" "privileged_op_denied" "PASS" "Privileged operation denied as expected"
    fi
    rm -f /tmp/cap-test 2>/dev/null || true

    # NoNewPrivs flag should be set to 1
    local no_new_privs
    no_new_privs=$(grep '^NoNewPrivs:' /proc/self/status 2>/dev/null | awk '{print $2}')
    if [ -z "$no_new_privs" ]; then
        report_result "capabilities" "no_new_privs" "ERROR" "Could not read NoNewPrivs from /proc/self/status"
    elif [ "$no_new_privs" = "1" ]; then
        report_result "capabilities" "no_new_privs" "PASS" "NoNewPrivs flag is set"
    else
        report_result "capabilities" "no_new_privs" "FAIL" "NoNewPrivs flag is ${no_new_privs}, expected 1"
    fi
}

# ---------------------------------------------------------------------------
# Category: Resource Limits
# ---------------------------------------------------------------------------

check_resource_limits() {
    # Memory limit — try cgroup v2 first, then v1
    if [ -f /sys/fs/cgroup/memory.max ]; then
        local mem_max
        mem_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)
        if [ "$mem_max" = "max" ]; then
            report_result "resources" "memory_limit" "FAIL" "No memory limit set (cgroup v2 reports max)"
        else
            report_result "resources" "memory_limit" "PASS" "Memory limit is ${mem_max} bytes (cgroup v2)"
        fi
    elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        local mem_limit
        mem_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
        # A very large value (close to max int64) means no real limit
        if [ "$mem_limit" -gt 9000000000000000000 ] 2>/dev/null; then
            report_result "resources" "memory_limit" "FAIL" "No effective memory limit set (cgroup v1)"
        else
            report_result "resources" "memory_limit" "PASS" "Memory limit is ${mem_limit} bytes (cgroup v1)"
        fi
    else
        report_result "resources" "memory_limit" "SKIP" "Neither cgroup v2 nor v1 memory interface found"
    fi

    # CPU limit — try cgroup v2 first, then v1
    if [ -f /sys/fs/cgroup/cpu.max ]; then
        local cpu_max
        cpu_max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null)
        local cpu_quota
        cpu_quota=$(echo "$cpu_max" | awk '{print $1}')
        if [ "$cpu_quota" = "max" ]; then
            report_result "resources" "cpu_limit" "FAIL" "No CPU limit set (cgroup v2 reports max)"
        else
            report_result "resources" "cpu_limit" "PASS" "CPU limit is ${cpu_max} (cgroup v2)"
        fi
    elif [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
        local cpu_quota_v1
        cpu_quota_v1=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null)
        if [ "$cpu_quota_v1" = "-1" ]; then
            report_result "resources" "cpu_limit" "FAIL" "No CPU limit set (cgroup v1 quota is -1)"
        else
            report_result "resources" "cpu_limit" "PASS" "CPU quota is ${cpu_quota_v1} us (cgroup v1)"
        fi
    else
        report_result "resources" "cpu_limit" "SKIP" "Neither cgroup v2 nor v1 CPU interface found"
    fi
}

# ---------------------------------------------------------------------------
# Category: Process Isolation
# ---------------------------------------------------------------------------

check_process_isolation() {
    # Visible process count should be small (< 10)
    local pid_count
    pid_count=$(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | wc -l)
    if [ "$pid_count" -lt 10 ]; then
        report_result "process" "pid_namespace" "PASS" "Only ${pid_count} processes visible"
    else
        report_result "process" "pid_namespace" "FAIL" "${pid_count} processes visible, expected fewer than 10"
    fi

    # PID 1 should be the bash entrypoint
    local pid1_cmd
    pid1_cmd=$(cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ')
    if [ -z "$pid1_cmd" ]; then
        report_result "process" "pid1_entrypoint" "ERROR" "Could not read /proc/1/cmdline"
    elif echo "$pid1_cmd" | grep -q "bash"; then
        report_result "process" "pid1_entrypoint" "PASS" "PID 1 is bash: ${pid1_cmd}"
    else
        report_result "process" "pid1_entrypoint" "FAIL" "PID 1 is not bash: ${pid1_cmd}"
    fi
}

# ---------------------------------------------------------------------------
# Category: Host-Level Hardening
# ---------------------------------------------------------------------------

check_host_hardening() {
    # Host /health endpoint should be unreachable
    if timeout 3 bash -c 'echo > /dev/tcp/172.17.0.1/8080' >/dev/null 2>&1; then
        report_result "host" "health_unreachable" "FAIL" "Host /health endpoint is reachable at 172.17.0.1:8080"
    else
        report_result "host" "health_unreachable" "PASS" "Host /health endpoint is unreachable"
    fi

    # No sensitive environment variables should be set
    local sensitive_vars
    sensitive_vars=$(env 2>/dev/null | grep -iE '(GITHUB_TOKEN|OIDC|AWS_SECRET|AWS_ACCESS|AWS_SESSION)' || true)
    if [ -z "$sensitive_vars" ]; then
        report_result "host" "no_sensitive_env" "PASS" "No sensitive environment variables found"
    else
        report_result "host" "no_sensitive_env" "FAIL" "Sensitive environment variables found: ${sensitive_vars}"
    fi
}

# ---------------------------------------------------------------------------
# Category: Attestation Isolation
# ---------------------------------------------------------------------------

check_attestation_isolation() {
    # /dev/nsm device should be absent
    if test -e /dev/nsm; then
        report_result "attestation" "nsm_device_absent" "FAIL" "/dev/nsm device exists"
    else
        report_result "attestation" "nsm_device_absent" "PASS" "/dev/nsm device is absent"
    fi

    # nitro-tpm-attest binary should be absent
    if which nitro-tpm-attest >/dev/null 2>&1; then
        report_result "attestation" "attest_binary_absent" "FAIL" "nitro-tpm-attest binary found"
    else
        report_result "attestation" "attest_binary_absent" "PASS" "nitro-tpm-attest binary not found"
    fi

    # Reading /dev/nsm should fail
    local nsm_output
    nsm_output=$(cat /dev/nsm 2>&1)
    if [ $? -ne 0 ]; then
        report_result "attestation" "nsm_read_fails" "PASS" "/dev/nsm read failed as expected"
    else
        report_result "attestation" "nsm_read_fails" "FAIL" "/dev/nsm read returned data"
    fi

    # No TPM-related device nodes should be present
    local tpm_devices
    tpm_devices=$(ls /dev/ 2>/dev/null | grep -iE '(nsm|tpm|tpmrm)' || true)
    if [ -z "$tpm_devices" ]; then
        report_result "attestation" "no_tpm_devices" "PASS" "No TPM-related device nodes found"
    else
        report_result "attestation" "no_tpm_devices" "FAIL" "TPM-related devices found: ${tpm_devices}"
    fi

    # Attestation Python modules should not be importable
    local cbor2_fail=0 wolfcrypt_fail=0
    if check_tool python3; then
        python3 -c 'import cbor2' >/dev/null 2>&1 || cbor2_fail=1
        python3 -c 'import wolfcrypt' >/dev/null 2>&1 || wolfcrypt_fail=1
        if [ "$cbor2_fail" -eq 1 ] && [ "$wolfcrypt_fail" -eq 1 ]; then
            report_result "attestation" "no_attest_libs" "PASS" "Attestation Python modules not importable"
        else
            local importable=""
            [ "$cbor2_fail" -eq 0 ] && importable="cbor2"
            [ "$wolfcrypt_fail" -eq 0 ] && importable="${importable:+${importable}, }wolfcrypt"
            report_result "attestation" "no_attest_libs" "FAIL" "Attestation modules importable: ${importable}"
        fi
    else
        report_result "attestation" "no_attest_libs" "SKIP" "python3 not available"
    fi
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

check_network_isolation
check_filesystem_isolation
check_capabilities
check_resource_limits
check_process_isolation
check_host_hardening
check_attestation_isolation

# ---------------------------------------------------------------------------
# Summary and exit code
# ---------------------------------------------------------------------------

echo "SECURITY_SUMMARY:TOTAL=${TOTAL_COUNT}:PASSED=${PASS_COUNT}:FAILED=${FAIL_COUNT}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
else
    exit 0
fi
