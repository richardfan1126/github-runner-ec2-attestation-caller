# Requirements Document

## Introduction

A bash script that runs inside the Remote Executor's Docker container (via the standard execution flow) and verifies that the server's security hardening is correctly applied. The script is submitted through the caller workflow like any other script, executes on the attestable EC2 instance, and reports pass/fail results for each security check. This provides an automated, repeatable way to validate that the server's defense-in-depth controls — container isolation, host hardening, service sandboxing, Docker daemon configuration, and network restrictions — are functioning as expected after deployment or AMI updates.

## Glossary

- **Security_Test_Script**: The bash script that runs inside the executor container and performs security verification checks
- **Remote_Executor**: The attestable EC2 server that executes scripts inside Docker containers with NitroTPM attestation
- **Executor_Container**: The Docker container created by the Remote Executor to run submitted scripts, configured with security constraints (read-only filesystem, no network, dropped capabilities, nobody user)
- **Host**: The EC2 instance running the Remote Executor server and Docker daemon
- **Caller_Workflow**: The GitHub Actions workflow that submits scripts to the Remote Executor via encrypted, attested communication
- **Test_Report**: The structured stdout output produced by the Security_Test_Script containing pass/fail results for each check
- **NitroTPM**: The Trusted Platform Module available on attestable EC2 instances, used for generating cryptographic attestation documents

## Requirements

### Requirement 1: Container Network Isolation Verification

**User Story:** As a security engineer, I want the script to verify that the container has no network access, so that I can confirm executed scripts cannot exfiltrate data or communicate with external services.

#### Acceptance Criteria

1. WHEN the Security_Test_Script attempts to resolve a DNS name, THE Security_Test_Script SHALL report PASS if the resolution fails and FAIL if the resolution succeeds
2. WHEN the Security_Test_Script attempts to open a TCP connection to an external host, THE Security_Test_Script SHALL report PASS if the connection is refused or times out and FAIL if the connection succeeds
3. WHEN the Security_Test_Script inspects the available network interfaces, THE Security_Test_Script SHALL report PASS if only the loopback interface is present and FAIL if additional interfaces are found

### Requirement 2: Container Filesystem Isolation Verification

**User Story:** As a security engineer, I want the script to verify that the container filesystem is read-only with only the expected writable paths, so that I can confirm executed scripts cannot persist data or tamper with the execution environment.

#### Acceptance Criteria

1. WHEN the Security_Test_Script attempts to write a file to the root filesystem (outside /tmp and /workspace), THE Security_Test_Script SHALL report PASS if the write fails with a read-only error and FAIL if the write succeeds
2. WHEN the Security_Test_Script attempts to write a file to /tmp, THE Security_Test_Script SHALL report PASS if the write succeeds (confirming the tmpfs mount is functional) and FAIL if the write is denied
3. WHEN the Security_Test_Script checks the mount options of the /workspace directory, THE Security_Test_Script SHALL report PASS if /workspace is mounted read-only and FAIL if /workspace is writable
4. WHEN the Security_Test_Script checks the size limit of the /tmp tmpfs mount, THE Security_Test_Script SHALL report PASS if the available size is bounded (64 MB or less) and FAIL if the size exceeds the expected limit

### Requirement 3: Container Capability and Privilege Verification

**User Story:** As a security engineer, I want the script to verify that the container runs with minimal privileges, so that I can confirm that privilege escalation paths are blocked.

#### Acceptance Criteria

1. WHEN the Security_Test_Script reads the effective user identity, THE Security_Test_Script SHALL report PASS if the process runs as the nobody user (UID 65534) and FAIL if it runs as root or another user
2. WHEN the Security_Test_Script reads the process capability sets from /proc/self/status, THE Security_Test_Script SHALL report PASS if all capability sets (CapInh, CapPrm, CapEff, CapBnd, CapAmb) are zero and FAIL if any capability is granted
3. WHEN the Security_Test_Script attempts to use a privileged operation (such as changing file ownership), THE Security_Test_Script SHALL report PASS if the operation is denied and FAIL if the operation succeeds
4. WHEN the Security_Test_Script reads the NoNewPrivs flag from /proc/self/status, THE Security_Test_Script SHALL report PASS if the flag is set to 1 and FAIL if it is set to 0

### Requirement 4: Container Resource Limits Verification

**User Story:** As a security engineer, I want the script to verify that the container has resource limits applied, so that I can confirm that a malicious script cannot exhaust host resources.

#### Acceptance Criteria

1. WHEN the Security_Test_Script reads the memory limit from the cgroup interface, THE Security_Test_Script SHALL report PASS if a memory limit is enforced and FAIL if no limit is set or the limit is unreasonably high
2. WHEN the Security_Test_Script reads the CPU quota from the cgroup interface, THE Security_Test_Script SHALL report PASS if a CPU limit is enforced and FAIL if no CPU limit is set

### Requirement 5: Container Process Isolation Verification

**User Story:** As a security engineer, I want the script to verify that the container has an isolated process namespace, so that I can confirm that executed scripts cannot observe or interfere with host processes or other containers.

#### Acceptance Criteria

1. WHEN the Security_Test_Script enumerates processes visible in /proc, THE Security_Test_Script SHALL report PASS if only the script's own process tree is visible and FAIL if host or other container processes are visible
2. WHEN the Security_Test_Script reads /proc/1/cmdline, THE Security_Test_Script SHALL report PASS if PID 1 is the container entrypoint (bash) and FAIL if PID 1 is a host init system

### Requirement 6: Host-Level Hardening Verification via Server API

**User Story:** As a security engineer, I want the script to verify that the server API endpoints behave securely, so that I can confirm that the server enforces authentication and rate limiting as expected.

#### Acceptance Criteria

1. WHEN the Security_Test_Script checks whether the /health endpoint is reachable from inside the container, THE Security_Test_Script SHALL report PASS if the request fails (confirming network isolation prevents reaching the host server) and FAIL if the request succeeds
2. WHEN the Security_Test_Script checks for the presence of sensitive environment variables (GITHUB_TOKEN, OIDC tokens, AWS credentials), THE Security_Test_Script SHALL report PASS if no sensitive environment variables are set inside the container and FAIL if any are found

### Requirement 7: Test Report Output Format

**User Story:** As a DevOps engineer, I want the script to produce structured, machine-parseable output, so that I can integrate security test results into CI pipelines and monitoring dashboards.

#### Acceptance Criteria

1. THE Security_Test_Script SHALL output each test result on a separate line in the format SECURITY_CHECK:<category>:<check_name>:<PASS|FAIL>:<detail_message>
2. WHEN all checks have completed, THE Security_Test_Script SHALL output a summary line in the format SECURITY_SUMMARY:TOTAL=<n>:PASSED=<p>:FAILED=<f>
3. IF any security check fails, THEN THE Security_Test_Script SHALL exit with a non-zero exit code
4. WHEN all security checks pass, THE Security_Test_Script SHALL exit with exit code 0
5. THE Security_Test_Script SHALL output a header line containing the script version, hostname, date, and kernel version before running any checks

### Requirement 8: Attestation Document Generation Isolation Verification

**User Story:** As a security engineer, I want the script to verify that the executor container cannot generate attestation documents, so that I can confirm that a malicious script cannot forge attestation and bypass the security model.

#### Acceptance Criteria

1. WHEN the Security_Test_Script checks for the presence of the NitroTPM device path /dev/nsm inside the container, THE Security_Test_Script SHALL report PASS if the device does not exist and FAIL if the device is accessible
2. WHEN the Security_Test_Script checks for the presence of the nitro-tpm-attest binary (at /usr/bin/nitro-tpm-attest or elsewhere in PATH), THE Security_Test_Script SHALL report PASS if the binary is not found and FAIL if the binary is present
3. WHEN the Security_Test_Script attempts to read from /dev/nsm, THE Security_Test_Script SHALL report PASS if the read operation fails with a "no such file or device" error and FAIL if any data is returned
4. WHEN the Security_Test_Script enumerates device nodes visible under /dev, THE Security_Test_Script SHALL report PASS if no TPM-related device nodes (nsm, tpm, tpmrm) are present and FAIL if any TPM-related device nodes are found
5. WHEN the Security_Test_Script checks for attestation-related libraries or Python modules (such as the cbor2 or wolfcrypt packages used by the attestation system), THE Security_Test_Script SHALL report PASS if the modules are not importable and FAIL if any attestation-related module is available

### Requirement 9: Script Robustness

**User Story:** As a DevOps engineer, I want the script to handle unexpected environments gracefully, so that I can get meaningful results even when running on a misconfigured or partially broken server.

#### Acceptance Criteria

1. IF a required tool (such as ip, cat, or grep) is not available in the container, THEN THE Security_Test_Script SHALL report SKIP for checks that depend on the missing tool and continue executing remaining checks
2. IF a check encounters an unexpected error, THEN THE Security_Test_Script SHALL report ERROR for that check with the error detail and continue executing remaining checks
3. THE Security_Test_Script SHALL complete all checks within 30 seconds under normal conditions
