"""Parsers for CUCM CLI command outputs"""

import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from app.models import (
    ClusterNode,
    HealthStatus,
    ReplicationStatus,
    ReplicationNodeStatus,
    ServicesStatus,
    ServiceInfo,
    NTPStatus,
    DiagnosticsStatus,
    DiagnosticTest,
    CoreFilesStatus,
)


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Args:
        text: Raw text that may contain ANSI codes

    Returns:
        Text with ANSI codes removed
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def parse_show_network_cluster(raw_output: str) -> List[ClusterNode]:
    """
    Parse the output of 'show network cluster' command.

    The command output contains a top block with node information, followed by
    a "Server Table" section. We only parse the top block.

    Example line format:
    104.156.46.39 den04wx051ccm01.wx051.webexcce.com den04wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Fri Mar 28 06:07:53 2025

    Args:
        raw_output: Raw output from the 'show network cluster' command

    Returns:
        List of ClusterNode objects, deduplicated by IP address
    """
    # Strip ANSI codes first
    clean_output = strip_ansi_codes(raw_output)

    nodes: Dict[str, ClusterNode] = {}  # Use dict for deduplication by IP

    # Split into lines
    lines = clean_output.split('\n')

    # Process lines until we hit "Server Table" section
    for line in lines:
        line = line.strip()

        # Stop processing when we hit the Server Table section
        if line.startswith('Server Table'):
            break

        # Skip empty lines or the command echo
        if not line or line.startswith('admin:'):
            continue

        # Try to parse the line
        # Expected format: IP FQDN HOST ROLE PRODUCT DBROLE [additional info...]
        # Split by whitespace and expect at least 6 fields
        parts = line.split()

        if len(parts) < 6:
            continue

        # Extract fields
        ip = parts[0]
        fqdn = parts[1]
        host = parts[2]
        role = parts[3]  # Publisher or Subscriber
        product = parts[4]  # callmanager, cups, etc.
        dbrole = parts[5]  # DBPub or DBSub

        # Validate IP format (basic check)
        if not _is_valid_ip_format(ip):
            continue

        # Validate role
        if role not in ['Publisher', 'Subscriber']:
            continue

        # Create node object (deduplicate by IP)
        if ip not in nodes:
            nodes[ip] = ClusterNode(
                ip=ip,
                fqdn=fqdn,
                host=host,
                role=role,
                product=product,
                dbrole=dbrole,
                raw=line
            )

    return list(nodes.values())


def _is_valid_ip_format(ip: str) -> bool:
    """
    Basic validation to check if a string looks like an IP address.

    Args:
        ip: String to validate

    Returns:
        True if it looks like an IP address, False otherwise
    """
    # Simple pattern: four groups of digits separated by dots
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    # Check each octet is 0-255
    octets = ip.split('.')
    try:
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False


# ============================================================================
# Health Check Parsers
# ============================================================================

# Critical CUCM services that must be running for healthy status
CRITICAL_SERVICES = [
    "Cisco CallManager",
    "Cisco CTIManager",
    "Cisco Tftp",
    "Cisco Database Layer Monitor",
    "A Cisco DB",
    "A Cisco DB Replicator",
    "Cisco Tomcat",
    "Cluster Manager",
]


def parse_dbreplication_runtimestate(raw_output: str) -> ReplicationStatus:
    """
    Parse the output of 'utils dbreplication runtimestate' command.

    Example output:
    Server Time: Fri Jan  2 16:18:22 -05 2026

    Cluster Replication State: Replication status command started at: 2026-01-02-16-18
         Replication status command COMPLETED. Checked 754 tables out of 754
         Last Completed Table: ...
         No Errors or Mismatches found.

    DB Version: ccm15_0_1_12900_234

    Repltimeout set to: 300s
    PROCESS option set to: 1

    Cluster Detailed View from cucm-01 (2 Servers):

                                               PING      DB/RPC/   REPL.    Replication    REPLICATION SETUP
    SERVER-NAME              IP ADDRESS        (msec)    DbMon?    QUEUE    Group ID       (RTMT) & Details
    -----------              ----------        ------    -------   -----    -----------    ------------------
    cucm-01                  172.168.0.101     0.045     Y/Y/Y     0        (g_2)          (2) Setup Completed
    cucm-02                  172.168.0.102     1.711     Y/Y/Y     0        (g_3)          (2) Setup Completed

    Args:
        raw_output: Raw output from the command

    Returns:
        ReplicationStatus object with parsed data
    """
    clean_output = strip_ansi_codes(raw_output)
    now = datetime.now(timezone.utc)

    # Initialize with defaults
    db_version = None
    repl_timeout = None
    tables_checked = None
    tables_total = None
    errors_found = False
    mismatches_found = False
    nodes: List[ReplicationNodeStatus] = []
    status = HealthStatus.UNKNOWN
    message = None

    # Check if replication is still in progress
    in_progress = False
    if "in PROGRESS" in clean_output or "in progress" in clean_output.lower():
        in_progress = True
        message = "Replication status check in progress"

    # Parse DB Version
    db_version_match = re.search(r'DB Version:\s*(\S+)', clean_output)
    if db_version_match:
        db_version = db_version_match.group(1)

    # Parse Replication timeout
    timeout_match = re.search(r'Repltimeout set to:\s*(\d+)s?', clean_output)
    if timeout_match:
        repl_timeout = int(timeout_match.group(1))

    # Parse tables checked
    tables_match = re.search(r'Checked\s+(\d+)\s+tables\s+out\s+of\s+(\d+)', clean_output)
    if tables_match:
        tables_checked = int(tables_match.group(1))
        tables_total = int(tables_match.group(2))

    # Check for errors or mismatches
    # First check if we have "No Errors or Mismatches found" - this means all is good
    no_errors_pattern = re.search(r'No\s+Errors?\s+(or\s+Mismatche?s?\s+)?(found|detected)', clean_output, re.IGNORECASE)

    if not no_errors_pattern:
        # Only check for errors/mismatches if we don't have the "No errors" message
        # Check for explicit error patterns like "Errors found in 3 tables"
        if re.search(r'Errors?\s+found\s+in\s+\d+', clean_output, re.IGNORECASE):
            errors_found = True
        elif re.search(r'Errors?\s+(found|detected)', clean_output, re.IGNORECASE):
            errors_found = True
        if re.search(r'Mismatche?s?\s+(found|detected)', clean_output, re.IGNORECASE):
            mismatches_found = True

    # Parse the node table
    # Look for lines that start with a hostname/server-name pattern
    # Format: SERVER-NAME  IP ADDRESS  PING(msec)  DB/RPC/DbMon?  QUEUE  Group ID  (RTMT) & Details
    node_pattern = re.compile(
        r'^(\S+)\s+'                      # Server name
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'  # IP address
        r'([\d.]+)\s+'                    # Ping (msec)
        r'([YN]/[YN]/[YN])\s+'            # DB/RPC/DbMon
        r'(\d+)\s+'                       # Replication queue
        r'\(([^)]+)\)\s+'                 # Group ID
        r'\((\d+)\)\s*(.+)?',             # RTMT state and details
        re.MULTILINE
    )

    for match in node_pattern.finditer(clean_output):
        server_name = match.group(1)
        ip_address = match.group(2)
        ping_ms = float(match.group(3))
        db_mon = match.group(4)
        repl_queue = int(match.group(5))
        group_id = match.group(6)
        setup_state = int(match.group(7))
        setup_status = match.group(8).strip() if match.group(8) else None

        nodes.append(ReplicationNodeStatus(
            server_name=server_name,
            ip_address=ip_address,
            ping_ms=ping_ms,
            db_mon=db_mon,
            repl_queue=repl_queue,
            group_id=group_id,
            setup_state=setup_state,
            setup_status=setup_status,
        ))

    # Determine overall status
    if errors_found or mismatches_found:
        status = HealthStatus.CRITICAL
        message = "Replication errors or mismatches found"
    elif in_progress:
        status = HealthStatus.UNKNOWN
    elif nodes:
        # Check all nodes for healthy status
        all_healthy = True
        any_issues = False

        for node in nodes:
            # Check DB/RPC/DbMon - all should be Y
            if node.db_mon != "Y/Y/Y":
                any_issues = True
            # Check replication queue - should be 0 or very low
            if node.repl_queue is not None and node.repl_queue > 10:
                any_issues = True
            # Check setup state - should be 2 (Setup Completed)
            if node.setup_state != 2:
                all_healthy = False

        if all_healthy and not any_issues:
            status = HealthStatus.HEALTHY
            message = "All replication checks passed"
        elif not all_healthy:
            status = HealthStatus.CRITICAL
            message = "Replication setup incomplete on one or more nodes"
        else:
            status = HealthStatus.DEGRADED
            message = "Replication has minor issues"
    else:
        # No nodes parsed - could be single node or parse error
        if "No Errors or Mismatches found" in clean_output:
            status = HealthStatus.HEALTHY
            message = "No errors or mismatches found"

    return ReplicationStatus(
        status=status,
        checked_at=now,
        db_version=db_version,
        repl_timeout=repl_timeout,
        tables_checked=tables_checked,
        tables_total=tables_total,
        errors_found=errors_found,
        mismatches_found=mismatches_found,
        nodes=nodes,
        raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
        message=message,
    )


def parse_service_list(raw_output: str) -> ServicesStatus:
    """
    Parse the output of 'utils service list' command.

    Example output:
    Requesting service status, please wait...
      Cluster Manager                      [STARTED]
      A Cisco DB                           [STARTED]
      A Cisco DB Replicator                [STARTED]
      Cisco AMC Service                    [STARTED]
      Cisco CallManager                    [STARTED]
      Cisco CTIManager                     [STOPPED]
      ...

    Args:
        raw_output: Raw output from the command

    Returns:
        ServicesStatus object with parsed data
    """
    clean_output = strip_ansi_codes(raw_output)
    now = datetime.now(timezone.utc)

    services: List[ServiceInfo] = []
    running_count = 0
    stopped_count = 0
    critical_down: List[str] = []

    # Parse service lines
    # Format: "  Service Name                       [STATUS]"
    service_pattern = re.compile(
        r'^\s*(.+?)\s+\[(STARTED|STOPPED|STARTING|STOPPING|NOT ACTIVATED)\]',
        re.MULTILINE
    )

    for match in service_pattern.finditer(clean_output):
        name = match.group(1).strip()
        status_str = match.group(2)
        is_running = status_str == "STARTED"

        services.append(ServiceInfo(
            name=name,
            status=status_str,
            is_running=is_running,
        ))

        if is_running:
            running_count += 1
        else:
            stopped_count += 1
            # Check if this is a critical service
            if any(crit.lower() in name.lower() for crit in CRITICAL_SERVICES):
                critical_down.append(name)

    # Determine overall status
    total = len(services)
    if total == 0:
        status = HealthStatus.UNKNOWN
        message = "No services found in output"
    elif critical_down:
        status = HealthStatus.CRITICAL
        message = f"Critical services down: {', '.join(critical_down)}"
    elif stopped_count > 0:
        status = HealthStatus.DEGRADED
        message = f"{stopped_count} service(s) not running"
    else:
        status = HealthStatus.HEALTHY
        message = f"All {running_count} services running"

    return ServicesStatus(
        status=status,
        checked_at=now,
        total_services=total,
        running_services=running_count,
        stopped_services=stopped_count,
        critical_services_down=critical_down,
        services=services,
        raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
        message=message,
    )


def parse_ntp_status(raw_output: str) -> NTPStatus:
    """
    Parse the output of 'utils ntp status' command.

    Example output:
    ntpd (pid 12345) is running...
    remote           refid      st t when poll reach   delay   offset  jitter
    ==============================================================================
    *10.10.10.1      .GPS.       1 u  123 1024  377    0.123    0.456   0.789

    Or:
    synchronised to NTP server (10.10.10.1) at stratum 3
       time correct to within 123 ms
       polling server every 1024 s

    Args:
        raw_output: Raw output from the command

    Returns:
        NTPStatus object with parsed data
    """
    clean_output = strip_ansi_codes(raw_output)
    now = datetime.now(timezone.utc)

    synchronized = False
    stratum = None
    ntp_server = None
    offset_ms = None
    message = None

    # Check if NTP is synchronized (not unsynchronized)
    lower_output = clean_output.lower()
    if "unsynchronised" in lower_output or "unsynchronized" in lower_output:
        synchronized = False
    elif "synchronised" in lower_output or "synchronized" in lower_output:
        synchronized = True

    # Parse stratum from various formats
    stratum_match = re.search(r'stratum\s+(\d+)', clean_output, re.IGNORECASE)
    if stratum_match:
        stratum = int(stratum_match.group(1))

    # Parse NTP server
    server_match = re.search(r'NTP server\s*\(([^)]+)\)', clean_output)
    if server_match:
        ntp_server = server_match.group(1)
    else:
        # Try to find server from ntpq-style output (line starting with *)
        ntpq_match = re.search(r'^\*(\S+)', clean_output, re.MULTILINE)
        if ntpq_match:
            ntp_server = ntpq_match.group(1)

    # Parse offset from "time correct to within X ms"
    offset_match = re.search(r'time correct to within\s+([\d.]+)\s*ms', clean_output)
    if offset_match:
        offset_ms = float(offset_match.group(1))
    else:
        # Try ntpq-style offset column
        ntpq_offset_match = re.search(r'^\*\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\d+\s+\d+\s+[\d.]+\s+([\d.-]+)', clean_output, re.MULTILINE)
        if ntpq_offset_match:
            offset_ms = float(ntpq_offset_match.group(1))

    # Determine status
    if not synchronized:
        status = HealthStatus.CRITICAL
        message = "NTP not synchronized"
    elif stratum is not None and stratum > 3:
        status = HealthStatus.DEGRADED
        message = f"NTP stratum {stratum} is higher than recommended (<=3)"
    else:
        status = HealthStatus.HEALTHY
        message = f"NTP synchronized" + (f" at stratum {stratum}" if stratum else "")

    return NTPStatus(
        status=status,
        checked_at=now,
        synchronized=synchronized,
        stratum=stratum,
        ntp_server=ntp_server,
        offset_ms=offset_ms,
        raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
        message=message,
    )


def parse_diagnose_test(raw_output: str) -> DiagnosticsStatus:
    """
    Parse the output of 'utils diagnose test' command.

    Example output:
    Log file: /var/log/active/platform/log/...
    Starting diagnostic test(s)
    ===========================
    test - validate_network : Passed
    test - ntp_reachability : Passed
    test - ntp_stratum : Passed
    test - dns_lookup : Failed - Unable to resolve hostname
    ...
    Diagnostics Completed

    Args:
        raw_output: Raw output from the command

    Returns:
        DiagnosticsStatus object with parsed data
    """
    clean_output = strip_ansi_codes(raw_output)
    now = datetime.now(timezone.utc)

    tests: List[DiagnosticTest] = []
    passed_count = 0
    failed_count = 0

    # Parse test results
    # Format: "test - test_name : Passed" or "test - test_name : Failed - reason"
    test_pattern = re.compile(
        r'test\s*-\s*(\S+)\s*:\s*(Passed|Failed)(?:\s*-\s*(.+))?',
        re.IGNORECASE | re.MULTILINE
    )

    for match in test_pattern.finditer(clean_output):
        name = match.group(1)
        passed = match.group(2).lower() == "passed"
        message = match.group(3).strip() if match.group(3) else None

        tests.append(DiagnosticTest(
            name=name,
            passed=passed,
            message=message,
        ))

        if passed:
            passed_count += 1
        else:
            failed_count += 1

    # Determine overall status
    total = len(tests)
    if total == 0:
        status = HealthStatus.UNKNOWN
        message = "No diagnostic tests found in output"
    elif failed_count > 0:
        # Check if critical tests failed
        critical_tests = ["validate_network", "ntp_reachability", "ntp_stratum"]
        critical_failed = [t.name for t in tests if not t.passed and t.name in critical_tests]

        if critical_failed:
            status = HealthStatus.CRITICAL
            message = f"Critical diagnostic tests failed: {', '.join(critical_failed)}"
        else:
            status = HealthStatus.DEGRADED
            message = f"{failed_count} diagnostic test(s) failed"
    else:
        status = HealthStatus.HEALTHY
        message = f"All {passed_count} diagnostic tests passed"

    return DiagnosticsStatus(
        status=status,
        checked_at=now,
        total_tests=total,
        passed_tests=passed_count,
        failed_tests=failed_count,
        tests=tests,
        raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
        message=message,
    )


def parse_core_active_list(raw_output: str) -> CoreFilesStatus:
    """
    Parse the output of 'utils core active list' command.

    Example output (no cores):
    No core files found.

    Example output (with cores):
    Size       Date          Core File Name
    12345      2025-01-01    core.12345.Cisco.CallManager.123456
    67890      2025-01-02    core.67890.Cisco.Tomcat.789012

    Args:
        raw_output: Raw output from the command

    Returns:
        CoreFilesStatus object with parsed data
    """
    clean_output = strip_ansi_codes(raw_output)
    now = datetime.now(timezone.utc)

    core_files: List[str] = []

    # Check for "no core files" message
    if re.search(r'no core files?\s*(found|available)?', clean_output, re.IGNORECASE):
        return CoreFilesStatus(
            status=HealthStatus.HEALTHY,
            checked_at=now,
            core_count=0,
            core_files=[],
            raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
            message="No core files found",
        )

    # Parse core file entries
    # Look for lines with core file names (typically start with "core.")
    core_pattern = re.compile(
        r'^\s*\d+\s+\S+\s+(core\.\S+)',
        re.MULTILINE
    )

    for match in core_pattern.finditer(clean_output):
        core_files.append(match.group(1))

    # Also try to match any line containing "core." as filename
    if not core_files:
        alt_pattern = re.compile(r'(core\.[^\s]+)', re.MULTILINE)
        for match in alt_pattern.finditer(clean_output):
            core_file = match.group(1)
            if core_file not in core_files:
                core_files.append(core_file)

    core_count = len(core_files)

    # Determine status
    if core_count == 0:
        status = HealthStatus.HEALTHY
        message = "No core files found"
    elif core_count <= 2:
        status = HealthStatus.DEGRADED
        message = f"{core_count} core file(s) found - investigate potential crashes"
    else:
        status = HealthStatus.CRITICAL
        message = f"{core_count} core files found - multiple service crashes detected"

    return CoreFilesStatus(
        status=status,
        checked_at=now,
        core_count=core_count,
        core_files=core_files[:20],  # Limit to 20 files in response
        raw_output=raw_output[:2000] if len(raw_output) > 2000 else raw_output,
        message=message,
    )
