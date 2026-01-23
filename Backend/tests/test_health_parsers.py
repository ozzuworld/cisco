"""Unit tests for CUCM health check parsers"""

import pytest
from datetime import datetime, timezone
from app.parsers import (
    parse_dbreplication_runtimestate,
    parse_service_list,
    parse_ntp_status,
    parse_diagnose_test,
    parse_core_active_list,
)
from app.models import HealthStatus


# ============================================================================
# Test Data - DB Replication
# ============================================================================

REPLICATION_HEALTHY_OUTPUT = """admin:utils dbreplication runtimestate

Server Time: Fri Jan  2 16:18:22 -05 2026

Cluster Replication State: Replication status command started at: 2026-01-02-16-18
     Replication status command COMPLETED. Checked 754 tables out of 754
     Last Completed Table: functionrole
     No Errors or Mismatches found.

     Use 'file view activelog cm/trace/dbl/sdi/ReplicationStatus.2026_01_02_16_18_07.out' to see the details


DB Version: ccm15_0_1_12900_234

Repltimeout set to: 300s
PROCESS option set to: 1


Cluster Detailed View from cucm-01 (2 Servers):

                                           PING      DB/RPC/   REPL.    Replication    REPLICATION SETUP
SERVER-NAME              IP ADDRESS        (msec)    DbMon?    QUEUE    Group ID       (RTMT) & Details
-----------              ----------        ------    -------   -----    -----------    ------------------
cucm-01                  172.168.0.101     0.045     Y/Y/Y     0        (g_2)          (2) Setup Completed
cucm-02                  172.168.0.102     1.711     Y/Y/Y     0        (g_3)          (2) Setup Completed
"""

REPLICATION_IN_PROGRESS_OUTPUT = """admin:utils dbreplication runtimestate

Server Time: Fri Jan  2 16:18:22 -05 2026

Cluster Replication State: Replication status command started at: 2026-01-02-16-18
     Replication status command in PROGRESS. Checked 134 tables out of 754
     Last Completed Table: functionrole
     No Errors or Mismatches found.

DB Version: ccm15_0_1_12900_234
"""

REPLICATION_ERROR_OUTPUT = """admin:utils dbreplication runtimestate

Server Time: Fri Jan  2 16:18:22 -05 2026

Cluster Replication State: Replication status command COMPLETED. Checked 754 tables out of 754
     Errors found in 3 tables.

DB Version: ccm15_0_1_12900_234

Cluster Detailed View from cucm-01 (2 Servers):

                                           PING      DB/RPC/   REPL.    Replication    REPLICATION SETUP
SERVER-NAME              IP ADDRESS        (msec)    DbMon?    QUEUE    Group ID       (RTMT) & Details
-----------              ----------        ------    -------   -----    -----------    ------------------
cucm-01                  172.168.0.101     0.045     Y/Y/Y     0        (g_2)          (2) Setup Completed
cucm-02                  172.168.0.102     1.711     N/Y/Y     5        (g_3)          (4) Setup Incomplete
"""


# ============================================================================
# Test Data - Services
# ============================================================================

SERVICES_HEALTHY_OUTPUT = """admin:utils service list
Requesting service status, please wait...
  Cluster Manager                      [STARTED]
  A Cisco DB                           [STARTED]
  A Cisco DB Replicator                [STARTED]
  Cisco AMC Service                    [STARTED]
  Cisco CallManager                    [STARTED]
  Cisco CTIManager                     [STARTED]
  Cisco Tftp                           [STARTED]
  Cisco Database Layer Monitor         [STARTED]
  Cisco Tomcat                         [STARTED]
  Cisco AXL Web Service                [STARTED]
"""

SERVICES_CRITICAL_OUTPUT = """admin:utils service list
Requesting service status, please wait...
  Cluster Manager                      [STARTED]
  A Cisco DB                           [STARTED]
  A Cisco DB Replicator                [STARTED]
  Cisco AMC Service                    [STARTED]
  Cisco CallManager                    [STOPPED]
  Cisco CTIManager                     [STARTED]
  Cisco Tftp                           [STARTED]
  Cisco Database Layer Monitor         [STARTED]
  Cisco Tomcat                         [STARTED]
"""

SERVICES_DEGRADED_OUTPUT = """admin:utils service list
Requesting service status, please wait...
  Cluster Manager                      [STARTED]
  A Cisco DB                           [STARTED]
  A Cisco DB Replicator                [STARTED]
  Cisco AMC Service                    [STOPPED]
  Cisco CallManager                    [STARTED]
  Cisco CTIManager                     [STARTED]
  Cisco Tftp                           [STARTED]
  Cisco Database Layer Monitor         [STARTED]
  Cisco Tomcat                         [STARTED]
"""


# ============================================================================
# Test Data - NTP
# ============================================================================

NTP_HEALTHY_OUTPUT = """admin:utils ntp status
ntpd (pid 12345) is running...
synchronised to NTP server (10.10.10.1) at stratum 2
   time correct to within 45 ms
   polling server every 1024 s
"""

NTP_UNHEALTHY_OUTPUT = """admin:utils ntp status
ntpd (pid 12345) is running...
unsynchronised
   time server re-starting
   polling server every 64 s
"""

NTP_HIGH_STRATUM_OUTPUT = """admin:utils ntp status
ntpd (pid 12345) is running...
synchronised to NTP server (10.10.10.1) at stratum 5
   time correct to within 123 ms
   polling server every 1024 s
"""


# ============================================================================
# Test Data - Diagnostics
# ============================================================================

DIAGNOSTICS_HEALTHY_OUTPUT = """admin:utils diagnose test
Log file: /var/log/active/platform/log/...
Starting diagnostic test(s)
===========================
test - validate_network : Passed
test - ntp_reachability : Passed
test - ntp_stratum : Passed
test - dns_lookup : Passed
test - disk_space : Passed

Diagnostics Completed
"""

DIAGNOSTICS_FAILED_OUTPUT = """admin:utils diagnose test
Log file: /var/log/active/platform/log/...
Starting diagnostic test(s)
===========================
test - validate_network : Failed - Network validation error
test - ntp_reachability : Passed
test - ntp_stratum : Passed
test - dns_lookup : Failed - Unable to resolve hostname
test - disk_space : Passed

Diagnostics Completed
"""

DIAGNOSTICS_CRITICAL_FAILED_OUTPUT = """admin:utils diagnose test
Log file: /var/log/active/platform/log/...
Starting diagnostic test(s)
===========================
test - validate_network : Failed - Network validation error
test - ntp_reachability : Failed - NTP server unreachable
test - ntp_stratum : Passed
test - dns_lookup : Passed

Diagnostics Completed
"""

DIAGNOSTICS_NON_CRITICAL_FAILED_OUTPUT = """admin:utils diagnose test
Log file: /var/log/active/platform/log/...
Starting diagnostic test(s)
===========================
test - validate_network : Passed
test - ntp_reachability : Passed
test - ntp_stratum : Passed
test - dns_lookup : Failed - Unable to resolve hostname
test - disk_space : Passed

Diagnostics Completed
"""


# ============================================================================
# Test Data - Core Files
# ============================================================================

CORE_FILES_NONE_OUTPUT = """admin:utils core active list
No core files found.
"""

CORE_FILES_SOME_OUTPUT = """admin:utils core active list
Size       Date          Core File Name
12345      2025-01-01    core.12345.Cisco.CallManager.123456
67890      2025-01-02    core.67890.Cisco.Tomcat.789012
"""

CORE_FILES_MANY_OUTPUT = """admin:utils core active list
Size       Date          Core File Name
12345      2025-01-01    core.12345.Cisco.CallManager.123456
67890      2025-01-02    core.67890.Cisco.Tomcat.789012
11111      2025-01-03    core.11111.Cisco.Service1.111111
22222      2025-01-04    core.22222.Cisco.Service2.222222
"""


# ============================================================================
# DB Replication Tests
# ============================================================================

class TestParseDbReplication:
    """Tests for parse_dbreplication_runtimestate"""

    def test_healthy_replication(self):
        """Test parsing healthy replication output"""
        result = parse_dbreplication_runtimestate(REPLICATION_HEALTHY_OUTPUT)

        assert result.status == HealthStatus.HEALTHY
        assert result.db_version == "ccm15_0_1_12900_234"
        assert result.repl_timeout == 300
        assert result.tables_checked == 754
        assert result.tables_total == 754
        assert result.errors_found is False
        assert result.mismatches_found is False
        assert len(result.nodes) == 2

        # Check first node
        node1 = result.nodes[0]
        assert node1.server_name == "cucm-01"
        assert node1.ip_address == "172.168.0.101"
        assert node1.ping_ms == 0.045
        assert node1.db_mon == "Y/Y/Y"
        assert node1.repl_queue == 0
        assert node1.setup_state == 2

    def test_replication_in_progress(self):
        """Test parsing replication in progress"""
        result = parse_dbreplication_runtimestate(REPLICATION_IN_PROGRESS_OUTPUT)

        assert result.status == HealthStatus.UNKNOWN
        assert result.tables_checked == 134
        assert result.tables_total == 754
        assert "in progress" in result.message.lower()

    def test_replication_with_errors(self):
        """Test parsing replication with errors"""
        result = parse_dbreplication_runtimestate(REPLICATION_ERROR_OUTPUT)

        assert result.status == HealthStatus.CRITICAL
        assert result.errors_found is True

        # Check degraded node
        node2 = result.nodes[1]
        assert node2.db_mon == "N/Y/Y"
        assert node2.repl_queue == 5
        assert node2.setup_state == 4

    def test_empty_output(self):
        """Test parsing empty output"""
        result = parse_dbreplication_runtimestate("")

        assert result.status == HealthStatus.UNKNOWN


# ============================================================================
# Services Tests
# ============================================================================

class TestParseServices:
    """Tests for parse_service_list"""

    def test_all_services_running(self):
        """Test parsing when all services are running"""
        result = parse_service_list(SERVICES_HEALTHY_OUTPUT)

        assert result.status == HealthStatus.HEALTHY
        assert result.total_services == 10
        assert result.running_services == 10
        assert result.stopped_services == 0
        assert len(result.critical_services_down) == 0

    def test_critical_service_down(self):
        """Test parsing when critical service is down"""
        result = parse_service_list(SERVICES_CRITICAL_OUTPUT)

        assert result.status == HealthStatus.CRITICAL
        assert result.stopped_services == 1
        assert "Cisco CallManager" in result.critical_services_down

    def test_non_critical_service_down(self):
        """Test parsing when non-critical service is down"""
        result = parse_service_list(SERVICES_DEGRADED_OUTPUT)

        assert result.status == HealthStatus.DEGRADED
        assert result.stopped_services == 1
        assert len(result.critical_services_down) == 0

    def test_empty_output(self):
        """Test parsing empty output"""
        result = parse_service_list("")

        assert result.status == HealthStatus.UNKNOWN
        assert result.total_services == 0


# ============================================================================
# NTP Tests
# ============================================================================

class TestParseNtp:
    """Tests for parse_ntp_status"""

    def test_ntp_synchronized(self):
        """Test parsing synchronized NTP"""
        result = parse_ntp_status(NTP_HEALTHY_OUTPUT)

        assert result.status == HealthStatus.HEALTHY
        assert result.synchronized is True
        assert result.stratum == 2
        assert result.ntp_server == "10.10.10.1"
        assert result.offset_ms == 45.0

    def test_ntp_not_synchronized(self):
        """Test parsing unsynchronized NTP"""
        result = parse_ntp_status(NTP_UNHEALTHY_OUTPUT)

        assert result.status == HealthStatus.CRITICAL
        assert result.synchronized is False

    def test_ntp_high_stratum(self):
        """Test parsing NTP with high stratum"""
        result = parse_ntp_status(NTP_HIGH_STRATUM_OUTPUT)

        assert result.status == HealthStatus.DEGRADED
        assert result.synchronized is True
        assert result.stratum == 5


# ============================================================================
# Diagnostics Tests
# ============================================================================

class TestParseDiagnostics:
    """Tests for parse_diagnose_test"""

    def test_all_tests_passed(self):
        """Test parsing when all diagnostic tests pass"""
        result = parse_diagnose_test(DIAGNOSTICS_HEALTHY_OUTPUT)

        assert result.status == HealthStatus.HEALTHY
        assert result.total_tests == 5
        assert result.passed_tests == 5
        assert result.failed_tests == 0

    def test_some_tests_failed(self):
        """Test parsing when some tests fail (including critical test)"""
        result = parse_diagnose_test(DIAGNOSTICS_FAILED_OUTPUT)

        # validate_network is a critical test, so status should be CRITICAL
        assert result.status == HealthStatus.CRITICAL
        assert result.failed_tests == 2
        assert result.passed_tests == 3

        # Check failed tests
        failed_tests = [t for t in result.tests if not t.passed]
        assert len(failed_tests) == 2
        assert any(t.name == "validate_network" for t in failed_tests)
        assert any(t.name == "dns_lookup" for t in failed_tests)

    def test_non_critical_tests_failed(self):
        """Test parsing when only non-critical tests fail"""
        result = parse_diagnose_test(DIAGNOSTICS_NON_CRITICAL_FAILED_OUTPUT)

        # Only dns_lookup failed which is not critical, so status should be DEGRADED
        assert result.status == HealthStatus.DEGRADED
        assert result.failed_tests == 1
        assert result.passed_tests == 4

    def test_critical_tests_failed(self):
        """Test parsing when critical tests fail"""
        result = parse_diagnose_test(DIAGNOSTICS_CRITICAL_FAILED_OUTPUT)

        assert result.status == HealthStatus.CRITICAL
        assert "validate_network" in result.message or "ntp_reachability" in result.message

    def test_empty_output(self):
        """Test parsing empty output"""
        result = parse_diagnose_test("")

        assert result.status == HealthStatus.UNKNOWN
        assert result.total_tests == 0


# ============================================================================
# Core Files Tests
# ============================================================================

class TestParseCoreFiles:
    """Tests for parse_core_active_list"""

    def test_no_core_files(self):
        """Test parsing when no core files found"""
        result = parse_core_active_list(CORE_FILES_NONE_OUTPUT)

        assert result.status == HealthStatus.HEALTHY
        assert result.core_count == 0
        assert len(result.core_files) == 0

    def test_some_core_files(self):
        """Test parsing when some core files found"""
        result = parse_core_active_list(CORE_FILES_SOME_OUTPUT)

        assert result.status == HealthStatus.DEGRADED
        assert result.core_count == 2
        assert len(result.core_files) == 2
        assert "core.12345.Cisco.CallManager.123456" in result.core_files

    def test_many_core_files(self):
        """Test parsing when many core files found"""
        result = parse_core_active_list(CORE_FILES_MANY_OUTPUT)

        assert result.status == HealthStatus.CRITICAL
        assert result.core_count == 4

    def test_empty_output(self):
        """Test parsing empty output - should default to healthy"""
        result = parse_core_active_list("")

        # Empty output with no "no core files" message should still be healthy
        # since no core files were detected
        assert result.core_count == 0


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and unusual inputs"""

    def test_ansi_codes_stripped(self):
        """Test that ANSI codes are stripped from all parsers"""
        output_with_ansi = "\x1b[32mNo core files found.\x1b[0m"
        result = parse_core_active_list(output_with_ansi)
        assert result.status == HealthStatus.HEALTHY

    def test_replication_single_node(self):
        """Test replication parsing for single node cluster"""
        output = """
DB Version: ccm15_0_1_12900_234
Repltimeout set to: 300s
No Errors or Mismatches found.
"""
        result = parse_dbreplication_runtimestate(output)
        assert result.status == HealthStatus.HEALTHY
        assert len(result.nodes) == 0  # No node table in single-node

    def test_services_with_not_activated(self):
        """Test services parsing with NOT ACTIVATED status"""
        output = """
  Cisco CallManager                    [STARTED]
  Cisco Extension Mobility             [NOT ACTIVATED]
  Cisco Tftp                           [STARTED]
"""
        result = parse_service_list(output)
        assert result.total_services == 3
        assert result.stopped_services == 1  # NOT ACTIVATED counts as not running


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
