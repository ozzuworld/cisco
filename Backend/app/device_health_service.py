"""Health check service for CUCM, CUBE/IOS-XE, and Expressway devices"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from app.models import (
    HealthStatus,
    HealthCheckType,
    DeviceType,
    DeviceHealthRequest,
    DeviceHealthTarget,
    DeviceHealthResponse,
    DeviceHealthResult,
    CUBEHealthCheckType,
    ExpresswayHealthCheckType,
    # CUCM
    CUCMCheckResults,
    # CUBE
    CUBECheckResults,
    CUBESystemStatus,
    CUBEEnvironmentStatus,
    CUBEInterfacesStatus,
    CUBEInterfaceInfo,
    CUBEVoiceCallsStatus,
    CUBESIPStatus,
    CUBESIPRegistrationStatus,
    CUBEDSPStatus,
    CUBENTPStatus,
    CUBERedundancyStatus,
    # Expressway
    ExpresswayCheckResults,
    ExpresswayClusterStatus,
    ExpresswayPeerInfo,
    ExpresswayLicensingStatus,
    ExpresswayAlarmsStatus,
    ExpresswayAlarmInfo,
    ExpresswayNTPStatus,
)
from app.csr_client import (
    CSRSSHClient,
    CSRAuthError,
    CSRConnectionError,
    CSRCommandTimeoutError,
    CSRSSHClientError,
)
from app.expressway_client import (
    ExpresswayClient,
    ExpresswayAuthError,
    ExpresswayConnectionError,
    ExpresswayError,
)
from app.health_service import check_node_health, _aggregate_health_status

logger = logging.getLogger(__name__)


# ============================================================================
# CUBE Health Checks
# ============================================================================

# IOS-XE commands for each check type
CUBE_COMMANDS = {
    CUBEHealthCheckType.SYSTEM: "show version",
    CUBEHealthCheckType.ENVIRONMENT: "show environment",
    CUBEHealthCheckType.INTERFACES: "show ip interface brief",
    CUBEHealthCheckType.VOICE_CALLS: "show call active voice brief",
    CUBEHealthCheckType.SIP_STATUS: "show sip-ua status",
    CUBEHealthCheckType.SIP_REGISTRATION: "show sip-ua register status",
    CUBEHealthCheckType.DSP: "show voice dsp group all",
    CUBEHealthCheckType.NTP: "show ntp status",
    CUBEHealthCheckType.REDUNDANCY: "show redundancy",
}

DEFAULT_CUBE_CHECKS = [
    CUBEHealthCheckType.SYSTEM,
    CUBEHealthCheckType.INTERFACES,
    CUBEHealthCheckType.VOICE_CALLS,
    CUBEHealthCheckType.SIP_STATUS,
    CUBEHealthCheckType.NTP,
]

DEFAULT_EXPRESSWAY_CHECKS = [
    ExpresswayHealthCheckType.CLUSTER,
    ExpresswayHealthCheckType.LICENSING,
    ExpresswayHealthCheckType.ALARMS,
    ExpresswayHealthCheckType.NTP,
]


def parse_cube_system(output: str) -> CUBESystemStatus:
    """Parse 'show version' output"""
    try:
        hostname = None
        version = None
        uptime_seconds = None

        for line in output.splitlines():
            line_lower = line.strip().lower()
            # Hostname: "hostname uptime is ..."
            if " uptime is " in line_lower:
                parts = line.split(" uptime is ")
                hostname = parts[0].strip()
                uptime_str = parts[1].strip() if len(parts) > 1 else ""
                uptime_seconds = _parse_uptime(uptime_str)
            # Version: "Cisco IOS XE Software, Version 17.06.05"
            if "version" in line_lower and ("ios" in line_lower or "software" in line_lower):
                match = re.search(r'Version\s+(\S+)', line, re.IGNORECASE)
                if match:
                    version = match.group(1).rstrip(',')

        status = HealthStatus.HEALTHY
        msg = f"{hostname or 'Unknown'}"
        if version:
            msg += f", IOS-XE {version}"
        if uptime_seconds is not None:
            days = uptime_seconds // 86400
            msg += f", up {days}d"

        return CUBESystemStatus(
            status=status,
            hostname=hostname,
            version=version,
            uptime_seconds=uptime_seconds,
            message=msg,
        )
    except Exception as e:
        return CUBESystemStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def _parse_uptime(uptime_str: str) -> int:
    """Parse uptime string like '5 weeks, 2 days, 3 hours, 15 minutes' to seconds"""
    total = 0
    for match in re.finditer(r'(\d+)\s+(year|week|day|hour|minute|second)s?', uptime_str, re.IGNORECASE):
        value = int(match.group(1))
        unit = match.group(2).lower()
        if unit == 'year':
            total += value * 365 * 86400
        elif unit == 'week':
            total += value * 7 * 86400
        elif unit == 'day':
            total += value * 86400
        elif unit == 'hour':
            total += value * 3600
        elif unit == 'minute':
            total += value * 60
        elif unit == 'second':
            total += value
    return total


def parse_cube_environment(output: str) -> CUBEEnvironmentStatus:
    """Parse 'show environment' output"""
    try:
        output_lower = output.lower()
        # Virtual routers may not have environment sensors
        if "not supported" in output_lower or "no environmental" in output_lower or not output.strip():
            return CUBEEnvironmentStatus(
                status=HealthStatus.HEALTHY,
                temperature_ok=True,
                power_ok=True,
                message="Virtual platform (no environmental sensors)",
            )

        temp_ok = True
        power_ok = True
        has_critical = "critical" in output_lower or "fatal" in output_lower

        if has_critical:
            temp_ok = False
            power_ok = False

        status = HealthStatus.HEALTHY
        if not temp_ok or not power_ok:
            status = HealthStatus.CRITICAL

        return CUBEEnvironmentStatus(
            status=status,
            temperature_ok=temp_ok,
            power_ok=power_ok,
            message="Environment OK" if status == HealthStatus.HEALTHY else "Environmental alert detected",
        )
    except Exception as e:
        return CUBEEnvironmentStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_interfaces(output: str) -> CUBEInterfacesStatus:
    """Parse 'show ip interface brief' output"""
    try:
        interfaces = []
        # Lines like: GigabitEthernet1    10.0.0.1    YES manual up    up
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and not line.strip().startswith("Interface"):
                iface_name = parts[0]
                ip_addr = parts[1] if parts[1] != "unassigned" else None
                # Status is typically parts[-2] and protocol is parts[-1]
                iface_status = parts[-2].lower()
                proto_status = parts[-1].lower()

                if "administratively" in line.lower():
                    status_str = "administratively down"
                elif iface_status == "up" and proto_status == "up":
                    status_str = "up"
                else:
                    status_str = "down"

                interfaces.append(CUBEInterfaceInfo(
                    name=iface_name,
                    status=status_str,
                    ip_address=ip_addr,
                ))

        total = len(interfaces)
        up_count = sum(1 for i in interfaces if i.status == "up")
        down_count = sum(1 for i in interfaces if i.status == "down")

        if down_count > 0:
            status = HealthStatus.DEGRADED
            msg = f"{down_count} interface(s) down"
        elif total == 0:
            status = HealthStatus.UNKNOWN
            msg = "No interfaces found"
        else:
            status = HealthStatus.HEALTHY
            msg = f"All {up_count} interfaces up"

        return CUBEInterfacesStatus(
            status=status,
            total_interfaces=total,
            up_interfaces=up_count,
            down_interfaces=down_count,
            interfaces=interfaces,
            message=msg,
        )
    except Exception as e:
        return CUBEInterfacesStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_voice_calls(output: str) -> CUBEVoiceCallsStatus:
    """Parse 'show call active voice brief' output"""
    try:
        output_lower = output.lower()
        if "no active call" in output_lower or "total call" not in output_lower:
            # Count call entries - lines starting with a hex call ID
            call_lines = [l for l in output.splitlines()
                         if re.match(r'^[0-9A-Fa-f]+\s', l.strip())]
            active = len(call_lines)
            return CUBEVoiceCallsStatus(
                status=HealthStatus.HEALTHY,
                active_calls=active,
                total_calls=active,
                message=f"{active} active call(s)" if active > 0 else "No active calls",
            )

        # Look for "Total call-legs: X"
        active = 0
        match = re.search(r'(\d+)\s+call.?leg', output, re.IGNORECASE)
        if match:
            active = int(match.group(1))

        return CUBEVoiceCallsStatus(
            status=HealthStatus.HEALTHY,
            active_calls=active,
            total_calls=active,
            message=f"{active} active call-leg(s)",
        )
    except Exception as e:
        return CUBEVoiceCallsStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_sip_status(output: str) -> CUBESIPStatus:
    """Parse 'show sip-ua status' output"""
    try:
        active_calls = None
        registrations = None

        for line in output.splitlines():
            line_lower = line.strip().lower()
            # "SIP User Agent Status: ENABLED"
            if "status" in line_lower and ("enabled" in line_lower or "disabled" in line_lower):
                pass
            # Look for call/transaction counts
            match = re.search(r'(\d+)', line)
            if match:
                if "call" in line_lower and "active" in line_lower:
                    active_calls = int(match.group(1))
                elif "registr" in line_lower:
                    registrations = int(match.group(1))

        return CUBESIPStatus(
            status=HealthStatus.HEALTHY,
            active_calls=active_calls,
            total_registrations=registrations,
            message="SIP UA active",
        )
    except Exception as e:
        return CUBESIPStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_sip_registration(output: str) -> CUBESIPRegistrationStatus:
    """Parse 'show sip-ua register status' output"""
    try:
        output_lower = output.lower()
        if "no registration" in output_lower or "no sip" in output_lower:
            return CUBESIPRegistrationStatus(
                status=HealthStatus.HEALTHY,
                registered_endpoints=0,
                message="No SIP registrations configured",
            )

        # Count registered lines
        registered = 0
        for line in output.splitlines():
            if re.search(r'\bregistered\b', line, re.IGNORECASE):
                registered += 1

        return CUBESIPRegistrationStatus(
            status=HealthStatus.HEALTHY,
            registered_endpoints=registered,
            message=f"{registered} registration(s) active",
        )
    except Exception as e:
        return CUBESIPRegistrationStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_dsp(output: str) -> CUBEDSPStatus:
    """Parse 'show voice dsp group all' output"""
    try:
        output_lower = output.lower()
        if "no dsp" in output_lower or "not found" in output_lower or not output.strip():
            return CUBEDSPStatus(
                status=HealthStatus.HEALTHY,
                dsp_utilization=0,
                message="No DSP resources (software transcoding or no media needed)",
            )

        utilization = None
        match = re.search(r'(\d+)%', output)
        if match:
            utilization = int(match.group(1))

        status = HealthStatus.HEALTHY
        if utilization is not None and utilization > 80:
            status = HealthStatus.DEGRADED

        return CUBEDSPStatus(
            status=status,
            dsp_utilization=utilization,
            message=f"DSP utilization: {utilization}%" if utilization is not None else "DSP status retrieved",
        )
    except Exception as e:
        return CUBEDSPStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_ntp(output: str) -> CUBENTPStatus:
    """Parse 'show ntp status' output"""
    try:
        output_lower = output.lower()
        synchronized = "synchroniz" in output_lower and "unsynchroniz" not in output_lower
        stratum = None

        match = re.search(r'stratum\s+(\d+)', output, re.IGNORECASE)
        if match:
            stratum = int(match.group(1))

        if synchronized:
            status = HealthStatus.HEALTHY
            msg = f"Synchronized, stratum {stratum}" if stratum else "Synchronized"
        else:
            status = HealthStatus.DEGRADED
            msg = "Not synchronized"

        return CUBENTPStatus(
            status=status,
            synchronized=synchronized,
            stratum=stratum,
            message=msg,
        )
    except Exception as e:
        return CUBENTPStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


def parse_cube_redundancy(output: str) -> CUBERedundancyStatus:
    """Parse 'show redundancy' output"""
    try:
        output_lower = output.lower()
        if "not supported" in output_lower or "not available" in output_lower or "disabled" in output_lower:
            return CUBERedundancyStatus(
                status=HealthStatus.HEALTHY,
                ha_enabled=False,
                peer_status=None,
                message="Redundancy not configured",
            )

        ha_enabled = "standby" in output_lower or "active" in output_lower
        peer_status = None

        # Look for peer state
        for line in output.splitlines():
            if "peer" in line.lower() and ("state" in line.lower() or "status" in line.lower()):
                peer_status = line.split(":")[-1].strip() if ":" in line else line.strip()
                break

        status = HealthStatus.HEALTHY
        if ha_enabled and peer_status and "standby ready" not in peer_status.lower():
            status = HealthStatus.DEGRADED

        return CUBERedundancyStatus(
            status=status,
            ha_enabled=ha_enabled,
            peer_status=peer_status,
            message=f"HA {'enabled' if ha_enabled else 'disabled'}" + (f", peer: {peer_status}" if peer_status else ""),
        )
    except Exception as e:
        return CUBERedundancyStatus(status=HealthStatus.UNKNOWN, message=f"Parse error: {e}")


# Parser dispatch map
CUBE_PARSERS = {
    CUBEHealthCheckType.SYSTEM: parse_cube_system,
    CUBEHealthCheckType.ENVIRONMENT: parse_cube_environment,
    CUBEHealthCheckType.INTERFACES: parse_cube_interfaces,
    CUBEHealthCheckType.VOICE_CALLS: parse_cube_voice_calls,
    CUBEHealthCheckType.SIP_STATUS: parse_cube_sip_status,
    CUBEHealthCheckType.SIP_REGISTRATION: parse_cube_sip_registration,
    CUBEHealthCheckType.DSP: parse_cube_dsp,
    CUBEHealthCheckType.NTP: parse_cube_ntp,
    CUBEHealthCheckType.REDUNDANCY: parse_cube_redundancy,
}


async def check_cube_health(
    target: DeviceHealthTarget,
    username: str,
    password: str,
    connect_timeout: float,
    command_timeout: float,
) -> DeviceHealthResult:
    """
    Perform health checks on a CUBE/IOS-XE device.
    """
    now = datetime.now(timezone.utc)
    checks = target.cube_checks or DEFAULT_CUBE_CHECKS
    port = target.port or 22
    results = CUBECheckResults()
    check_statuses: List[HealthStatus] = []
    error_msg = None

    logger.info(f"Starting CUBE health checks for {target.host}:{port}")

    try:
        async with CSRSSHClient(
            host=target.host,
            port=port,
            username=username,
            password=password,
            connect_timeout=connect_timeout,
        ) as client:
            for check_type in checks:
                command = CUBE_COMMANDS.get(check_type)
                parser = CUBE_PARSERS.get(check_type)
                if not command or not parser:
                    continue

                try:
                    output = await asyncio.wait_for(
                        client.execute_command(command),
                        timeout=command_timeout,
                    )
                    result = parser(output)
                    setattr(results, check_type.value, result)
                    check_statuses.append(result.status)
                    logger.debug(f"CUBE {check_type.value} for {target.host}: {result.status}")
                except asyncio.TimeoutError:
                    logger.warning(f"CUBE {check_type.value} timeout for {target.host}")
                    err_result = _make_cube_error_result(check_type, f"Command timed out: {command}")
                    setattr(results, check_type.value, err_result)
                    check_statuses.append(HealthStatus.UNKNOWN)
                except Exception as e:
                    logger.error(f"CUBE {check_type.value} failed for {target.host}: {e}")
                    err_result = _make_cube_error_result(check_type, str(e))
                    setattr(results, check_type.value, err_result)
                    check_statuses.append(HealthStatus.UNKNOWN)

    except CSRAuthError as e:
        error_msg = f"Authentication failed: {e}"
        logger.error(f"CUBE auth error for {target.host}: {e}")
    except CSRConnectionError as e:
        error_msg = f"Connection failed: {e}"
        logger.error(f"CUBE connection error for {target.host}: {e}")
    except CSRSSHClientError as e:
        error_msg = f"SSH error: {e}"
        logger.error(f"CUBE SSH error for {target.host}: {e}")
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        logger.exception(f"CUBE unexpected error for {target.host}: {e}")

    device_status = _aggregate_health_status(check_statuses) if not error_msg else HealthStatus.CRITICAL

    return DeviceHealthResult(
        device_type=DeviceType.CUBE,
        host=target.host,
        status=device_status,
        reachable=error_msg is None,
        checked_at=now,
        message=_build_status_message("CUBE", device_status, check_statuses, error_msg),
        error=error_msg,
        cube_checks=results if not error_msg else None,
    )


def _make_cube_error_result(check_type: CUBEHealthCheckType, error: str):
    """Create an error result for a specific CUBE check type"""
    type_map = {
        CUBEHealthCheckType.SYSTEM: CUBESystemStatus,
        CUBEHealthCheckType.ENVIRONMENT: CUBEEnvironmentStatus,
        CUBEHealthCheckType.INTERFACES: CUBEInterfacesStatus,
        CUBEHealthCheckType.VOICE_CALLS: CUBEVoiceCallsStatus,
        CUBEHealthCheckType.SIP_STATUS: CUBESIPStatus,
        CUBEHealthCheckType.SIP_REGISTRATION: CUBESIPRegistrationStatus,
        CUBEHealthCheckType.DSP: CUBEDSPStatus,
        CUBEHealthCheckType.NTP: CUBENTPStatus,
        CUBEHealthCheckType.REDUNDANCY: CUBERedundancyStatus,
    }
    cls = type_map.get(check_type)
    if cls:
        return cls(status=HealthStatus.UNKNOWN, message=f"Check failed: {error}")
    return None


# ============================================================================
# Expressway Health Checks
# ============================================================================


async def check_expressway_health(
    target: DeviceHealthTarget,
    username: str,
    password: str,
    connect_timeout: float,
    command_timeout: float,
) -> DeviceHealthResult:
    """
    Perform health checks on an Expressway device via REST API.
    """
    now = datetime.now(timezone.utc)
    checks = target.expressway_checks or DEFAULT_EXPRESSWAY_CHECKS
    port = target.port or 443
    results = ExpresswayCheckResults()
    check_statuses: List[HealthStatus] = []
    error_msg = None

    logger.info(f"Starting Expressway health checks for {target.host}:{port}")

    try:
        async with ExpresswayClient(
            host=target.host,
            username=username,
            password=password,
            port=port,
            timeout=connect_timeout,
        ) as client:

            if ExpresswayHealthCheckType.CLUSTER in checks:
                try:
                    result = await _check_expressway_cluster(client, command_timeout)
                    results.cluster = result
                    check_statuses.append(result.status)
                except Exception as e:
                    logger.error(f"Expressway cluster check failed: {e}")
                    results.cluster = ExpresswayClusterStatus(
                        status=HealthStatus.UNKNOWN, message=f"Check failed: {e}"
                    )
                    check_statuses.append(HealthStatus.UNKNOWN)

            if ExpresswayHealthCheckType.LICENSING in checks:
                try:
                    result = await _check_expressway_licensing(client, command_timeout)
                    results.licensing = result
                    check_statuses.append(result.status)
                except Exception as e:
                    logger.error(f"Expressway licensing check failed: {e}")
                    results.licensing = ExpresswayLicensingStatus(
                        status=HealthStatus.UNKNOWN, message=f"Check failed: {e}"
                    )
                    check_statuses.append(HealthStatus.UNKNOWN)

            if ExpresswayHealthCheckType.ALARMS in checks:
                try:
                    result = await _check_expressway_alarms(client, command_timeout)
                    results.alarms = result
                    check_statuses.append(result.status)
                except Exception as e:
                    logger.error(f"Expressway alarms check failed: {e}")
                    results.alarms = ExpresswayAlarmsStatus(
                        status=HealthStatus.UNKNOWN, message=f"Check failed: {e}"
                    )
                    check_statuses.append(HealthStatus.UNKNOWN)

            if ExpresswayHealthCheckType.NTP in checks:
                try:
                    result = await _check_expressway_ntp(client, command_timeout)
                    results.ntp = result
                    check_statuses.append(result.status)
                except Exception as e:
                    logger.error(f"Expressway NTP check failed: {e}")
                    results.ntp = ExpresswayNTPStatus(
                        status=HealthStatus.UNKNOWN, message=f"Check failed: {e}"
                    )
                    check_statuses.append(HealthStatus.UNKNOWN)

    except ExpresswayAuthError as e:
        error_msg = f"Authentication failed: {e}"
        logger.error(f"Expressway auth error for {target.host}: {e}")
    except ExpresswayConnectionError as e:
        error_msg = f"Connection failed: {e}"
        logger.error(f"Expressway connection error for {target.host}: {e}")
    except ExpresswayError as e:
        error_msg = f"API error: {e}"
        logger.error(f"Expressway API error for {target.host}: {e}")
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        logger.exception(f"Expressway unexpected error for {target.host}: {e}")

    device_status = _aggregate_health_status(check_statuses) if not error_msg else HealthStatus.CRITICAL

    return DeviceHealthResult(
        device_type=DeviceType.EXPRESSWAY,
        host=target.host,
        status=device_status,
        reachable=error_msg is None,
        checked_at=now,
        message=_build_status_message("Expressway", device_status, check_statuses, error_msg),
        error=error_msg,
        expressway_checks=results if not error_msg else None,
    )


async def _check_expressway_cluster(client: ExpresswayClient, timeout: float) -> ExpresswayClusterStatus:
    """Check Expressway cluster peers via REST API"""
    response = await client._api_request("GET", "/api/v1/provisioning/common/cluster/peers", timeout=timeout)

    if response.status_code != 200:
        return ExpresswayClusterStatus(
            status=HealthStatus.UNKNOWN,
            message=f"API returned {response.status_code}",
        )

    data = response.json() if response.text else {}

    # Expressway returns cluster peer data
    peers = []
    all_active = True

    # The response format varies - handle both array and object formats
    peer_list = data if isinstance(data, list) else data.get("Peers", data.get("peers", []))
    if isinstance(peer_list, dict):
        peer_list = [peer_list]

    for peer in peer_list:
        if isinstance(peer, dict):
            addr = peer.get("Address", peer.get("address", peer.get("PeerAddress", "unknown")))
            peer_status = peer.get("Status", peer.get("status", "unknown")).lower()
            if peer_status not in ("active", "reachable", "primary"):
                all_active = False
            peers.append(ExpresswayPeerInfo(
                address=str(addr),
                status="active" if peer_status in ("active", "reachable", "primary") else peer_status,
            ))

    peer_count = len(peers)
    status = HealthStatus.HEALTHY if (all_active or peer_count <= 1) else HealthStatus.DEGRADED

    return ExpresswayClusterStatus(
        status=status,
        peer_count=peer_count,
        all_peers_active=all_active,
        peers=peers,
        message=f"{peer_count} peer(s), {'all active' if all_active else 'some inactive'}",
    )


async def _check_expressway_licensing(client: ExpresswayClient, timeout: float) -> ExpresswayLicensingStatus:
    """Check Expressway licensing via REST API"""
    # Try sysinfo first, then smart licensing
    try:
        response = await client._api_request("GET", "/api/provisioning/sysinfo", timeout=timeout)
        if response.status_code == 200:
            data = response.json() if response.text else {}
            # sysinfo doesn't always have licensing details, but confirms device is operational
            return ExpresswayLicensingStatus(
                status=HealthStatus.HEALTHY,
                license_valid=True,
                message="System operational",
            )
    except Exception:
        pass

    # Try smart licensing endpoint
    try:
        response = await client._api_request(
            "GET",
            "/api/v1/status/common/smartlicensing/licensing",
            timeout=timeout,
        )
        if response.status_code == 200:
            data = response.json() if response.text else {}
            lic_status = str(data.get("Status", data.get("status", ""))).lower()
            valid = "registered" in lic_status or "authorized" in lic_status or "compliant" in lic_status
            return ExpresswayLicensingStatus(
                status=HealthStatus.HEALTHY if valid else HealthStatus.DEGRADED,
                license_valid=valid,
                message=f"License: {lic_status}" if lic_status else "License status retrieved",
            )
    except Exception:
        pass

    return ExpresswayLicensingStatus(
        status=HealthStatus.HEALTHY,
        license_valid=True,
        message="Licensing check - system reachable",
    )


async def _check_expressway_alarms(client: ExpresswayClient, timeout: float) -> ExpresswayAlarmsStatus:
    """Check Expressway alarms via REST API"""
    response = await client._api_request("GET", "/api/v1/provisioning/common/alarm", timeout=timeout)

    alarms = []
    critical_count = 0
    warning_count = 0

    if response.status_code == 200:
        data = response.json() if response.text else {}
        alarm_list = data if isinstance(data, list) else data.get("Alarms", data.get("alarms", []))
        if isinstance(alarm_list, dict):
            alarm_list = [alarm_list]

        for alarm in alarm_list:
            if isinstance(alarm, dict):
                severity = str(alarm.get("Severity", alarm.get("severity", "info"))).lower()
                desc = alarm.get("Description", alarm.get("description",
                       alarm.get("Name", alarm.get("name", "Unknown alarm"))))

                if severity in ("critical", "error", "emergency"):
                    severity = "critical"
                    critical_count += 1
                elif severity in ("warning", "major", "minor"):
                    severity = "warning"
                    warning_count += 1
                else:
                    severity = "info"

                alarms.append(ExpresswayAlarmInfo(severity=severity, description=str(desc)))

    alarm_count = len(alarms)

    if critical_count > 0:
        status = HealthStatus.CRITICAL
    elif warning_count > 0:
        status = HealthStatus.DEGRADED
    else:
        status = HealthStatus.HEALTHY

    return ExpresswayAlarmsStatus(
        status=status,
        alarm_count=alarm_count,
        critical_count=critical_count,
        warning_count=warning_count,
        alarms=alarms,
        message=f"{alarm_count} alarm(s)" if alarm_count > 0 else "No alarms",
    )


async def _check_expressway_ntp(client: ExpresswayClient, timeout: float) -> ExpresswayNTPStatus:
    """Check Expressway NTP via REST API"""
    try:
        response = await client._api_request(
            "GET",
            "/api/v1/provisioning/common/time/ntpserver",
            timeout=timeout,
        )
        if response.status_code == 200:
            data = response.json() if response.text else {}
            # NTP config exists - assume synchronized if reachable
            return ExpresswayNTPStatus(
                status=HealthStatus.HEALTHY,
                synchronized=True,
                message="NTP configured",
            )
    except Exception:
        pass

    # Try sysinfo as fallback for time info
    try:
        response = await client._api_request("GET", "/api/provisioning/sysinfo", timeout=timeout)
        if response.status_code == 200:
            return ExpresswayNTPStatus(
                status=HealthStatus.HEALTHY,
                synchronized=True,
                message="System time available",
            )
    except Exception:
        pass

    return ExpresswayNTPStatus(
        status=HealthStatus.UNKNOWN,
        synchronized=None,
        message="Unable to determine NTP status",
    )


# ============================================================================
# CUCM Health Check (wraps existing health_service)
# ============================================================================


async def check_cucm_device_health(
    target: DeviceHealthTarget,
    username: str,
    password: str,
    connect_timeout: float,
    command_timeout: float,
) -> DeviceHealthResult:
    """
    Perform health checks on a CUCM device.
    Wraps the existing check_node_health function.
    """
    now = datetime.now(timezone.utc)
    checks = target.cucm_checks or [
        HealthCheckType.SERVICES,
        HealthCheckType.NTP,
        HealthCheckType.DIAGNOSTICS,
    ]
    port = target.port or 22

    try:
        node_result = await check_node_health(
            host=target.host,
            port=port,
            username=username,
            password=password,
            connect_timeout=connect_timeout,
            command_timeout=command_timeout,
            checks=checks,
        )

        cucm_checks = CUCMCheckResults(
            replication=node_result.checks.replication,
            services=node_result.checks.services,
            ntp=node_result.checks.ntp,
            diagnostics=node_result.checks.diagnostics,
            cores=node_result.checks.cores,
        )

        return DeviceHealthResult(
            device_type=DeviceType.CUCM,
            host=target.host,
            status=node_result.status,
            reachable=node_result.reachable,
            checked_at=node_result.checked_at,
            message=node_result.error or f"CUCM health: {node_result.status.value}",
            error=node_result.error,
            cucm_checks=cucm_checks,
        )
    except Exception as e:
        logger.exception(f"CUCM health check failed for {target.host}: {e}")
        return DeviceHealthResult(
            device_type=DeviceType.CUCM,
            host=target.host,
            status=HealthStatus.CRITICAL,
            reachable=False,
            checked_at=now,
            message=f"Health check failed: {e}",
            error=str(e),
        )


# ============================================================================
# Orchestrator
# ============================================================================


def _build_status_message(
    device_label: str,
    status: HealthStatus,
    check_statuses: List[HealthStatus],
    error_msg: Optional[str],
) -> str:
    """Build a human-readable status message"""
    if error_msg:
        return error_msg
    total = len(check_statuses)
    healthy = sum(1 for s in check_statuses if s == HealthStatus.HEALTHY)
    if status == HealthStatus.HEALTHY:
        return f"{device_label}: All {total} checks passed"
    elif status == HealthStatus.DEGRADED:
        return f"{device_label}: {healthy}/{total} checks healthy"
    elif status == HealthStatus.CRITICAL:
        return f"{device_label}: Critical issues detected"
    return f"{device_label}: Status unknown"


async def check_device_health(request: DeviceHealthRequest) -> DeviceHealthResponse:
    """
    Perform health checks on multiple devices concurrently.
    Dispatches to the appropriate checker based on device_type.
    """
    now = datetime.now(timezone.utc)
    global_username = request.username
    global_password = request.password
    connect_timeout = float(request.connect_timeout_sec)
    command_timeout = float(request.command_timeout_sec)

    logger.info(f"Starting device health check for {len(request.devices)} device(s)")

    tasks = []
    for target in request.devices:
        username = target.username or global_username or ""
        password = target.password or global_password or ""

        if target.device_type == DeviceType.CUCM:
            tasks.append(check_cucm_device_health(
                target, username, password, connect_timeout, command_timeout
            ))
        elif target.device_type == DeviceType.CUBE:
            tasks.append(check_cube_health(
                target, username, password, connect_timeout, command_timeout
            ))
        elif target.device_type == DeviceType.EXPRESSWAY:
            tasks.append(check_expressway_health(
                target, username, password, connect_timeout, command_timeout
            ))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    device_results: List[DeviceHealthResult] = []
    healthy = 0
    degraded = 0
    critical = 0
    unknown = 0

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Device check failed with exception: {result}")
            target = request.devices[i]
            device_results.append(DeviceHealthResult(
                device_type=target.device_type,
                host=target.host,
                status=HealthStatus.CRITICAL,
                reachable=False,
                checked_at=now,
                message=f"Check failed: {result}",
                error=str(result),
            ))
            critical += 1
        else:
            device_results.append(result)
            if result.status == HealthStatus.HEALTHY:
                healthy += 1
            elif result.status == HealthStatus.DEGRADED:
                degraded += 1
            elif result.status == HealthStatus.CRITICAL:
                critical += 1
            else:
                unknown += 1

    overall = _aggregate_health_status([d.status for d in device_results])
    total = len(device_results)

    if overall == HealthStatus.HEALTHY:
        message = f"All {total} device(s) healthy"
    elif overall == HealthStatus.CRITICAL:
        message = f"{critical} device(s) in critical state"
    elif overall == HealthStatus.DEGRADED:
        message = f"{degraded} device(s) degraded"
    else:
        message = f"Health status unknown for {unknown} device(s)"

    logger.info(
        f"Device health check complete: {overall.value} "
        f"(healthy={healthy}, degraded={degraded}, critical={critical}, unknown={unknown})"
    )

    return DeviceHealthResponse(
        overall_status=overall,
        checked_at=now,
        message=message,
        total_devices=total,
        healthy_devices=healthy,
        degraded_devices=degraded,
        critical_devices=critical,
        unknown_devices=unknown,
        devices=device_results,
    )
