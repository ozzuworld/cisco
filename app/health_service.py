"""Health check service for CUCM clusters"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict

from app.models import (
    ClusterHealthRequest,
    ClusterHealthResponse,
    NodeHealthStatus,
    NodeHealthChecks,
    HealthStatus,
    HealthCheckType,
    ReplicationStatus,
    ServicesStatus,
    NTPStatus,
    DiagnosticsStatus,
    CoreFilesStatus,
)
from app.ssh_client import (
    CUCMSSHClient,
    CUCMAuthError,
    CUCMConnectionError,
    CUCMCommandTimeoutError,
    CUCMSSHClientError,
)
from app.parsers import (
    parse_show_network_cluster,
    parse_dbreplication_runtimestate,
    parse_service_list,
    parse_ntp_status,
    parse_diagnose_test,
    parse_core_active_list,
)


logger = logging.getLogger(__name__)


# Health check commands
HEALTH_COMMANDS = {
    HealthCheckType.REPLICATION: "utils dbreplication runtimestate",
    HealthCheckType.SERVICES: "utils service list",
    HealthCheckType.NTP: "utils ntp status",
    HealthCheckType.DIAGNOSTICS: "utils diagnose test",
    HealthCheckType.CORES: "utils core active list",
}


async def run_health_command(
    client: CUCMSSHClient,
    command: str,
    timeout: float
) -> str:
    """
    Execute a health check command on a CUCM node.

    Args:
        client: Connected SSH client
        command: Command to execute
        timeout: Command timeout in seconds

    Returns:
        Raw command output
    """
    try:
        output = await asyncio.wait_for(
            client.execute_command(command),
            timeout=timeout
        )
        return output
    except asyncio.TimeoutError:
        raise CUCMCommandTimeoutError(f"Command timed out after {timeout}s: {command}")


async def check_node_health(
    host: str,
    port: int,
    username: str,
    password: str,
    connect_timeout: float,
    command_timeout: float,
    checks: List[HealthCheckType],
    hostname: Optional[str] = None,
    role: Optional[str] = None,
) -> NodeHealthStatus:
    """
    Perform health checks on a single CUCM node.

    Args:
        host: Node IP or hostname
        port: SSH port
        username: SSH username
        password: SSH password
        connect_timeout: Connection timeout in seconds
        command_timeout: Command timeout in seconds
        checks: List of health checks to perform
        hostname: Optional known hostname
        role: Optional known role (Publisher/Subscriber)

    Returns:
        NodeHealthStatus with all check results
    """
    now = datetime.now(timezone.utc)
    health_checks = NodeHealthChecks()
    node_status = HealthStatus.UNKNOWN
    error_msg = None

    logger.info(f"Starting health checks for node {host}")

    try:
        async with CUCMSSHClient(
            host=host,
            port=port,
            username=username,
            password=password,
            connect_timeout=connect_timeout,
        ) as client:
            # Run each requested check
            check_statuses: List[HealthStatus] = []

            # Replication check (usually run from publisher only, but we include it)
            if HealthCheckType.REPLICATION in checks:
                try:
                    output = await run_health_command(
                        client,
                        HEALTH_COMMANDS[HealthCheckType.REPLICATION],
                        command_timeout
                    )
                    health_checks.replication = parse_dbreplication_runtimestate(output)
                    check_statuses.append(health_checks.replication.status)
                    logger.debug(f"Replication check for {host}: {health_checks.replication.status}")
                except CUCMCommandTimeoutError as e:
                    logger.warning(f"Replication check timeout for {host}: {e}")
                    health_checks.replication = ReplicationStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Command timeout: {e}"
                    )
                except Exception as e:
                    logger.error(f"Replication check failed for {host}: {e}")
                    health_checks.replication = ReplicationStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Check failed: {e}"
                    )

            # Services check
            if HealthCheckType.SERVICES in checks:
                try:
                    output = await run_health_command(
                        client,
                        HEALTH_COMMANDS[HealthCheckType.SERVICES],
                        command_timeout
                    )
                    health_checks.services = parse_service_list(output)
                    check_statuses.append(health_checks.services.status)
                    logger.debug(f"Services check for {host}: {health_checks.services.status}")
                except CUCMCommandTimeoutError as e:
                    logger.warning(f"Services check timeout for {host}: {e}")
                    health_checks.services = ServicesStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Command timeout: {e}"
                    )
                except Exception as e:
                    logger.error(f"Services check failed for {host}: {e}")
                    health_checks.services = ServicesStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Check failed: {e}"
                    )

            # NTP check
            if HealthCheckType.NTP in checks:
                try:
                    output = await run_health_command(
                        client,
                        HEALTH_COMMANDS[HealthCheckType.NTP],
                        command_timeout
                    )
                    health_checks.ntp = parse_ntp_status(output)
                    check_statuses.append(health_checks.ntp.status)
                    logger.debug(f"NTP check for {host}: {health_checks.ntp.status}")
                except CUCMCommandTimeoutError as e:
                    logger.warning(f"NTP check timeout for {host}: {e}")
                    health_checks.ntp = NTPStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Command timeout: {e}"
                    )
                except Exception as e:
                    logger.error(f"NTP check failed for {host}: {e}")
                    health_checks.ntp = NTPStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Check failed: {e}"
                    )

            # Diagnostics check
            if HealthCheckType.DIAGNOSTICS in checks:
                try:
                    output = await run_health_command(
                        client,
                        HEALTH_COMMANDS[HealthCheckType.DIAGNOSTICS],
                        command_timeout
                    )
                    health_checks.diagnostics = parse_diagnose_test(output)
                    check_statuses.append(health_checks.diagnostics.status)
                    logger.debug(f"Diagnostics check for {host}: {health_checks.diagnostics.status}")
                except CUCMCommandTimeoutError as e:
                    logger.warning(f"Diagnostics check timeout for {host}: {e}")
                    health_checks.diagnostics = DiagnosticsStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Command timeout: {e}"
                    )
                except Exception as e:
                    logger.error(f"Diagnostics check failed for {host}: {e}")
                    health_checks.diagnostics = DiagnosticsStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Check failed: {e}"
                    )

            # Core files check
            if HealthCheckType.CORES in checks:
                try:
                    output = await run_health_command(
                        client,
                        HEALTH_COMMANDS[HealthCheckType.CORES],
                        command_timeout
                    )
                    health_checks.cores = parse_core_active_list(output)
                    check_statuses.append(health_checks.cores.status)
                    logger.debug(f"Core files check for {host}: {health_checks.cores.status}")
                except CUCMCommandTimeoutError as e:
                    logger.warning(f"Core files check timeout for {host}: {e}")
                    health_checks.cores = CoreFilesStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Command timeout: {e}"
                    )
                except Exception as e:
                    logger.error(f"Core files check failed for {host}: {e}")
                    health_checks.cores = CoreFilesStatus(
                        status=HealthStatus.UNKNOWN,
                        checked_at=now,
                        message=f"Check failed: {e}"
                    )

            # Determine overall node status
            node_status = _aggregate_health_status(check_statuses)

    except CUCMAuthError as e:
        logger.error(f"Authentication failed for {host}: {e}")
        error_msg = f"Authentication failed: {e}"
        node_status = HealthStatus.CRITICAL

    except CUCMConnectionError as e:
        logger.error(f"Connection failed for {host}: {e}")
        error_msg = f"Connection failed: {e}"
        node_status = HealthStatus.CRITICAL

    except CUCMCommandTimeoutError as e:
        logger.error(f"Command timeout for {host}: {e}")
        error_msg = f"Command timeout: {e}"
        node_status = HealthStatus.UNKNOWN

    except CUCMSSHClientError as e:
        logger.error(f"SSH client error for {host}: {e}")
        error_msg = f"SSH error: {e}"
        node_status = HealthStatus.CRITICAL

    except Exception as e:
        logger.exception(f"Unexpected error checking health for {host}: {e}")
        error_msg = f"Unexpected error: {e}"
        node_status = HealthStatus.UNKNOWN

    return NodeHealthStatus(
        ip=host,
        hostname=hostname,
        role=role,
        status=node_status,
        reachable=error_msg is None,
        error=error_msg,
        checks=health_checks,
        checked_at=datetime.now(timezone.utc),
    )


def _aggregate_health_status(statuses: List[HealthStatus]) -> HealthStatus:
    """
    Aggregate multiple health statuses into a single status.

    Priority: CRITICAL > DEGRADED > UNKNOWN > HEALTHY

    Args:
        statuses: List of health statuses

    Returns:
        Aggregated health status
    """
    if not statuses:
        return HealthStatus.UNKNOWN

    if HealthStatus.CRITICAL in statuses:
        return HealthStatus.CRITICAL
    elif HealthStatus.DEGRADED in statuses:
        return HealthStatus.DEGRADED
    elif HealthStatus.UNKNOWN in statuses:
        return HealthStatus.UNKNOWN
    else:
        return HealthStatus.HEALTHY


async def check_cluster_health(request: ClusterHealthRequest) -> ClusterHealthResponse:
    """
    Perform health checks on a CUCM cluster.

    Args:
        request: Cluster health check request

    Returns:
        ClusterHealthResponse with health status for all nodes
    """
    now = datetime.now(timezone.utc)
    nodes_to_check: List[Dict] = []

    logger.info(
        f"Starting cluster health check for {request.publisher_host} "
        f"with checks: {[c.value for c in request.checks]}"
    )

    # If nodes list provided, use it directly
    if request.nodes:
        for node_ip in request.nodes:
            nodes_to_check.append({
                "ip": node_ip,
                "hostname": None,
                "role": None,
            })
    else:
        # Discover nodes from publisher
        try:
            from app.ssh_client import run_show_network_cluster

            raw_output = await run_show_network_cluster(
                host=request.publisher_host,
                port=request.port,
                username=request.username,
                password=request.password,
                connect_timeout=float(request.connect_timeout_sec),
                command_timeout=float(request.command_timeout_sec)
            )

            discovered_nodes = parse_show_network_cluster(raw_output)
            for node in discovered_nodes:
                nodes_to_check.append({
                    "ip": node.ip,
                    "hostname": node.host,
                    "role": node.role,
                })

            logger.info(f"Discovered {len(nodes_to_check)} nodes for health check")

        except Exception as e:
            logger.error(f"Failed to discover nodes: {e}")
            # Fall back to just checking the publisher
            nodes_to_check.append({
                "ip": request.publisher_host,
                "hostname": None,
                "role": "Publisher",
            })

    # Check health of each node concurrently
    tasks = []
    for node_info in nodes_to_check:
        task = check_node_health(
            host=node_info["ip"],
            port=request.port,
            username=request.username,
            password=request.password,
            connect_timeout=float(request.connect_timeout_sec),
            command_timeout=float(request.command_timeout_sec),
            checks=request.checks,
            hostname=node_info["hostname"],
            role=node_info["role"],
        )
        tasks.append(task)

    node_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    node_statuses: List[NodeHealthStatus] = []
    healthy_count = 0
    degraded_count = 0
    critical_count = 0
    unreachable_count = 0

    for result in node_results:
        if isinstance(result, Exception):
            logger.error(f"Node check failed with exception: {result}")
            # Create a failed node status
            node_statuses.append(NodeHealthStatus(
                ip="unknown",
                status=HealthStatus.CRITICAL,
                reachable=False,
                error=str(result),
                checks=NodeHealthChecks(),
                checked_at=now,
            ))
            critical_count += 1
        else:
            node_statuses.append(result)
            if not result.reachable:
                unreachable_count += 1
            elif result.status == HealthStatus.HEALTHY:
                healthy_count += 1
            elif result.status == HealthStatus.DEGRADED:
                degraded_count += 1
            elif result.status == HealthStatus.CRITICAL:
                critical_count += 1

    # Determine overall cluster status
    cluster_status = _aggregate_health_status([n.status for n in node_statuses])

    # Generate summary message
    total = len(node_statuses)
    if cluster_status == HealthStatus.HEALTHY:
        message = f"All {total} nodes are healthy"
    elif cluster_status == HealthStatus.CRITICAL:
        message = f"Cluster critical: {critical_count} node(s) in critical state"
    elif cluster_status == HealthStatus.DEGRADED:
        message = f"Cluster degraded: {degraded_count} node(s) have issues"
    else:
        message = f"Cluster status unknown: unable to determine health"

    logger.info(
        f"Cluster health check complete: {cluster_status.value} "
        f"(healthy={healthy_count}, degraded={degraded_count}, "
        f"critical={critical_count}, unreachable={unreachable_count})"
    )

    return ClusterHealthResponse(
        cluster_status=cluster_status,
        publisher_host=request.publisher_host,
        checked_at=now,
        total_nodes=total,
        healthy_nodes=healthy_count,
        degraded_nodes=degraded_count,
        critical_nodes=critical_count,
        unreachable_nodes=unreachable_count,
        nodes=node_statuses,
        checks_performed=request.checks,
        message=message,
    )
