"""Pydantic models for CUCM Log Collector API"""

from typing import List, Optional, Literal
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field, field_validator, model_validator


class DiscoverNodesRequest(BaseModel):
    """Request model for discovering CUCM cluster nodes"""

    publisher_host: str = Field(
        ...,
        description="IP address or FQDN of the CUCM Publisher",
        examples=["10.10.10.10", "cucm-pub.example.com"]
    )
    port: int = Field(
        default=22,
        description="SSH port (typically 22)",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username",
        examples=["admin"]
    )
    password: str = Field(
        ...,
        description="OS Admin password (not logged)"
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=5,
        le=300
    )
    command_timeout_sec: int = Field(
        default=120,
        description="Command execution timeout in seconds",
        ge=10,
        le=600
    )

    @field_validator("publisher_host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Validate that host is not empty"""
        if not v or not v.strip():
            raise ValueError("publisher_host cannot be empty")
        return v.strip()

    @field_validator("username", "password")
    @classmethod
    def validate_credentials(cls, v: str) -> str:
        """Validate that credentials are not empty"""
        if not v:
            raise ValueError("Credentials cannot be empty")
        return v


class ClusterNode(BaseModel):
    """Represents a single node in the CUCM cluster"""

    ip: str = Field(..., description="Node IP address")
    fqdn: str = Field(..., description="Fully Qualified Domain Name")
    host: str = Field(..., description="Short hostname")
    role: str = Field(..., description="Node role (Publisher/Subscriber)")
    product: str = Field(..., description="Product type (callmanager/cups/etc)")
    dbrole: str = Field(..., description="Database role (DBPub/DBSub)")
    raw: str = Field(..., description="Original raw line from output")


class DiscoverNodesResponse(BaseModel):
    """Response model for node discovery"""

    nodes: List[ClusterNode] = Field(
        default_factory=list,
        description="List of discovered cluster nodes"
    )
    raw_output: Optional[str] = Field(
        default=None,
        description="Raw command output (included when nodes list is empty or debug enabled)"
    )
    raw_output_truncated: bool = Field(
        default=False,
        description="Whether raw output was truncated to max size"
    )


class ErrorResponse(BaseModel):
    """Error response model"""

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    request_id: Optional[str] = Field(
        default=None,
        description="Request ID for tracing"
    )
    details: Optional[str] = Field(
        default=None,
        description="Additional error details (only in debug mode)"
    )


# ============================================================================
# Job Management Models
# ============================================================================


class JobStatus(str, Enum):
    """Job execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"  # Some nodes succeeded, some failed
    CANCELLED = "cancelled"  # Job was cancelled


class DebugLevel(str, Enum):
    """
    Debug/trace verbosity level for CUCM log collection.

    TAC typically requests specific debug levels:
    - BASIC: Default trace levels, minimal performance impact
    - DETAILED: Increased trace verbosity for troubleshooting
    - VERBOSE: Maximum trace detail for deep debugging (performance impact)
    """
    BASIC = "basic"
    DETAILED = "detailed"
    VERBOSE = "verbose"


# ============================================================================
# Trace Level Management Models
# ============================================================================


class ServiceTraceLevel(BaseModel):
    """Trace level for a single CUCM service"""
    service_name: str = Field(..., description="CUCM service name (e.g., 'Cisco CallManager')")
    current_level: str = Field(..., description="Current trace level")
    raw_output: Optional[str] = Field(None, description="Raw command output")


class GetTraceLevelRequest(BaseModel):
    """Request to get current trace levels from CUCM node(s)"""

    hosts: List[str] = Field(
        ...,
        description="List of CUCM node IPs or hostnames to check",
        min_length=1,
        examples=[["10.10.10.10", "10.10.10.11"]]
    )
    port: int = Field(
        default=22,
        description="SSH port",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username"
    )
    password: str = Field(
        ...,
        description="OS Admin password (not logged)"
    )
    services: Optional[List[str]] = Field(
        default=None,
        description="List of services to check. If not provided, checks default services (CallManager, CTIManager)"
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=5,
        le=120
    )

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, v: List[str]) -> List[str]:
        cleaned = [h.strip() for h in v if h and h.strip()]
        if not cleaned:
            raise ValueError("hosts cannot be empty")
        return cleaned


class NodeTraceLevelStatus(BaseModel):
    """Trace level status for a single node"""

    host: str = Field(..., description="Node IP/hostname checked")
    success: bool = Field(..., description="Whether the check succeeded")
    services: List[ServiceTraceLevel] = Field(
        default_factory=list,
        description="Trace levels for each service"
    )
    error: Optional[str] = Field(None, description="Error message if check failed")


class GetTraceLevelResponse(BaseModel):
    """Response with current trace levels for multiple nodes"""

    results: List[NodeTraceLevelStatus] = Field(
        default_factory=list,
        description="Trace level status for each node"
    )
    total_nodes: int = Field(..., description="Total nodes checked")
    successful_nodes: int = Field(..., description="Number of nodes successfully checked")
    failed_nodes: int = Field(..., description="Number of nodes that failed")
    checked_at: datetime = Field(..., description="When the check was performed")
    message: Optional[str] = Field(None, description="Status message")


class SetTraceLevelRequest(BaseModel):
    """Request to set trace level on CUCM node(s)"""

    hosts: List[str] = Field(
        ...,
        description="List of CUCM node IPs or hostnames to configure",
        min_length=1
    )
    port: int = Field(
        default=22,
        description="SSH port",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username"
    )
    password: str = Field(
        ...,
        description="OS Admin password (not logged)"
    )
    level: DebugLevel = Field(
        ...,
        description="Trace level to set (basic, detailed, verbose)"
    )
    services: Optional[List[str]] = Field(
        default=None,
        description="List of services to configure. If not provided, configures default services (CallManager, CTIManager)"
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=5,
        le=120
    )

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one host must be specified")
        return [h.strip() for h in v if h.strip()]


class NodeTraceLevelResult(BaseModel):
    """Result of setting trace level on a single node"""

    host: str = Field(..., description="Node IP/hostname")
    success: bool = Field(..., description="Whether the operation succeeded")
    services_updated: List[str] = Field(
        default_factory=list,
        description="Services that were successfully updated"
    )
    error: Optional[str] = Field(None, description="Error message if failed")


class SetTraceLevelResponse(BaseModel):
    """Response after setting trace levels"""

    level: DebugLevel = Field(..., description="Trace level that was set")
    results: List[NodeTraceLevelResult] = Field(
        default_factory=list,
        description="Results for each node"
    )
    total_nodes: int = Field(..., description="Total nodes attempted")
    successful_nodes: int = Field(..., description="Nodes successfully configured")
    failed_nodes: int = Field(..., description="Nodes that failed")
    completed_at: datetime = Field(..., description="When the operation completed")
    message: str = Field(..., description="Summary message")


class NodeStatus(str, Enum):
    """Individual node processing status"""
    PENDING = "pending"
    QUEUED = "queued"  # Waiting for concurrency slot
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"  # Node processing was cancelled


class FailureClassification(str, Enum):
    """Classification of node failures for actionable error reporting"""
    AUTH_FAILED = "auth_failed"  # SSH authentication failed
    SSH_TIMEOUT = "ssh_timeout"  # SSH connection timeout
    SFTP_TIMEOUT = "sftp_timeout"  # SFTP upload timeout
    CUCM_COMMAND_ERROR = "cucm_command_error"  # CUCM command error (no files, etc.)
    UNKNOWN = "unknown"  # Other/unclassified errors


class CollectionOptions(BaseModel):
    """Options for log collection (can override profile defaults)"""

    # Time collection mode
    time_mode: Optional[Literal["relative", "range"]] = Field(
        default="relative",
        description="Time collection mode: 'relative' for reltime_minutes, 'range' for absolute datetime range"
    )

    # Relative time mode (existing)
    reltime_minutes: Optional[int] = Field(
        default=None,
        description="Override relative time window in minutes (used when time_mode='relative')",
        ge=1,
        le=10080
    )

    # Absolute time range mode (new)
    start_time: Optional[datetime] = Field(
        default=None,
        description="Start of time range (ISO-8601 datetime, used when time_mode='range')"
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="End of time range (ISO-8601 datetime, used when time_mode='range')"
    )

    # Debug/trace verbosity level
    debug_level: Optional[DebugLevel] = Field(
        default=None,
        description="Debug/trace verbosity level for CUCM log collection. "
                    "BASIC=default traces, DETAILED=more verbose, VERBOSE=full debug (performance impact). "
                    "TAC typically requests 'detailed' or 'verbose' for troubleshooting."
    )

    compress: Optional[bool] = Field(
        default=None,
        description="Override compression setting"
    )
    recurs: Optional[bool] = Field(
        default=None,
        description="Override recursive collection setting"
    )
    match: Optional[str] = Field(
        default=None,
        description="Override filename match pattern"
    )

    @model_validator(mode="after")
    def validate_time_settings(self):
        """Validate time mode consistency"""
        if self.time_mode == "range":
            # Range mode requires both start_time and end_time
            if self.start_time is None or self.end_time is None:
                raise ValueError("time_mode='range' requires both start_time and end_time")

            # Validate start_time < end_time
            if self.start_time >= self.end_time:
                raise ValueError("start_time must be before end_time")

            # Validate end_time is not in the future
            now = datetime.now(timezone.utc)
            # Make both timezone-aware for comparison
            end_time_aware = self.end_time if self.end_time.tzinfo else self.end_time.replace(tzinfo=timezone.utc)
            if end_time_aware > now:
                raise ValueError("end_time cannot be in the future")

        elif self.time_mode == "relative":
            # Relative mode should use reltime_minutes (will fall back to profile default if None)
            pass

        return self


class CreateJobRequest(BaseModel):
    """Request to create a new log collection job"""

    publisher_host: str = Field(
        ...,
        description="CUCM Publisher host",
        examples=["10.10.10.10"]
    )
    port: int = Field(
        default=22,
        description="SSH port",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username"
    )
    password: str = Field(
        ...,
        description="OS Admin password (never logged)"
    )
    nodes: List[str] = Field(
        ...,
        description="List of node IPs or hostnames to collect from",
        min_length=1
    )
    profile: str = Field(
        ...,
        description="Collection profile name"
    )
    options: Optional[CollectionOptions] = Field(
        default=None,
        description="Optional overrides for profile defaults"
    )

    @field_validator("nodes")
    @classmethod
    def validate_nodes(cls, v: List[str]) -> List[str]:
        """Validate nodes list is not empty"""
        if not v:
            raise ValueError("At least one node must be specified")
        return v


class CreateJobResponse(BaseModel):
    """Response when creating a job"""

    job_id: str = Field(..., description="Unique job identifier (UUID)")
    status: JobStatus = Field(..., description="Initial job status")
    created_at: datetime = Field(..., description="Job creation timestamp")


class Artifact(BaseModel):
    """Represents a collected log file artifact"""

    node: str = Field(..., description="Node that generated this artifact")
    path: str = Field(..., description="Relative path to the artifact file")
    filename: str = Field(..., description="Artifact filename")
    size_bytes: int = Field(..., description="File size in bytes")
    created_at: datetime = Field(..., description="File creation timestamp")
    artifact_id: Optional[str] = Field(
        default=None,
        description="Stable artifact ID for downloads"
    )

    # Time range collection metadata
    collection_start_time: Optional[datetime] = Field(
        default=None,
        description="Start of the time range for log collection"
    )
    collection_end_time: Optional[datetime] = Field(
        default=None,
        description="End of the time range for log collection"
    )
    reltime_used: Optional[str] = Field(
        default=None,
        description="The reltime value used in CUCM command (e.g., 'hours 3', 'minutes 120')"
    )


class NodeJobStatus(BaseModel):
    """Status of log collection for a single node"""

    node: str = Field(..., description="Node identifier (IP or hostname)")
    status: NodeStatus = Field(..., description="Current status")
    error: Optional[str] = Field(
        default=None,
        description="Error message if failed"
    )
    failure_classification: Optional[FailureClassification] = Field(
        default=None,
        description="Classification of failure type for actionable error reporting"
    )
    transcript_path: Optional[str] = Field(
        default=None,
        description="Path to transcript file (relative to storage root)"
    )
    artifacts: List[Artifact] = Field(
        default_factory=list,
        description="List of collected artifacts"
    )
    started_at: Optional[datetime] = Field(
        default=None,
        description="When processing started for this node"
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="When processing completed for this node"
    )
    # Progress tracking fields
    step: Optional[str] = Field(
        default=None,
        description="Current processing step (e.g., 'connecting', 'collecting', 'discovering')"
    )
    message: Optional[str] = Field(
        default=None,
        description="Progress message for current step"
    )
    last_updated_at: Optional[datetime] = Field(
        default=None,
        description="Last time this node status was updated"
    )
    percent: Optional[int] = Field(
        default=None,
        description="Progress percentage (0-100) for this node",
        ge=0,
        le=100
    )

    # Retry tracking
    retry_count: int = Field(
        default=0,
        description="Number of retry attempts (0 for initial attempt)"
    )
    current_attempt: int = Field(
        default=1,
        description="Current attempt number (1 for initial, 2+ for retries)"
    )


class JobStatusResponse(BaseModel):
    """Response for job status query"""

    job_id: str = Field(..., description="Job identifier")
    status: JobStatus = Field(..., description="Overall job status")
    created_at: datetime = Field(..., description="Job creation timestamp")
    started_at: Optional[datetime] = Field(
        default=None,
        description="When job execution started"
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="When job execution completed"
    )
    profile: str = Field(..., description="Profile name used")
    nodes: List[NodeJobStatus] = Field(
        default_factory=list,
        description="Status for each node"
    )
    # Progress metrics
    total_nodes: int = Field(..., description="Total number of nodes in this job")
    completed_nodes: int = Field(..., description="Number of completed nodes (succeeded + failed)")
    succeeded_nodes: int = Field(..., description="Number of succeeded nodes")
    failed_nodes: int = Field(..., description="Number of failed nodes")
    running_nodes: int = Field(..., description="Number of currently running nodes")
    percent_complete: int = Field(
        ...,
        description="Overall job completion percentage (0-100)",
        ge=0,
        le=100
    )
    last_updated_at: Optional[datetime] = Field(
        default=None,
        description="Last time any node status was updated"
    )

    # Time window configuration (for auditability and reproducibility)
    requested_start_time: Optional[datetime] = Field(
        default=None,
        description="Requested start time for log collection (range mode)"
    )
    requested_end_time: Optional[datetime] = Field(
        default=None,
        description="Requested end time for log collection (range mode)"
    )
    requested_reltime_minutes: Optional[int] = Field(
        default=None,
        description="Requested relative time window in minutes (relative mode)"
    )
    computed_reltime_unit: Optional[str] = Field(
        default=None,
        description="Computed reltime unit used (minutes/hours/days/weeks/months)"
    )
    computed_reltime_value: Optional[int] = Field(
        default=None,
        description="Computed reltime value used"
    )
    computation_timestamp: Optional[datetime] = Field(
        default=None,
        description="Server 'now' timestamp used for reltime computation"
    )

    # Debug level configuration
    debug_level: Optional[DebugLevel] = Field(
        default=None,
        description="Debug/trace verbosity level used for this job (basic/detailed/verbose)"
    )

    # Download availability
    download_available: bool = Field(
        default=False,
        description="Whether artifacts are available for download"
    )


class ArtifactsResponse(BaseModel):
    """Response for artifacts listing"""

    job_id: str = Field(..., description="Job identifier")
    artifacts: List[Artifact] = Field(
        default_factory=list,
        description="List of all collected artifacts"
    )


class ProfileResponse(BaseModel):
    """Response model for a single profile"""

    name: str = Field(..., description="Profile name")
    description: str = Field(..., description="Profile description")
    paths: List[str] = Field(..., description="Log paths to collect")
    reltime_minutes: int = Field(..., description="Default time window")
    compress: bool = Field(..., description="Default compression setting")
    recurs: bool = Field(..., description="Default recursive setting")
    match: Optional[str] = Field(None, description="Default match pattern")


class ProfilesResponse(BaseModel):
    """Response for profiles listing"""

    profiles: List[ProfileResponse] = Field(
        default_factory=list,
        description="List of available profiles"
    )


class JobSummary(BaseModel):
    """Summary of a job for list view"""

    job_id: str
    status: JobStatus
    profile: str
    created_at: datetime
    node_count: int


class JobsListResponse(BaseModel):
    """Response for jobs listing"""

    jobs: List[JobSummary] = Field(
        default_factory=list,
        description="List of recent jobs"
    )


# ============================================================================
# Cancellation Models
# ============================================================================


class CancelJobResponse(BaseModel):
    """Response for job cancellation request"""

    job_id: str = Field(..., description="Job identifier")
    status: JobStatus = Field(..., description="Job status after cancellation")
    cancelled: bool = Field(..., description="Whether cancellation was successful")
    message: str = Field(..., description="Cancellation status message")


# ============================================================================
# Retry Failed Nodes Models
# ============================================================================


class RetryJobResponse(BaseModel):
    """Response for retry failed nodes request"""

    job_id: str = Field(..., description="Job identifier")
    status: JobStatus = Field(..., description="Job status after retry initiated")
    retried_nodes: List[str] = Field(
        default_factory=list,
        description="List of nodes that were retried"
    )
    retry_count: int = Field(..., description="Total number of nodes being retried")
    message: str = Field(..., description="Retry status message")


# ============================================================================
# Dry-run / Estimate Models
# ============================================================================


class CommandEstimate(BaseModel):
    """Estimate for a single CUCM command that would be executed"""

    path: str = Field(..., description="Log path to collect")
    command: str = Field(..., description="Full CUCM CLI command that would be executed")
    reltime_unit: str = Field(..., description="Reltime unit (minutes/hours/days/weeks/months)")
    reltime_value: int = Field(..., description="Reltime value")


class NodeEstimate(BaseModel):
    """Estimate for log collection on a single node"""

    node: str = Field(..., description="Node IP or hostname")
    commands: List[CommandEstimate] = Field(
        default_factory=list,
        description="List of commands that would be executed"
    )
    total_commands: int = Field(..., description="Total number of commands for this node")


class EstimateResponse(BaseModel):
    """Response for job estimation (dry-run)"""

    profile: str = Field(..., description="Profile name")
    nodes: List[NodeEstimate] = Field(
        default_factory=list,
        description="Estimate for each node"
    )
    total_nodes: int = Field(..., description="Total number of nodes")
    total_commands: int = Field(..., description="Total number of commands across all nodes")

    # Time window configuration
    time_mode: str = Field(..., description="Time mode (relative or range)")
    requested_start_time: Optional[datetime] = Field(
        default=None,
        description="Requested start time (range mode)"
    )
    requested_end_time: Optional[datetime] = Field(
        default=None,
        description="Requested end time (range mode)"
    )
    requested_reltime_minutes: Optional[int] = Field(
        default=None,
        description="Requested reltime minutes (relative mode)"
    )
    computed_reltime_unit: str = Field(..., description="Computed reltime unit")
    computed_reltime_value: int = Field(..., description="Computed reltime value")
    computation_timestamp: datetime = Field(..., description="When reltime was computed")


# ============================================================================
# Cluster Health Status Models
# ============================================================================


class HealthStatus(str, Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthCheckType(str, Enum):
    """Types of health checks available"""
    REPLICATION = "replication"
    SERVICES = "services"
    NTP = "ntp"
    DIAGNOSTICS = "diagnostics"
    CORES = "cores"


class ClusterHealthRequest(BaseModel):
    """Request model for cluster health check"""

    publisher_host: str = Field(
        ...,
        description="IP address or FQDN of the CUCM Publisher",
        examples=["10.10.10.10", "cucm-pub.example.com"]
    )
    port: int = Field(
        default=22,
        description="SSH port (typically 22)",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username",
        examples=["admin"]
    )
    password: str = Field(
        ...,
        description="OS Admin password (not logged)"
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=5,
        le=300
    )
    command_timeout_sec: int = Field(
        default=120,
        description="Command execution timeout in seconds",
        ge=10,
        le=600
    )
    nodes: Optional[List[str]] = Field(
        default=None,
        description="List of node IPs to check. If not provided, discovers nodes from publisher."
    )
    checks: List[HealthCheckType] = Field(
        default=[
            HealthCheckType.REPLICATION,
            HealthCheckType.SERVICES,
            HealthCheckType.NTP,
        ],
        description="Health checks to perform"
    )

    @field_validator("publisher_host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Validate that host is not empty"""
        if not v or not v.strip():
            raise ValueError("publisher_host cannot be empty")
        return v.strip()

    @field_validator("username", "password")
    @classmethod
    def validate_credentials(cls, v: str) -> str:
        """Validate that credentials are not empty"""
        if not v:
            raise ValueError("Credentials cannot be empty")
        return v


class ReplicationNodeStatus(BaseModel):
    """Replication status for a single node in the cluster"""

    server_name: str = Field(..., description="Server hostname")
    ip_address: str = Field(..., description="Server IP address")
    ping_ms: Optional[float] = Field(None, description="Ping time in milliseconds")
    db_mon: Optional[str] = Field(None, description="DB/RPC/DbMon status (e.g., 'Y/Y/Y')")
    repl_queue: Optional[int] = Field(None, description="Replication queue depth")
    group_id: Optional[str] = Field(None, description="Replication group ID")
    setup_state: Optional[int] = Field(None, description="RTMT replication setup state (2=complete)")
    setup_status: Optional[str] = Field(None, description="Setup status message")


class ReplicationStatus(BaseModel):
    """Database replication health status"""

    status: HealthStatus = Field(..., description="Overall replication health")
    checked_at: datetime = Field(..., description="When the check was performed")
    db_version: Optional[str] = Field(None, description="Database version")
    repl_timeout: Optional[int] = Field(None, description="Replication timeout in seconds")
    tables_checked: Optional[int] = Field(None, description="Number of tables checked")
    tables_total: Optional[int] = Field(None, description="Total number of tables")
    errors_found: bool = Field(default=False, description="Whether errors were found")
    mismatches_found: bool = Field(default=False, description="Whether mismatches were found")
    nodes: List[ReplicationNodeStatus] = Field(
        default_factory=list,
        description="Per-node replication status"
    )
    raw_output: Optional[str] = Field(None, description="Raw command output for debugging")
    message: Optional[str] = Field(None, description="Status message or error details")


class ServiceInfo(BaseModel):
    """Information about a single service"""

    name: str = Field(..., description="Service name")
    status: str = Field(..., description="Service status (STARTED, STOPPED, etc.)")
    is_running: bool = Field(..., description="Whether the service is running")


class ServicesStatus(BaseModel):
    """Services health status"""

    status: HealthStatus = Field(..., description="Overall services health")
    checked_at: datetime = Field(..., description="When the check was performed")
    total_services: int = Field(default=0, description="Total number of services")
    running_services: int = Field(default=0, description="Number of running services")
    stopped_services: int = Field(default=0, description="Number of stopped services")
    critical_services_down: List[str] = Field(
        default_factory=list,
        description="List of critical services that are not running"
    )
    services: List[ServiceInfo] = Field(
        default_factory=list,
        description="All services and their status"
    )
    raw_output: Optional[str] = Field(None, description="Raw command output for debugging")
    message: Optional[str] = Field(None, description="Status message or error details")


class NTPStatus(BaseModel):
    """NTP synchronization health status"""

    status: HealthStatus = Field(..., description="Overall NTP health")
    checked_at: datetime = Field(..., description="When the check was performed")
    synchronized: bool = Field(default=False, description="Whether NTP is synchronized")
    stratum: Optional[int] = Field(None, description="NTP stratum level (lower is better, <=3 recommended)")
    ntp_server: Optional[str] = Field(None, description="Current NTP server")
    offset_ms: Optional[float] = Field(None, description="Time offset in milliseconds")
    raw_output: Optional[str] = Field(None, description="Raw command output for debugging")
    message: Optional[str] = Field(None, description="Status message or error details")


class DiagnosticTest(BaseModel):
    """Result of a single diagnostic test"""

    name: str = Field(..., description="Test name")
    passed: bool = Field(..., description="Whether the test passed")
    message: Optional[str] = Field(None, description="Test result message")


class DiagnosticsStatus(BaseModel):
    """System diagnostics health status"""

    status: HealthStatus = Field(..., description="Overall diagnostics health")
    checked_at: datetime = Field(..., description="When the check was performed")
    total_tests: int = Field(default=0, description="Total number of tests run")
    passed_tests: int = Field(default=0, description="Number of passed tests")
    failed_tests: int = Field(default=0, description="Number of failed tests")
    tests: List[DiagnosticTest] = Field(
        default_factory=list,
        description="Individual test results"
    )
    raw_output: Optional[str] = Field(None, description="Raw command output for debugging")
    message: Optional[str] = Field(None, description="Status message or error details")


class CoreFilesStatus(BaseModel):
    """Core files (crash dumps) health status"""

    status: HealthStatus = Field(..., description="Overall core files health")
    checked_at: datetime = Field(..., description="When the check was performed")
    core_count: int = Field(default=0, description="Number of core files found")
    core_files: List[str] = Field(
        default_factory=list,
        description="List of core file names/paths"
    )
    raw_output: Optional[str] = Field(None, description="Raw command output for debugging")
    message: Optional[str] = Field(None, description="Status message or error details")


class NodeHealthChecks(BaseModel):
    """Health check results for a single node"""

    replication: Optional[ReplicationStatus] = Field(
        None, description="Database replication status"
    )
    services: Optional[ServicesStatus] = Field(
        None, description="Services status"
    )
    ntp: Optional[NTPStatus] = Field(
        None, description="NTP synchronization status"
    )
    diagnostics: Optional[DiagnosticsStatus] = Field(
        None, description="System diagnostics status"
    )
    cores: Optional[CoreFilesStatus] = Field(
        None, description="Core files status"
    )


class NodeHealthStatus(BaseModel):
    """Health status for a single CUCM node"""

    ip: str = Field(..., description="Node IP address")
    hostname: Optional[str] = Field(None, description="Node hostname")
    role: Optional[str] = Field(None, description="Node role (Publisher/Subscriber)")
    status: HealthStatus = Field(..., description="Overall node health status")
    reachable: bool = Field(default=True, description="Whether the node is reachable via SSH")
    error: Optional[str] = Field(None, description="Error message if node is unreachable")
    checks: NodeHealthChecks = Field(
        default_factory=NodeHealthChecks,
        description="Individual health check results"
    )
    checked_at: datetime = Field(..., description="When the node was checked")


class ClusterHealthResponse(BaseModel):
    """Response model for cluster health check"""

    cluster_status: HealthStatus = Field(..., description="Overall cluster health status")
    publisher_host: str = Field(..., description="Publisher host used for the check")
    checked_at: datetime = Field(..., description="When the health check was performed")
    total_nodes: int = Field(default=0, description="Total number of nodes checked")
    healthy_nodes: int = Field(default=0, description="Number of healthy nodes")
    degraded_nodes: int = Field(default=0, description="Number of degraded nodes")
    critical_nodes: int = Field(default=0, description="Number of critical nodes")
    unreachable_nodes: int = Field(default=0, description="Number of unreachable nodes")
    nodes: List[NodeHealthStatus] = Field(
        default_factory=list,
        description="Health status for each node"
    )
    checks_performed: List[HealthCheckType] = Field(
        default_factory=list,
        description="List of health checks that were performed"
    )
    message: Optional[str] = Field(None, description="Summary message")


# ============================================================================
# Packet Capture Models
# ============================================================================


class CaptureStatus(str, Enum):
    """Packet capture status"""
    PENDING = "pending"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    STOPPED = "stopped"  # For rotating captures stopped by user


class CaptureMode(str, Enum):
    """Packet capture mode"""
    STANDARD = "standard"  # Regular capture with duration/packet limit
    ROTATING = "rotating"  # Ring buffer capture with file rotation


class CaptureDeviceType(str, Enum):
    """Type of device for packet capture"""
    CUCM = "cucm"
    CUBE = "cube"
    CSR1000V = "csr1000v"
    EXPRESSWAY = "expressway"


class CaptureFilter(BaseModel):
    """Filter options for packet capture"""

    host: Optional[str] = Field(
        default=None,
        description="Filter by host IP address (captures traffic to/from this host)"
    )
    src: Optional[str] = Field(
        default=None,
        description="Filter by source IP address"
    )
    dest: Optional[str] = Field(
        default=None,
        description="Filter by destination IP address"
    )
    port: Optional[int] = Field(
        default=None,
        description="Filter by port number (e.g., 5060 for SIP)",
        ge=1,
        le=65535
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Filter by protocol (ip, arp, rarp, or all)",
        pattern="^(ip|arp|rarp|all)$"
    )

    @model_validator(mode="after")
    def validate_filters(self):
        """Validate filter combinations"""
        # Can't use both host and src/dest at the same time
        if self.host and (self.src or self.dest):
            raise ValueError("Cannot use 'host' filter together with 'src' or 'dest' filters")
        return self


class StartCaptureRequest(BaseModel):
    """Request to start a packet capture"""

    device_type: CaptureDeviceType = Field(
        default=CaptureDeviceType.CUCM,
        description="Type of device to capture on (cucm, csr1000v)"
    )
    host: str = Field(
        ...,
        description="IP address or FQDN of the device",
        examples=["10.10.10.10", "cucm-pub.example.com", "csr1000v.example.com"]
    )
    port: int = Field(
        default=22,
        description="SSH port (typically 22)",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="OS Admin username",
        examples=["admin"]
    )
    password: str = Field(
        ...,
        description="OS Admin password (not logged)"
    )
    # Capture mode
    mode: CaptureMode = Field(
        default=CaptureMode.STANDARD,
        description="Capture mode: 'standard' for fixed duration, 'rotating' for continuous ring buffer"
    )
    duration_sec: Optional[int] = Field(
        default=None,
        description="Capture duration in seconds (required for standard mode, ignored for rotating mode)",
        ge=10,
        le=600,  # Max 10 minutes for standard mode
        examples=[60, 120, 300]
    )
    interface: str = Field(
        default="eth0",
        description="Network interface to capture on",
        examples=["eth0"]
    )
    filename: Optional[str] = Field(
        default=None,
        description="Custom filename for capture (without extension). Auto-generated if not provided.",
        pattern="^[a-zA-Z0-9_-]+$",
        max_length=50
    )
    filter: Optional[CaptureFilter] = Field(
        default=None,
        description="Optional capture filters"
    )
    packet_count: int = Field(
        default=100000,
        description="Maximum number of packets to capture (standard mode only)",
        ge=100,
        le=100000
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="SSH connection timeout in seconds",
        ge=5,
        le=120
    )
    # Rotating capture options
    size_per_file_mb: int = Field(
        default=25,
        description="Size of each rotation file in MB (rotating mode only)",
        ge=1,
        le=100
    )
    max_files: int = Field(
        default=10,
        description="Maximum number of rotation files to keep (rotating mode only, ring buffer)",
        ge=2,
        le=100
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("host cannot be empty")
        return v.strip()

    @field_validator("username", "password")
    @classmethod
    def validate_credentials(cls, v: str) -> str:
        if not v:
            raise ValueError("Credentials cannot be empty")
        return v

    @model_validator(mode="after")
    def validate_mode_settings(self):
        """Validate mode-specific settings"""
        if self.mode == CaptureMode.STANDARD:
            if self.duration_sec is None:
                raise ValueError("duration_sec is required for standard capture mode")
        return self


class CaptureInfo(BaseModel):
    """Information about a packet capture"""

    capture_id: str = Field(..., description="Unique capture identifier")
    status: CaptureStatus = Field(..., description="Current capture status")
    device_type: CaptureDeviceType = Field(
        default=CaptureDeviceType.CUCM,
        description="Type of device"
    )
    mode: CaptureMode = Field(
        default=CaptureMode.STANDARD,
        description="Capture mode (standard or rotating)"
    )
    host: str = Field(..., description="Target host IP or FQDN")
    interface: str = Field(..., description="Network interface")
    filename: str = Field(..., description="Capture filename (without path)")
    duration_sec: Optional[int] = Field(None, description="Requested capture duration (standard mode)")
    filter: Optional[CaptureFilter] = Field(None, description="Applied filters")
    packet_count: int = Field(..., description="Maximum packet count")
    started_at: Optional[datetime] = Field(None, description="When capture started")
    completed_at: Optional[datetime] = Field(None, description="When capture completed")
    created_at: datetime = Field(..., description="When capture was created")
    file_size_bytes: Optional[int] = Field(None, description="Capture file size in bytes")
    packets_captured: Optional[int] = Field(None, description="Number of packets captured")
    error: Optional[str] = Field(None, description="Error message if failed")
    message: Optional[str] = Field(None, description="Status message")
    # Rotating capture fields
    size_per_file_mb: Optional[int] = Field(None, description="Size per rotation file in MB")
    max_files: Optional[int] = Field(None, description="Max rotation files (ring buffer size)")
    files_collected: Optional[int] = Field(None, description="Number of rotation files collected")


class StartCaptureResponse(BaseModel):
    """Response when starting a capture"""

    capture_id: str = Field(..., description="Unique capture identifier")
    status: CaptureStatus = Field(..., description="Initial capture status")
    host: str = Field(..., description="Target host")
    filename: str = Field(..., description="Capture filename")
    duration_sec: int = Field(..., description="Capture duration")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="When capture was created")


class CaptureStatusResponse(BaseModel):
    """Response for capture status query"""

    capture: CaptureInfo = Field(..., description="Capture information")
    download_available: bool = Field(
        default=False,
        description="Whether the capture file is available for download"
    )


class CaptureListResponse(BaseModel):
    """Response for listing captures"""

    captures: List[CaptureInfo] = Field(
        default_factory=list,
        description="List of captures"
    )
    total: int = Field(default=0, description="Total number of captures")


class StopCaptureResponse(BaseModel):
    """Response when stopping a capture"""

    capture_id: str = Field(..., description="Capture identifier")
    status: CaptureStatus = Field(..., description="Capture status after stop")
    message: str = Field(..., description="Status message")


# ============================================================================
# Capture Session Models (Multi-Device Orchestration)
# ============================================================================


class CaptureSessionStatus(str, Enum):
    """Status of an orchestrated capture session"""
    PENDING = "pending"          # Created, not started
    CONFIGURING = "configuring"  # Connecting to devices, configuring
    READY = "ready"              # All devices ready
    STARTING = "starting"        # Sending start commands
    CAPTURING = "capturing"      # Active capture in progress
    STOPPING = "stopping"        # Stopping captures
    COLLECTING = "collecting"    # Retrieving files from devices
    COMPLETED = "completed"      # Done - all succeeded
    PARTIAL = "partial"          # Some devices succeeded
    FAILED = "failed"            # All devices failed
    CANCELLED = "cancelled"      # User cancelled


class CaptureTargetStatus(str, Enum):
    """Status of a single target in a capture session"""
    PENDING = "pending"
    CONFIGURING = "configuring"
    READY = "ready"
    CAPTURING = "capturing"
    STOPPING = "stopping"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CaptureTargetRequest(BaseModel):
    """Request for a single device target in a multi-device capture session"""

    device_type: CaptureDeviceType = Field(
        ...,
        description="Type of device (cucm, cube, csr1000v, expressway)"
    )
    host: str = Field(
        ...,
        description="IP address or FQDN of the device"
    )
    port: Optional[int] = Field(
        default=None,
        description="SSH port (defaults by device type: cucm/cube/csr=22, expressway=443)",
        ge=1,
        le=65535
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface (defaults by device: cucm/expressway=eth0, cube/csr=GigabitEthernet1)"
    )
    username: Optional[str] = Field(
        default=None,
        description="Device-specific username (falls back to session global credentials)"
    )
    password: Optional[str] = Field(
        default=None,
        description="Device-specific password (falls back to session global credentials)"
    )


class StartCaptureSessionRequest(BaseModel):
    """Request to start a multi-device capture session"""

    name: Optional[str] = Field(
        default=None,
        description="Optional session name",
        max_length=100
    )
    mode: CaptureMode = Field(
        default=CaptureMode.STANDARD,
        description="Capture mode: 'standard' for fixed duration, 'rotating' for continuous ring buffer"
    )
    duration_sec: Optional[int] = Field(
        default=None,
        description="Capture duration in seconds (required for standard mode)",
        ge=10,
        le=600
    )
    size_per_file_mb: int = Field(
        default=25,
        description="Size of each rotation file in MB (rotating mode only)",
        ge=1,
        le=100
    )
    max_files: int = Field(
        default=10,
        description="Maximum number of rotation files to keep (rotating mode only)",
        ge=2,
        le=100
    )
    filter: Optional[CaptureFilter] = Field(
        default=None,
        description="Optional capture filters (applied to all targets)"
    )
    targets: List[CaptureTargetRequest] = Field(
        ...,
        description="List of device targets to capture from",
        min_length=1
    )
    username: Optional[str] = Field(
        default=None,
        description="Global username (fallback for targets without credentials)"
    )
    password: Optional[str] = Field(
        default=None,
        description="Global password (fallback for targets without credentials)"
    )

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[CaptureTargetRequest]) -> List[CaptureTargetRequest]:
        if not v or len(v) == 0:
            raise ValueError("At least one target is required")
        if len(v) > 10:
            raise ValueError("Maximum 10 targets allowed per session")
        return v

    @model_validator(mode='after')
    def validate_mode_params(self) -> 'StartCaptureSessionRequest':
        """Validate that duration_sec is provided for standard mode"""
        if self.mode == CaptureMode.STANDARD and self.duration_sec is None:
            raise ValueError("duration_sec is required for standard capture mode")
        return self


class CaptureTargetInfo(BaseModel):
    """Information about a single target in a capture session"""

    device_type: CaptureDeviceType = Field(..., description="Device type")
    host: str = Field(..., description="Device host")
    port: int = Field(..., description="SSH port")
    interface: str = Field(..., description="Network interface")
    status: CaptureTargetStatus = Field(..., description="Target status")
    error: Optional[str] = Field(None, description="Error message if failed")
    message: Optional[str] = Field(None, description="Status message")
    config_started_at: Optional[datetime] = Field(None, description="When configuration started")
    capture_started_at: Optional[datetime] = Field(None, description="When capture started")
    capture_stopped_at: Optional[datetime] = Field(None, description="When capture stopped")
    completed_at: Optional[datetime] = Field(None, description="When target completed")
    packets_captured: Optional[int] = Field(None, description="Number of packets captured")
    file_size_bytes: Optional[int] = Field(None, description="Capture file size")
    filename: Optional[str] = Field(None, description="Capture filename")
    capture_id: Optional[str] = Field(None, description="Underlying capture ID")


class CaptureSessionInfo(BaseModel):
    """Information about a capture session"""

    session_id: str = Field(..., description="Unique session identifier")
    name: Optional[str] = Field(None, description="Session name")
    mode: CaptureMode = Field(default=CaptureMode.STANDARD, description="Capture mode")
    status: CaptureSessionStatus = Field(..., description="Current session status")
    created_at: datetime = Field(..., description="When session was created")
    capture_started_at: Optional[datetime] = Field(None, description="When captures started")
    completed_at: Optional[datetime] = Field(None, description="When session completed")
    duration_sec: Optional[int] = Field(None, description="Capture duration (standard mode only)")
    size_per_file_mb: Optional[int] = Field(None, description="Size per file in MB (rotating mode only)")
    max_files: Optional[int] = Field(None, description="Max files to keep (rotating mode only)")
    targets: List[CaptureTargetInfo] = Field(
        default_factory=list,
        description="List of capture targets"
    )
    bundle_filename: Optional[str] = Field(None, description="ZIP bundle filename")


class StartCaptureSessionResponse(BaseModel):
    """Response when starting a capture session"""

    session_id: str = Field(..., description="Unique session identifier")
    status: CaptureSessionStatus = Field(..., description="Initial session status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="When session was created")
    targets: List[CaptureTargetInfo] = Field(
        default_factory=list,
        description="Initial target information"
    )


class CaptureSessionStatusResponse(BaseModel):
    """Response for capture session status query"""

    session: CaptureSessionInfo = Field(..., description="Session information")
    download_available: bool = Field(
        default=False,
        description="Whether the bundle is available for download"
    )
    elapsed_sec: Optional[int] = Field(None, description="Elapsed time during capture")
    remaining_sec: Optional[int] = Field(None, description="Remaining time during capture")


class CaptureSessionListResponse(BaseModel):
    """Response for listing capture sessions"""

    sessions: List[CaptureSessionInfo] = Field(
        default_factory=list,
        description="List of capture sessions"
    )
    total: int = Field(default=0, description="Total number of sessions")


class StopCaptureSessionResponse(BaseModel):
    """Response when stopping a capture session"""

    session_id: str = Field(..., description="Session identifier")
    status: CaptureSessionStatus = Field(..., description="Session status after stop")
    message: str = Field(..., description="Status message")


# ============================================================================
# Log Collection Models
# ============================================================================


class LogDeviceType(str, Enum):
    """Type of device for log collection"""
    CUBE = "cube"
    EXPRESSWAY = "expressway"


class LogCollectionMethod(str, Enum):
    """Method used for log collection"""
    VOIP_TRACE = "voip_trace"  # CUBE: show voip trace (IOS-XE 17.3.2+)
    DEBUG_CCSIP = "debug_ccsip"  # CUBE: Traditional debug (older IOS-XE)
    DIAGNOSTIC = "diagnostic"  # Expressway: diagnostic logging API


class LogCollectionStatus(str, Enum):
    """Status of a log collection operation"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StartLogCollectionRequest(BaseModel):
    """Request to start log collection from a device"""

    device_type: LogDeviceType = Field(
        ...,
        description="Type of device to collect logs from"
    )
    host: str = Field(
        ...,
        description="IP address or FQDN of the device",
        examples=["10.10.10.10", "cube.example.com", "expressway.example.com"]
    )
    port: int = Field(
        default=22,
        description="SSH/HTTPS port (22 for CUBE, 443 for Expressway)",
        ge=1,
        le=65535
    )
    username: str = Field(
        ...,
        description="Admin username",
        examples=["admin"]
    )
    password: str = Field(
        ...,
        description="Admin password (not logged)"
    )
    profile: Optional[str] = Field(
        default=None,
        description="Collection profile name (e.g., 'voip_trace', 'diagnostic_full'). Uses device default if not specified."
    )
    method: Optional[LogCollectionMethod] = Field(
        default=None,
        description="Collection method (auto-detected from profile if not specified)"
    )
    duration_sec: int = Field(
        default=30,
        description="For debug collection: how long to enable debug before collecting",
        ge=5,
        le=300
    )
    include_debug: bool = Field(
        default=False,
        description="CUBE: Enable debug ccsip messages before collection (CPU intensive)"
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=5,
        le=120
    )

    @model_validator(mode="after")
    def set_default_port(self):
        """Set default port based on device type if port is default SSH"""
        if self.port == 22 and self.device_type == LogDeviceType.EXPRESSWAY:
            object.__setattr__(self, 'port', 443)
        return self


class LogCollectionInfo(BaseModel):
    """Information about a log collection operation"""

    collection_id: str = Field(..., description="Unique collection identifier")
    status: LogCollectionStatus = Field(..., description="Current status")
    device_type: LogDeviceType = Field(..., description="Device type")
    profile: Optional[str] = Field(None, description="Profile used for collection")
    method: Optional[LogCollectionMethod] = Field(None, description="Collection method used")
    host: str = Field(..., description="Target host")
    started_at: Optional[datetime] = Field(None, description="When collection started")
    completed_at: Optional[datetime] = Field(None, description="When collection completed")
    created_at: datetime = Field(..., description="When collection was created")
    file_size_bytes: Optional[int] = Field(None, description="Collected log file size")
    error: Optional[str] = Field(None, description="Error message if failed")
    message: Optional[str] = Field(None, description="Status message")


class StartLogCollectionResponse(BaseModel):
    """Response when starting log collection"""

    collection_id: str = Field(..., description="Unique collection identifier")
    status: LogCollectionStatus = Field(..., description="Initial status")
    host: str = Field(..., description="Target host")
    device_type: LogDeviceType = Field(..., description="Device type")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="When collection was created")


class LogCollectionStatusResponse(BaseModel):
    """Response for log collection status query"""

    collection: LogCollectionInfo = Field(..., description="Collection information")
    download_available: bool = Field(
        default=False,
        description="Whether the log file is available for download"
    )


class LogCollectionListResponse(BaseModel):
    """Response for listing log collections"""

    collections: List[LogCollectionInfo] = Field(
        default_factory=list,
        description="List of log collections"
    )
    total: int = Field(default=0, description="Total number of collections")


class CubeProfileResponse(BaseModel):
    """Response model for a CUBE profile"""

    name: str = Field(..., description="Profile name")
    description: str = Field(..., description="Profile description")
    device_type: str = Field(default="cube", description="Device type")
    method: str = Field(..., description="Collection method")
    commands: List[str] = Field(default_factory=list, description="Commands to execute")
    include_debug: bool = Field(default=False, description="Whether debug is enabled")
    duration_sec: int = Field(default=30, description="Debug duration in seconds")


class ExpresswayProfileResponse(BaseModel):
    """Response model for an Expressway profile"""

    name: str = Field(..., description="Profile name")
    description: str = Field(..., description="Profile description")
    device_type: str = Field(default="expressway", description="Device type")
    method: str = Field(..., description="Collection method")
    tcpdump: bool = Field(default=False, description="Include packet capture")


class LogProfilesResponse(BaseModel):
    """Response for listing CUBE and Expressway profiles"""

    cube_profiles: List[CubeProfileResponse] = Field(
        default_factory=list,
        description="List of CUBE profiles"
    )
    expressway_profiles: List[ExpresswayProfileResponse] = Field(
        default_factory=list,
        description="List of Expressway profiles"
    )
