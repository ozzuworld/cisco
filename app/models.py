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
        description="Request ID for tracing (v0.3)"
    )
    details: Optional[str] = Field(
        default=None,
        description="Additional error details (only in debug mode)"
    )


# ============================================================================
# Job Management Models (v0.2)
# ============================================================================


class JobStatus(str, Enum):
    """Job execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"  # Some nodes succeeded, some failed
    CANCELLED = "cancelled"  # Job was cancelled (v0.3)


class NodeStatus(str, Enum):
    """Individual node processing status"""
    PENDING = "pending"
    QUEUED = "queued"  # BE-031: Waiting for concurrency slot
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"  # Node processing was cancelled (v0.3)


class FailureClassification(str, Enum):
    """BE-032: Classification of node failures for actionable error reporting"""
    AUTH_FAILED = "auth_failed"  # SSH authentication failed
    SSH_TIMEOUT = "ssh_timeout"  # SSH connection timeout
    SFTP_TIMEOUT = "sftp_timeout"  # SFTP upload timeout
    CUCM_COMMAND_ERROR = "cucm_command_error"  # CUCM command error (no files, etc.)
    UNKNOWN = "unknown"  # Other/unclassified errors


class CollectionOptions(BaseModel):
    """Options for log collection (can override profile defaults)"""

    # BE-024: Time collection mode
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

    # BE-024: Absolute time range mode (new)
    start_time: Optional[datetime] = Field(
        default=None,
        description="Start of time range (ISO-8601 datetime, used when time_mode='range')"
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="End of time range (ISO-8601 datetime, used when time_mode='range')"
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
        """BE-024: Validate time mode consistency"""
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
        description="Stable artifact ID for downloads (v0.3)"
    )

    # BE-024: Time range collection metadata
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
        description="BE-032: Classification of failure type for actionable error reporting"
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
    # BE-019: Progress tracking fields
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

    # BE-030: Retry tracking
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
    # BE-019: Progress metrics
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

    # BE-026: Time window configuration (for auditability and reproducibility)
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
# v0.3 Models - Cancellation
# ============================================================================


class CancelJobResponse(BaseModel):
    """Response for job cancellation request"""

    job_id: str = Field(..., description="Job identifier")
    status: JobStatus = Field(..., description="Job status after cancellation")
    cancelled: bool = Field(..., description="Whether cancellation was successful")
    message: str = Field(..., description="Cancellation status message")


# ============================================================================
# BE-030 Models - Retry Failed Nodes
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
# BE-027 Models - Dry-run / Estimate
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


class CaptureDeviceType(str, Enum):
    """Type of device for packet capture"""
    CUCM = "cucm"
    CUBE = "cube"


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

    host: str = Field(
        ...,
        description="IP address or FQDN of the CUCM node",
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
    duration_sec: int = Field(
        ...,
        description="Capture duration in seconds",
        ge=10,
        le=600,  # Max 10 minutes
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
        description="Maximum number of packets to capture",
        ge=100,
        le=100000
    )
    connect_timeout_sec: int = Field(
        default=30,
        description="SSH connection timeout in seconds",
        ge=5,
        le=120
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


class CaptureInfo(BaseModel):
    """Information about a packet capture"""

    capture_id: str = Field(..., description="Unique capture identifier")
    status: CaptureStatus = Field(..., description="Current capture status")
    device_type: CaptureDeviceType = Field(
        default=CaptureDeviceType.CUCM,
        description="Type of device"
    )
    host: str = Field(..., description="Target host IP or FQDN")
    interface: str = Field(..., description="Network interface")
    filename: str = Field(..., description="Capture filename (without path)")
    duration_sec: int = Field(..., description="Requested capture duration")
    filter: Optional[CaptureFilter] = Field(None, description="Applied filters")
    packet_count: int = Field(..., description="Maximum packet count")
    started_at: Optional[datetime] = Field(None, description="When capture started")
    completed_at: Optional[datetime] = Field(None, description="When capture completed")
    created_at: datetime = Field(..., description="When capture was created")
    file_size_bytes: Optional[int] = Field(None, description="Capture file size in bytes")
    packets_captured: Optional[int] = Field(None, description="Number of packets captured")
    error: Optional[str] = Field(None, description="Error message if failed")
    message: Optional[str] = Field(None, description="Status message")


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
