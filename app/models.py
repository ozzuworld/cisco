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
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"  # Node processing was cancelled (v0.3)


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
