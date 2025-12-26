"""Pydantic models for CUCM Log Collector API"""

from typing import List, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, field_validator


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


class NodeStatus(str, Enum):
    """Individual node processing status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CollectionOptions(BaseModel):
    """Options for log collection (can override profile defaults)"""

    reltime_minutes: Optional[int] = Field(
        default=None,
        description="Override relative time window in minutes",
        ge=1,
        le=10080
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
    path: str = Field(..., description="Full path to the artifact file")
    filename: str = Field(..., description="Artifact filename")
    size_bytes: int = Field(..., description="File size in bytes")
    created_at: datetime = Field(..., description="File creation timestamp")


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
