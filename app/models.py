"""Pydantic models for CUCM Log Collector API"""

from typing import List, Optional
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
