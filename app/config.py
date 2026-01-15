"""Configuration management for CUCM Log Collector"""

import logging
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # Debug Settings
    debug_http: bool = False  # Enable detailed HTTP request logging

    # CORS Settings - allows localhost, loopback, and private network ranges by default
    # For Docker deployments, this ensures browsers can access from the host's IP
    cors_allowed_origins: str = r"^https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$"

    # Authentication
    api_key: Optional[str] = None  # If set, enables API key auth

    # SFTP Server Settings (where CUCM pushes logs)
    # sftp_host: If empty/None, auto-detects the host's IP at runtime
    sftp_host: Optional[str] = None  # Auto-detect if not set
    sftp_port: int = 2222  # Default to embedded SFTP port
    sftp_username: str = "cucm-collector"
    sftp_password: str = ""  # Never logged
    # Empty base dir - SFTP chroots directly to storage/received
    # Backend creates {job-id}/{node}/ and CUCM uploads there
    sftp_remote_base_dir: str = ""

    # Embedded SFTP Server Settings (Docker mode)
    # When enabled, runs an SFTP server inside the container
    sftp_server_enabled: bool = False  # Set to True in Docker
    sftp_server_host: str = "0.0.0.0"
    sftp_server_port: int = 2222  # Different from 22 to avoid conflicts
    sftp_server_host_key_path: Optional[str] = None  # Auto-generated if not set

    # Storage Settings
    storage_root: Path = Path("./storage")

    # Job Execution Settings
    max_concurrency_per_job: int = 2
    job_command_timeout_sec: int = 600  # 10 minutes per file get command
    job_connect_timeout_sec: int = 30

    # Security Settings
    max_ssh_retries: int = 3  # Maximum SSH connection retry attempts per host
    max_sftp_retries: int = 3  # Maximum SFTP connection retry attempts

    # Profiles
    profiles_path: Path = Path("./profiles.yaml")

    # Input Validation Limits
    max_reltime_minutes: int = 1440  # 24 hours max
    max_nodes_per_job: int = 20  # Max nodes per job
    max_concurrency_limit: int = 5  # Max concurrency setting

    # Retention & Cleanup
    retention_days: int = 7  # Keep jobs for 7 days
    cleanup_enabled: bool = True  # Enable automatic cleanup

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @property
    def transcripts_dir(self) -> Path:
        """Directory for storing job transcripts"""
        return self.storage_root / "transcripts"

    @property
    def jobs_dir(self) -> Path:
        """Directory for storing job metadata JSON files"""
        return self.storage_root / "jobs"

    @property
    def artifacts_dir(self) -> Path:
        """Directory where SFTP receives artifacts"""
        return self.storage_root / "received"

    @property
    def ssh_host_key_path(self) -> Path:
        """Path to SSH host key for embedded SFTP server"""
        if self.sftp_server_host_key_path:
            return Path(self.sftp_server_host_key_path)
        return self.storage_root / "ssh_host_key"

    @property
    def effective_sftp_host(self) -> str:
        """
        Get the effective SFTP host address.

        If sftp_host is set, returns that value.
        Otherwise, auto-detects the host's IP address.

        Returns:
            IP address or hostname for SFTP connections
        """
        if self.sftp_host:
            return self.sftp_host

        # Auto-detect IP
        from app.network_utils import get_host_ip
        detected_ip = get_host_ip()
        if detected_ip:
            logger.info(f"Auto-detected SFTP host IP: {detected_ip}")
            return detected_ip

        # Fallback - this likely won't work for external CUCM
        logger.warning("Could not auto-detect IP, using 127.0.0.1 (may not work!)")
        return "127.0.0.1"

    def ensure_directories(self):
        """Create necessary storage directories if they don't exist"""
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self.transcripts_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get or create the global settings instance.

    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_directories()
    return _settings


def reload_settings() -> Settings:
    """
    Force reload settings from environment.

    Returns:
        New settings instance
    """
    global _settings
    _settings = Settings()
    _settings.ensure_directories()
    return _settings
