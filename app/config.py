"""Configuration management for CUCM Log Collector"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # SFTP Server Settings (where CUCM pushes logs)
    sftp_host: str
    sftp_port: int = 22
    sftp_username: str
    sftp_password: str  # Never logged
    sftp_remote_base_dir: str = "/cucm-logs"

    # Storage Settings
    storage_root: Path = Path("./storage")

    # Job Execution Settings
    max_concurrency_per_job: int = 2
    job_command_timeout_sec: int = 600  # 10 minutes per file get command
    job_connect_timeout_sec: int = 30

    # Profiles
    profiles_path: Path = Path("./profiles.yaml")

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
