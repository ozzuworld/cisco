"""Artifact management for secure downloads"""

import hashlib
import logging
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from app.config import get_settings
from app.models import Artifact


logger = logging.getLogger(__name__)


def generate_artifact_id(job_id: str, node: str, filename: str) -> str:
    """
    Generate a stable, secure artifact ID.

    Args:
        job_id: Job identifier
        node: Node identifier
        filename: File name

    Returns:
        Stable artifact ID (hash-based)
    """
    # Use SHA256 hash of job_id:node:filename for stable ID
    key = f"{job_id}:{node}:{filename}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def get_artifact_path(artifact_id: str) -> Optional[Path]:
    """
    Get the filesystem path for an artifact by its ID.

    Performs security checks to prevent path traversal.

    Args:
        artifact_id: Artifact identifier

    Returns:
        Path to artifact file if found and valid, None otherwise
    """
    settings = get_settings()

    # Search all jobs for this artifact
    artifacts_root = settings.artifacts_dir

    if not artifacts_root.exists():
        return None

    # Iterate through jobs/nodes to find artifact
    for job_dir in artifacts_root.iterdir():
        if not job_dir.is_dir():
            continue

        for node_dir in job_dir.iterdir():
            if not node_dir.is_dir():
                continue

            for file_path in node_dir.rglob("*"):
                if not file_path.is_file():
                    continue

                # Generate ID for this file
                job_id = job_dir.name
                node = node_dir.name
                filename = file_path.name

                file_artifact_id = generate_artifact_id(job_id, node, filename)

                if file_artifact_id == artifact_id:
                    # Security: Verify path is within artifacts_root
                    try:
                        file_path.resolve().relative_to(artifacts_root.resolve())
                        return file_path
                    except ValueError:
                        # Path traversal attempt
                        logger.warning(f"Path traversal attempt detected: {file_path}")
                        return None

    return None


def get_transcript_path(job_id: str, node: str) -> Optional[Path]:
    """
    Get the filesystem path for a transcript.

    Args:
        job_id: Job identifier
        node: Node identifier

    Returns:
        Path to transcript file if found, None otherwise
    """
    settings = get_settings()
    transcript_file = settings.transcripts_dir / job_id / f"{node}.log"

    if not transcript_file.exists():
        return None

    # Security: Verify path is within transcripts_dir
    try:
        transcript_file.resolve().relative_to(settings.transcripts_dir.resolve())
        return transcript_file
    except ValueError:
        logger.warning(f"Path traversal attempt in transcript: {transcript_file}")
        return None


def list_artifacts_for_job(job_id: str) -> List[Artifact]:
    """
    List all artifacts for a specific job with stable IDs.

    Args:
        job_id: Job identifier

    Returns:
        List of artifacts with artifact_id field populated
    """
    settings = get_settings()
    artifacts = []

    job_artifacts_dir = settings.artifacts_dir / job_id

    if not job_artifacts_dir.exists():
        return artifacts

    for node_dir in job_artifacts_dir.iterdir():
        if not node_dir.is_dir():
            continue

        node = node_dir.name

        for file_path in node_dir.rglob("*"):
            if not file_path.is_file():
                continue

            try:
                stat = file_path.stat()
                artifact_id = generate_artifact_id(job_id, node, file_path.name)

                artifact = Artifact(
                    node=node,
                    path=str(file_path.relative_to(settings.storage_root)),
                    filename=file_path.name,
                    size_bytes=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_mtime),
                    artifact_id=artifact_id  # type: ignore # Will be added to model
                )
                artifacts.append(artifact)
            except Exception as e:
                logger.error(f"Error processing artifact {file_path}: {e}")
                continue

    return artifacts
