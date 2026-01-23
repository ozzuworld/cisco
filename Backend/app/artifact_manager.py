"""Artifact management for secure downloads"""

import hashlib
import json
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, List, Dict, Any
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


def generate_manifest(
    job_id: str,
    profile: str,
    nodes: List[str],
    artifacts: List[Artifact],
    time_mode: Optional[str] = None,
    requested_start_time: Optional[datetime] = None,
    requested_end_time: Optional[datetime] = None,
    requested_reltime_minutes: Optional[int] = None,
    computed_reltime_unit: Optional[str] = None,
    computed_reltime_value: Optional[int] = None,
    computation_timestamp: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Generate manifest.json content for zip archive.

    Args:
        job_id: Job identifier
        profile: Profile name used
        nodes: List of nodes collected from
        artifacts: List of artifacts in the archive
        time_mode: Time mode (relative or range)
        requested_start_time: Requested start time (range mode)
        requested_end_time: Requested end time (range mode)
        requested_reltime_minutes: Requested reltime minutes (relative mode)
        computed_reltime_unit: Computed reltime unit
        computed_reltime_value: Computed reltime value
        computation_timestamp: When reltime was computed

    Returns:
        Dictionary containing manifest data
    """
    manifest = {
        "job_id": job_id,
        "profile": profile,
        "nodes": nodes,
        "artifact_count": len(artifacts),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifacts": []
    }

    # Add time window information if available
    if time_mode:
        manifest["time_mode"] = time_mode

    if requested_start_time:
        manifest["requested_start_time"] = requested_start_time.isoformat()
    if requested_end_time:
        manifest["requested_end_time"] = requested_end_time.isoformat()
    if requested_reltime_minutes is not None:
        manifest["requested_reltime_minutes"] = requested_reltime_minutes

    if computed_reltime_unit:
        manifest["computed_reltime_unit"] = computed_reltime_unit
    if computed_reltime_value is not None:
        manifest["computed_reltime_value"] = computed_reltime_value
    if computation_timestamp:
        manifest["computation_timestamp"] = computation_timestamp.isoformat()

    # Add artifact list with metadata
    for artifact in artifacts:
        artifact_info = {
            "node": artifact.node,
            "filename": artifact.filename,
            "size_bytes": artifact.size_bytes,
            "path_in_zip": f"{artifact.node}/{artifact.filename}"
        }

        # Include time range metadata if available
        if artifact.collection_start_time:
            artifact_info["collection_start_time"] = artifact.collection_start_time.isoformat()
        if artifact.collection_end_time:
            artifact_info["collection_end_time"] = artifact.collection_end_time.isoformat()
        if artifact.reltime_used:
            artifact_info["reltime_used"] = artifact.reltime_used

        manifest["artifacts"].append(artifact_info)

    return manifest


def generate_zip_filename(
    job_id: str,
    profile: str,
    time_mode: Optional[str] = None,
    requested_start_time: Optional[datetime] = None,
    requested_end_time: Optional[datetime] = None,
    requested_reltime_minutes: Optional[int] = None,
    node: Optional[str] = None
) -> str:
    """
    Generate standardized zip filename.

    Format: job_<id>_<profile>_<time-info>[_node_<node>].zip

    Args:
        job_id: Job identifier (truncated to first 8 chars)
        profile: Profile name
        time_mode: Time mode (relative or range)
        requested_start_time: Start time (range mode)
        requested_end_time: End time (range mode)
        requested_reltime_minutes: Reltime minutes (relative mode)
        node: Optional node identifier for single-node zips

    Returns:
        Standardized filename (without .zip extension)
    """
    # Truncate job_id for readability
    short_id = job_id[:8] if len(job_id) > 8 else job_id

    # Build time component
    if time_mode == "range" and requested_start_time and requested_end_time:
        # Format: YYYYMMDD-HHmm_YYYYMMDD-HHmm
        start_str = requested_start_time.strftime("%Y%m%d-%H%M")
        end_str = requested_end_time.strftime("%Y%m%d-%H%M")
        time_part = f"{start_str}_{end_str}"
    elif requested_reltime_minutes is not None:
        # Format: last_XXm
        time_part = f"last_{requested_reltime_minutes}m"
    else:
        # Fallback to timestamp
        time_part = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    # Build filename
    parts = ["job", short_id, profile, time_part]

    if node:
        # Single-node zip
        parts.extend(["node", node.replace(".", "-")])

    return "_".join(parts)


def create_zip_archive(
    artifacts: List[Artifact],
    zip_name: str,
    manifest_data: Optional[Dict[str, Any]] = None
) -> Path:
    """
    Create a zip archive containing specified artifacts.

    Creates a temporary zip file that should be deleted after serving.
    Can include manifest.json with job metadata.

    Args:
        artifacts: List of artifacts to include in zip
        zip_name: Base name for the zip file (without extension)
        manifest_data: Optional manifest data to include as manifest.json

    Returns:
        Path to temporary zip file

    Raises:
        FileNotFoundError: If artifact file doesn't exist
        Exception: If zip creation fails
    """
    settings = get_settings()

    # Create temporary zip file
    # Use delete=False so we can return the path and delete after serving
    temp_fd, temp_path = tempfile.mkstemp(suffix='.zip', prefix=f'{zip_name}_')
    temp_zip_path = Path(temp_path)

    try:
        # Close the file descriptor, we'll use the path with zipfile
        import os
        os.close(temp_fd)

        # Create zip file
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add manifest.json first (if provided)
            if manifest_data:
                manifest_json = json.dumps(manifest_data, indent=2)
                zipf.writestr("manifest.json", manifest_json)
                logger.debug("Added manifest.json to zip")

            # Add artifacts
            for artifact in artifacts:
                # Get full path to artifact
                artifact_path = settings.storage_root / artifact.path

                if not artifact_path.exists():
                    logger.warning(f"Artifact not found, skipping: {artifact_path}")
                    continue

                # Add to zip with a clean archive name
                # Format: node/filename (preserves node organization)
                archive_name = f"{artifact.node}/{artifact.filename}"
                zipf.write(artifact_path, arcname=archive_name)
                logger.debug(f"Added to zip: {archive_name}")

        logger.info(f"Created zip archive with {len(artifacts)} artifacts{' + manifest' if manifest_data else ''}: {temp_zip_path}")
        return temp_zip_path

    except Exception as e:
        # Clean up temp file on error
        if temp_zip_path.exists():
            temp_zip_path.unlink()
        logger.error(f"Failed to create zip archive: {e}")
        raise
