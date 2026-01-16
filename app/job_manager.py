"""Job management and execution for CUCM log collection"""

import asyncio
import json
import logging
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import asyncssh

from app.config import get_settings
from app.models import (
    JobStatus,
    NodeStatus,
    NodeJobStatus,
    Artifact,
    CreateJobRequest,
    CollectionOptions,
    FailureClassification
)
from app.profiles import CollectionProfile, get_profile_catalog
from app.prompt_responder import PromptResponder, build_file_get_command, compute_reltime_from_range
from app.ssh_client import CUCMSSHClient, CUCMSSHClientError, CUCMAuthError, CUCMConnectionError, CUCMCommandTimeoutError, CUCMSFTPTimeoutError
from app.artifact_manager import list_artifacts_for_job


logger = logging.getLogger(__name__)

# Per-job write locks to prevent concurrent modifications
_job_write_locks: Dict[str, threading.Lock] = {}
_job_write_locks_lock = threading.Lock()  # Lock for the locks dict itself


def _get_job_write_lock(job_id: str) -> threading.Lock:
    """
    Get or create a write lock for a specific job.

    Args:
        job_id: Job identifier

    Returns:
        Threading lock for this job
    """
    with _job_write_locks_lock:
        if job_id not in _job_write_locks:
            _job_write_locks[job_id] = threading.Lock()
        return _job_write_locks[job_id]


def _classify_failure(exception: Exception, error_context: str = "") -> tuple[FailureClassification, str]:
    """
    Classify failure type and generate actionable error message.

    Args:
        exception: The exception that occurred
        error_context: Additional context (e.g., from transcript)

    Returns:
        Tuple of (classification, error_message)
    """
    # Check for authentication failures
    if isinstance(exception, CUCMAuthError):
        return (
            FailureClassification.AUTH_FAILED,
            f"Authentication failed: {str(exception)}. Verify username and password are correct."
        )

    # Check for SSH connection timeout
    if isinstance(exception, CUCMConnectionError):
        if "timeout" in str(exception).lower():
            return (
                FailureClassification.SSH_TIMEOUT,
                f"SSH connection timeout: {str(exception)}. Check network connectivity and firewall rules."
            )
        else:
            return (
                FailureClassification.SSH_TIMEOUT,
                f"SSH connection failed: {str(exception)}. Check network connectivity and node availability."
            )

    # Check for SFTP timeout
    if isinstance(exception, CUCMSFTPTimeoutError):
        return (
            FailureClassification.SFTP_TIMEOUT,
            f"{str(exception)}. Check SFTP server availability and network bandwidth."
        )

    # Check for command timeout
    if isinstance(exception, (CUCMCommandTimeoutError, asyncio.TimeoutError)):
        return (
            FailureClassification.SFTP_TIMEOUT,
            f"Command execution timeout: {str(exception)}. The operation took too long to complete."
        )

    # Check for CUCM command errors (no files matched, etc.)
    if "No files matched filter criteria" in error_context or "No artifacts collected" in error_context:
        return (
            FailureClassification.CUCM_COMMAND_ERROR,
            "No files matched filter criteria. Check path pattern, reltime window, and verify logs exist for the time range."
        )

    # Default: UNKNOWN
    error_type = type(exception).__name__
    return (
        FailureClassification.UNKNOWN,
        f"{error_type}: {str(exception)}"
    )


class Job:
    """
    Represents a log collection job with full state management.

    Handles persistence to disk as JSON and tracks status of all nodes.
    """

    def __init__(
        self,
        job_id: str,
        publisher_host: str,
        port: int,
        username: str,
        password: str,  # Never persisted or logged
        nodes: List[str],
        profile: CollectionProfile,
        options: Optional[CollectionOptions] = None,
    ):
        """
        Initialize a new job.

        Args:
            job_id: Unique job identifier
            publisher_host: CUCM publisher host
            port: SSH port
            username: OS Admin username
            password: OS Admin password (not persisted)
            nodes: List of nodes to collect from
            profile: Collection profile
            options: Optional overrides for profile defaults
        """
        self.job_id = job_id
        self.publisher_host = publisher_host
        self.port = port
        self.username = username
        self.password = password  # NEVER persist this
        self.nodes_list = nodes
        self.profile = profile
        self.options = options or CollectionOptions()

        # Job state
        self.status = JobStatus.QUEUED
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.cancelled = False
        self.last_updated_at = datetime.utcnow()  # track last update

        # Time window configuration (set during execution)
        self.requested_start_time: Optional[datetime] = None
        self.requested_end_time: Optional[datetime] = None
        self.requested_reltime_minutes: Optional[int] = None
        self.computed_reltime_unit: Optional[str] = None
        self.computed_reltime_value: Optional[int] = None
        self.computation_timestamp: Optional[datetime] = None  # Server "now" used for calculation

        # Debug level configuration
        self.debug_level: Optional[str] = None  # basic, detailed, verbose

        # Node states
        self.node_statuses: Dict[str, NodeJobStatus] = {}
        for node in nodes:
            self.node_statuses[node] = NodeJobStatus(
                node=node,
                status=NodeStatus.PENDING,
                last_updated_at=datetime.utcnow()
            )

    def to_dict(self) -> dict:
        """
        Convert job to dictionary (for JSON serialization).

        Does NOT include password.

        Returns:
            Dictionary representation of job
        """
        return {
            "job_id": self.job_id,
            "publisher_host": self.publisher_host,
            "port": self.port,
            "username": self.username,
            # password is intentionally excluded
            "nodes": self.nodes_list,
            "profile": self.profile.name,
            "status": self.status.value,
            "cancelled": self.cancelled,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "last_updated_at": self.last_updated_at.isoformat() if self.last_updated_at else None,
            # Time window configuration
            "requested_start_time": self.requested_start_time.isoformat() if self.requested_start_time else None,
            "requested_end_time": self.requested_end_time.isoformat() if self.requested_end_time else None,
            "requested_reltime_minutes": self.requested_reltime_minutes,
            "computed_reltime_unit": self.computed_reltime_unit,
            "computed_reltime_value": self.computed_reltime_value,
            "computation_timestamp": self.computation_timestamp.isoformat() if self.computation_timestamp else None,
            "debug_level": self.debug_level,
            "node_statuses": {
                node: status.model_dump(mode='json')  # mode='json' serializes datetime properly
                for node, status in self.node_statuses.items()
            }
        }

    @classmethod
    def from_dict(cls, data: dict, profile_catalog) -> 'Job':
        """
        Reconstruct a Job from persisted JSON data.

        Note: Password is not persisted, so reconstructed jobs cannot be re-executed.
        They are used for status tracking only.

        Args:
            data: Job data from JSON
            profile_catalog: ProfileCatalog to resolve profile name

        Returns:
            Reconstructed Job instance
        """
        # Get profile from catalog
        profile = profile_catalog.get_profile(data["profile"])
        if not profile:
            raise ValueError(f"Profile not found: {data['profile']}")

        # Create job with empty password (can't re-execute)
        job = cls(
            job_id=data["job_id"],
            publisher_host=data["publisher_host"],
            port=data["port"],
            username=data["username"],
            password="",  # Password not persisted
            nodes=data["nodes"],
            profile=profile,
            options=None  # Could be persisted if needed
        )

        # Restore state
        job.status = JobStatus(data["status"])
        job.cancelled = data.get("cancelled", False)
        job.created_at = datetime.fromisoformat(data["created_at"])
        job.started_at = datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None
        job.completed_at = datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None
        job.last_updated_at = datetime.fromisoformat(data["last_updated_at"]) if data.get("last_updated_at") else job.created_at

        # Restore time window configuration
        job.requested_start_time = datetime.fromisoformat(data["requested_start_time"]) if data.get("requested_start_time") else None
        job.requested_end_time = datetime.fromisoformat(data["requested_end_time"]) if data.get("requested_end_time") else None
        job.requested_reltime_minutes = data.get("requested_reltime_minutes")
        job.computed_reltime_unit = data.get("computed_reltime_unit")
        job.computed_reltime_value = data.get("computed_reltime_value")
        job.computation_timestamp = datetime.fromisoformat(data["computation_timestamp"]) if data.get("computation_timestamp") else None

        # Restore debug level
        job.debug_level = data.get("debug_level")

        # Restore node statuses
        job.node_statuses = {}
        for node, status_data in data["node_statuses"].items():
            job.node_statuses[node] = NodeJobStatus(**status_data)

        return job

    def save(self):
        """
        Persist job state to disk atomically.

        Uses atomic write (temp file + fsync + rename) to prevent corruption if process
        crashes during write.

        Thread-safe: Uses per-job write lock to prevent concurrent modifications.
        """
        # Acquire per-job write lock
        lock = _get_job_write_lock(self.job_id)
        with lock:
            settings = get_settings()
            job_file = settings.jobs_dir / f"{self.job_id}.json"
            temp_file = settings.jobs_dir / f"{self.job_id}.json.tmp"

            try:
                # Ensure jobs directory exists
                settings.jobs_dir.mkdir(parents=True, exist_ok=True)

                # Write to temp file first
                with open(temp_file, 'w') as f:
                    json.dump(self.to_dict(), f, indent=2)
                    # Flush and fsync to ensure data is written to disk
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename (overwrites existing file atomically)
                os.replace(temp_file, job_file)

                logger.debug(f"Saved job {self.job_id} to {job_file}")
            except Exception as e:
                logger.error(f"Failed to save job {self.job_id}: {e}")
                # Clean up temp file if it exists
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except Exception:
                        pass

    def update_status(self, new_status: JobStatus):
        """Update job status and save"""
        self.status = new_status
        self.last_updated_at = datetime.utcnow()
        if new_status == JobStatus.RUNNING and not self.started_at:
            self.started_at = datetime.utcnow()
        elif new_status in [JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.PARTIAL, JobStatus.CANCELLED]:
            self.completed_at = datetime.utcnow()
        self.save()

    def update_node_status(
        self,
        node: str,
        status: NodeStatus,
        error: Optional[str] = None,
        failure_classification: Optional[FailureClassification] = None,
        step: Optional[str] = None,
        message: Optional[str] = None,
        percent: Optional[int] = None
    ):
        """Update status for a specific node"""
        if node in self.node_statuses:
            now = datetime.utcnow()
            self.node_statuses[node].status = status
            self.node_statuses[node].last_updated_at = now
            self.last_updated_at = now  # update job last_updated too

            if error:
                self.node_statuses[node].error = error
            if failure_classification:
                self.node_statuses[node].failure_classification = failure_classification
            if step:
                self.node_statuses[node].step = step
            if message:
                self.node_statuses[node].message = message
            if percent is not None:
                self.node_statuses[node].percent = percent

            if status == NodeStatus.RUNNING:
                self.node_statuses[node].started_at = now
            elif status in [NodeStatus.SUCCEEDED, NodeStatus.FAILED, NodeStatus.CANCELLED]:
                self.node_statuses[node].completed_at = now
                self.node_statuses[node].percent = 100  # mark complete
            self.save()

    def get_progress_metrics(self) -> dict:
        """
        Calculate real-time progress metrics.

        Returns:
            Dictionary with progress metrics
        """
        total = len(self.nodes_list)
        succeeded = sum(1 for ns in self.node_statuses.values() if ns.status == NodeStatus.SUCCEEDED)
        failed = sum(1 for ns in self.node_statuses.values() if ns.status == NodeStatus.FAILED)
        running = sum(1 for ns in self.node_statuses.values() if ns.status == NodeStatus.RUNNING)
        completed = succeeded + failed + sum(1 for ns in self.node_statuses.values() if ns.status == NodeStatus.CANCELLED)

        # Calculate percent_complete (avoid division by zero)
        percent_complete = int((completed / total) * 100) if total > 0 else 0

        # Find last updated timestamp from all nodes
        node_updates = [ns.last_updated_at for ns in self.node_statuses.values() if ns.last_updated_at]
        last_node_update = max(node_updates) if node_updates else None

        # Use the most recent of job last_updated or last node update
        last_updated = max(
            filter(None, [self.last_updated_at, last_node_update]),
            default=self.created_at
        )

        return {
            "total_nodes": total,
            "completed_nodes": completed,
            "succeeded_nodes": succeeded,
            "failed_nodes": failed,
            "running_nodes": running,
            "percent_complete": percent_complete,
            "last_updated_at": last_updated
        }


class JobManager:
    """
    Manages job lifecycle: creation, execution, status tracking.

    Singleton pattern - one instance per application.
    """

    def __init__(self):
        """Initialize job manager"""
        self.jobs: Dict[str, Job] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.node_tasks: Dict[str, Dict[str, asyncio.Task]] = {}
        self.settings = get_settings()
        self._load_existing_jobs()

    def _load_existing_jobs(self):
        """
        Load existing jobs from disk on startup.

        Corrupted job files are moved to _corrupt/ directory for safe recovery.
        """
        jobs_dir = self.settings.jobs_dir
        if not jobs_dir.exists():
            logger.info("Jobs directory does not exist yet - no jobs to load")
            return

        logger.info(f"Loading existing jobs from {jobs_dir}")
        profile_catalog = get_profile_catalog()
        loaded_count = 0
        corrupted_count = 0

        # Ensure _corrupt directory exists for quarantining bad files
        corrupt_dir = jobs_dir / "_corrupt"
        corrupt_dir.mkdir(parents=True, exist_ok=True)

        for job_file in sorted(jobs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(job_file, 'r') as f:
                    data = json.load(f)

                # Reconstruct job (without password - can't execute, just status tracking)
                job = Job.from_dict(data, profile_catalog)
                self.jobs[job.job_id] = job
                loaded_count += 1
                logger.debug(f"Loaded job {job.job_id} (status: {job.status.value})")
            except Exception as e:
                # Move corrupted file to _corrupt/ directory
                corrupted_count += 1
                corrupt_file = corrupt_dir / job_file.name
                try:
                    # If file with same name exists in _corrupt, append timestamp
                    if corrupt_file.exists():
                        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                        corrupt_file = corrupt_dir / f"{job_file.stem}_{timestamp}.json"

                    job_file.rename(corrupt_file)
                    logger.warning(
                        f"Corrupted job file moved to {corrupt_file.relative_to(self.settings.storage_root)}: {e}"
                    )
                except Exception as move_error:
                    logger.error(f"Failed to move corrupted file {job_file}: {move_error}")

        logger.info(
            f"Loaded {loaded_count} jobs from disk "
            f"({corrupted_count} corrupted files quarantined)"
        )

    def create_job(self, request: CreateJobRequest) -> Job:
        """
        Create a new log collection job.

        Args:
            request: Job creation request

        Returns:
            Created Job instance

        Raises:
            ValueError: If profile not found
        """
        # Get profile
        catalog = get_profile_catalog()
        profile = catalog.get_profile(request.profile)
        if not profile:
            raise ValueError(f"Profile not found: {request.profile}")

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Create job
        job = Job(
            job_id=job_id,
            publisher_host=request.publisher_host,
            port=request.port,
            username=request.username,
            password=request.password,
            nodes=request.nodes,
            profile=profile,
            options=request.options
        )

        # Save to disk
        job.save()

        # Store in memory
        self.jobs[job_id] = job

        logger.info(f"Created job {job_id} with profile {profile.name} for {len(request.nodes)} nodes")

        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        """
        Get a job by ID.

        Jobs are loaded from disk at startup, so all jobs are in memory.

        Args:
            job_id: Job identifier

        Returns:
            Job if found, None otherwise
        """
        return self.jobs.get(job_id)

    def list_jobs(self, limit: int = 20) -> List[Job]:
        """
        List recent jobs.

        Args:
            limit: Maximum number of jobs to return

        Returns:
            List of recent jobs
        """
        # For now, just return from memory
        # In production, you'd want to sort by created_at
        jobs = list(self.jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running job (best-effort).

        Immediately finalizes node and job status for fast visibility.

        Args:
            job_id: Job to cancel

        Returns:
            True if job was found and cancellation initiated, False otherwise
        """
        job = self.get_job(job_id)
        if not job:
            logger.warning(f"Cannot cancel job {job_id}: not found")
            return False

        # Mark job as cancelled
        job.cancelled = True

      
        if job_id in self.running_tasks:
            task = self.running_tasks[job_id]
            if not task.done():
                task.cancel()
                logger.info(f"Job {job_id} main task cancelled")

      
        if job_id in self.node_tasks:
            for node, task in self.node_tasks[job_id].items():
                if not task.done():
                    task.cancel()
                    logger.info(f"Job {job_id} node {node} task cancelled")

      
        # This ensures UI sees cancellation immediately
        for node, node_status in job.node_statuses.items():
            if node_status.status in [NodeStatus.PENDING, NodeStatus.QUEUED, NodeStatus.RUNNING]:
                job.update_node_status(node, NodeStatus.CANCELLED)
                logger.info(f"Job {job_id} node {node} marked CANCELLED")

      
        node_statuses = [ns.status for ns in job.node_statuses.values()]
        if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
            job.update_status(JobStatus.PARTIAL)
        else:
            job.update_status(JobStatus.CANCELLED)

        job.save()
        logger.info(f"Job {job_id} cancelled - status: {job.status}")
        return True

    def retry_failed_nodes(self, job_id: str) -> Optional[List[str]]:
        """
        Retry only the failed nodes in a job.

        Reuses the same job configuration (profile, time window, credentials)
        but only re-executes nodes that have FAILED status.

        Args:
            job_id: Job to retry failed nodes for

        Returns:
            List of node names being retried, or None if job not found
        """
        job = self.get_job(job_id)
        if not job:
            logger.warning(f"Cannot retry job {job_id}: not found")
            return None

        # Find all failed nodes
        failed_nodes = [
            node for node, status in job.node_statuses.items()
            if status.status == NodeStatus.FAILED
        ]

        if not failed_nodes:
            logger.info(f"Job {job_id} has no failed nodes to retry")
            return []

        logger.info(f"Job {job_id}: Retrying {len(failed_nodes)} failed nodes: {failed_nodes}")

        # Update retry tracking for each failed node
        for node in failed_nodes:
            node_status = job.node_statuses[node]
            node_status.retry_count += 1
            node_status.current_attempt += 1
            # Reset node to PENDING for retry
            job.update_node_status(
                node,
                NodeStatus.PENDING,
                step="queued",
                message=f"Queued for retry (attempt {node_status.current_attempt})",
                percent=0
            )
            # Preserve retry tracking
            job.node_statuses[node].retry_count = node_status.retry_count
            job.node_statuses[node].current_attempt = node_status.current_attempt
            logger.info(
                f"Job {job_id} node {node}: retry_count={node_status.retry_count}, "
                f"attempt={node_status.current_attempt}"
            )

        # Update job status to RUNNING (it will be re-determined after retry completes)
        job.update_status(JobStatus.RUNNING)
        job.save()

        # Launch async task to retry these nodes
        # Create a new task for this retry operation
        task = asyncio.create_task(self._retry_nodes_async(job, failed_nodes))
        # Don't store in running_tasks since this is a partial retry
        # Just let it run in the background

        return failed_nodes

    async def _retry_nodes_async(self, job: Job, nodes: List[str]):
        """
        Asynchronously retry a list of nodes for a job.

        Args:
            job: Job to retry nodes for
            nodes: List of node names to retry
        """
        job_id = job.job_id
        logger.info(f"[Job {job_id}] Starting retry for {len(nodes)} nodes")

        try:
            # Process nodes with concurrency limit (same as execute_job)
            semaphore = asyncio.Semaphore(self.settings.max_concurrency_per_job)

            async def process_with_semaphore(node):
                # Check cancellation before processing
                if job.cancelled:
                    job.update_node_status(node, NodeStatus.CANCELLED)
                    return

                # Set node to QUEUED before waiting for semaphore
                job.update_node_status(
                    node,
                    NodeStatus.QUEUED,
                    step="queued",
                    message="Waiting for execution slot",
                    percent=0
                )

                async with semaphore:
                    # Check cancellation after acquiring semaphore
                    if job.cancelled:
                        job.update_node_status(node, NodeStatus.CANCELLED)
                        return
                    await self._process_node(job, node)

            # Track per-node tasks for potential cancellation
            if job_id not in self.node_tasks:
                self.node_tasks[job_id] = {}

            tasks = []
            for node in nodes:
                task = asyncio.create_task(process_with_semaphore(node))
                self.node_tasks[job_id][node] = task
                tasks.append(task)

            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                # Cancel all remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()
                # Wait for all tasks to finish cancelling
                await asyncio.gather(*tasks, return_exceptions=True)
                raise

            # Determine final job status after retry
            node_statuses = [ns.status for ns in job.node_statuses.values()]
            if job.cancelled:
                # Check if any nodes succeeded before cancellation
                if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
                    job.update_status(JobStatus.PARTIAL)
                else:
                    job.update_status(JobStatus.CANCELLED)
            elif all(s == NodeStatus.SUCCEEDED for s in node_statuses):
                job.update_status(JobStatus.SUCCEEDED)
            elif all(s == NodeStatus.FAILED for s in node_statuses):
                job.update_status(JobStatus.FAILED)
            else:
                job.update_status(JobStatus.PARTIAL)

            logger.info(f"Job {job_id} retry completed with status {job.status}")

        except asyncio.CancelledError:
            logger.info(f"Job {job_id} retry was cancelled")
            job.cancelled = True
            # Mark any non-completed nodes as cancelled
            for node in nodes:
                ns = job.node_statuses[node]
                if ns.status in [NodeStatus.PENDING, NodeStatus.QUEUED, NodeStatus.RUNNING]:
                    job.update_node_status(node, NodeStatus.CANCELLED)

            # Determine final status based on what completed
            node_statuses = [ns.status for ns in job.node_statuses.values()]
            if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
                job.update_status(JobStatus.PARTIAL)
            else:
                job.update_status(JobStatus.CANCELLED)
            job.save()

        except Exception as e:
            logger.error(f"Job {job_id} retry failed with exception: {e}")
            job.update_status(JobStatus.FAILED)
            job.save()

    async def execute_job(self, job_id: str):
        """
        Execute a job asynchronously.

        Args:
            job_id: Job to execute
        """
        job = self.get_job(job_id)
        if not job:
            logger.error(f"Job not found: {job_id}")
            return

        # Check if already cancelled
        if job.cancelled:
            logger.info(f"Job {job_id} was cancelled before execution started")
            job.update_status(JobStatus.CANCELLED)
            return

        logger.info(f"Starting execution of job {job_id}")
        job.update_status(JobStatus.RUNNING)

        # Populate time window configuration for auditability
        time_mode = job.options.time_mode if job.options.time_mode else "relative"
        computation_now = datetime.utcnow()

        if time_mode == "range":
            # Absolute time range mode
            job.requested_start_time = job.options.start_time
            job.requested_end_time = job.options.end_time
            job.computation_timestamp = computation_now

            # Compute reltime from range
            reltime_unit, reltime_value = compute_reltime_from_range(
                job.options.start_time,
                job.options.end_time
            )
            job.computed_reltime_unit = reltime_unit
            job.computed_reltime_value = reltime_value

            logger.info(
                f"[Job {job_id}] Time range mode - "
                f"start={job.requested_start_time}, end={job.requested_end_time}, "
                f"computed={reltime_unit} {reltime_value} at {computation_now}"
            )
        else:
            # Relative time mode (existing behavior)
            job.requested_reltime_minutes = job.options.reltime_minutes or job.profile.reltime_minutes
            job.computed_reltime_unit = "minutes"
            job.computed_reltime_value = job.requested_reltime_minutes
            job.computation_timestamp = computation_now

            logger.info(
                f"[Job {job_id}] Relative time mode - "
                f"{job.requested_reltime_minutes} minutes at {computation_now}"
            )

        # Set debug level from options (default to 'basic' if not specified)
        if job.options and job.options.debug_level:
            job.debug_level = job.options.debug_level.value
        else:
            job.debug_level = "basic"  # Default debug level

        logger.info(f"[Job {job_id}] Debug level: {job.debug_level}")

        # Save job with time window configuration
        job.save()

        try:
            # Process nodes with concurrency limit
            semaphore = asyncio.Semaphore(self.settings.max_concurrency_per_job)

            async def process_with_semaphore(node):
                # Check cancellation before processing
                if job.cancelled:
                    job.update_node_status(node, NodeStatus.CANCELLED)
                    return

                # Set node to QUEUED before waiting for semaphore
                job.update_node_status(
                    node,
                    NodeStatus.QUEUED,
                    step="queued",
                    message="Waiting for execution slot",
                    percent=0
                )

                async with semaphore:
                    # Check cancellation after acquiring semaphore
                    if job.cancelled:
                        job.update_node_status(node, NodeStatus.CANCELLED)
                        return
                    await self._process_node(job, node)

          
            self.node_tasks[job_id] = {}
            tasks = []
            for node in job.nodes_list:
                task = asyncio.create_task(process_with_semaphore(node))
                self.node_tasks[job_id][node] = task
                tasks.append(task)

            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                # Cancel all remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()
                # Wait for all tasks to finish cancelling
                await asyncio.gather(*tasks, return_exceptions=True)
                raise  # Re-raise to be caught by outer handler

            # Determine final job status
            node_statuses = [ns.status for ns in job.node_statuses.values()]
            if job.cancelled:
                # Check if any nodes succeeded before cancellation
                if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
                    job.update_status(JobStatus.PARTIAL)
                else:
                    job.update_status(JobStatus.CANCELLED)
            elif all(s == NodeStatus.SUCCEEDED for s in node_statuses):
                job.update_status(JobStatus.SUCCEEDED)
            elif all(s == NodeStatus.FAILED for s in node_statuses):
                job.update_status(JobStatus.FAILED)
            else:
                job.update_status(JobStatus.PARTIAL)

            logger.info(f"Job {job_id} completed with status {job.status}")

        except asyncio.CancelledError:
            logger.info(f"Job {job_id} was cancelled")
            job.cancelled = True
          
            for node, ns in job.node_statuses.items():
                if ns.status in [NodeStatus.PENDING, NodeStatus.QUEUED, NodeStatus.RUNNING]:
                    job.update_node_status(node, NodeStatus.CANCELLED)

            # Determine final status based on what completed
            node_statuses = [ns.status for ns in job.node_statuses.values()]
            if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
                job.update_status(JobStatus.PARTIAL)
            else:
                job.update_status(JobStatus.CANCELLED)
            raise  # Re-raise to properly handle task cancellation

        except Exception as e:
            logger.exception(f"Unexpected error in job {job_id}: {e}")
            job.update_status(JobStatus.FAILED)

        finally:
          
            if job_id in self.running_tasks:
                del self.running_tasks[job_id]
            if job_id in self.node_tasks:
                del self.node_tasks[job_id]

    async def _ensure_sftp_directory(self, directory_path: str) -> None:
        """
        Pre-create directory on SFTP server before CUCM tries to push files.

        CUCM's file get activelog command does NOT create nested directories.
        If the directory doesn't exist, CUCM fails with "Invalid download directory specified."

        Args:
            directory_path: Full path to create on SFTP server (e.g., "/incoming/job-id/node")

        Raises:
            Exception: If directory creation fails
        """
        logger.info(f"Pre-creating SFTP directory: {directory_path} on {self.settings.effective_sftp_host}:{self.settings.sftp_port}")

        try:
            async with asyncssh.connect(
                host=self.settings.effective_sftp_host,
                port=self.settings.sftp_port,
                username=self.settings.sftp_username,
                password=self.settings.sftp_password,
                known_hosts=None,  # Don't use known_hosts file
                server_host_key_algs=None  # Accept any host key algorithm (CUCM compatibility)
            ) as conn:
                logger.debug(f"Connected to SFTP server {self.settings.effective_sftp_host}")

                # Use SFTP subsystem to create directory
                async with conn.start_sftp_client() as sftp:
                    # FIX: Handle relative paths correctly (don't add leading /)
                    # Create directory with parents (like mkdir -p)
                    is_absolute = directory_path.startswith('/')
                    parts = [p for p in directory_path.split('/') if p]

                    for i, part in enumerate(parts):
                        if i == 0:
                            # First part: use as-is for relative, with / for absolute
                            current_path = ('/' + part) if is_absolute else part
                        else:
                            # Subsequent parts: always append with /
                            current_path += '/' + part

                        try:
                            await sftp.mkdir(current_path)
                            # Set permissions so SFTP user can write
                            await sftp.chmod(current_path, 0o775)
                            logger.debug(f"Created directory: {current_path} (mode=775)")
                        except asyncssh.sftp.SFTPFailure as e:
                            # FIX: install-sftp.sh creates base 'incoming' dir - treat failures as "already exists"
                            # Some SFTP servers return FX_FAILURE (code=4) instead of FX_FILE_ALREADY_EXISTS
                            if e.code == asyncssh.sftp.FX_FILE_ALREADY_EXISTS:
                                logger.debug(f"Directory already exists: {current_path}")
                            elif e.code == 4 and i == 0:  # FX_FAILURE on base dir = assume it exists
                                logger.debug(f"Base directory exists (install-sftp.sh): {current_path}")
                            elif e.code == asyncssh.sftp.FX_PERMISSION_DENIED:
                                error_msg = f"Permission denied creating {current_path} (SFTP user: {self.settings.sftp_username})"
                                logger.error(error_msg)
                                raise Exception(error_msg) from e
                            else:
                                error_msg = f"SFTP error creating {current_path}: code={e.code}, reason={e.reason}"
                                logger.error(error_msg)
                                raise Exception(error_msg) from e

                logger.info(f"SFTP directory ready: {directory_path}")

        except asyncssh.Error as e:
            error_msg = f"SSH/SFTP connection failed to {self.settings.effective_sftp_host}:{self.settings.sftp_port}: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg) from e
        except Exception as e:
            if "Permission denied" in str(e) or "SFTP error" in str(e):
                # Already formatted error message - re-raise as is
                raise
            error_msg = f"Failed to create SFTP directory {directory_path}: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg) from e

    async def _process_node(self, job: Job, node: str):
        """
        Process log collection for a single node.

        Args:
            job: Parent job
            node: Node to process
        """
      
        # This prevents race where cancel() is called but node still becomes RUNNING
        if job.cancelled:
            logger.info(f"[Job {job.job_id}][{node}] Cancelled before start")
            job.update_node_status(node, NodeStatus.CANCELLED)
            return

        logger.info(f"[Job {job.job_id}] Processing node: {node}")
        # Set initial step and progress
        job.update_node_status(
            node,
            NodeStatus.RUNNING,
            step="initializing",
            message="Preparing to collect logs",
            percent=0
        )

        # FIX: Prepare transcript file and set path immediately
        transcript_path = self.settings.transcripts_dir / job.job_id / f"{node}.log"
        transcript_path.parent.mkdir(parents=True, exist_ok=True)

        # Set transcript path immediately so we can see progress even if job hangs
        rel_transcript_path = str(transcript_path.relative_to(self.settings.storage_root))
        job.node_statuses[node].transcript_path = rel_transcript_path
        job.save()

        transcript_lines = []

        try:
            # FIX: Open transcript file for incremental writing
            transcript_file = open(transcript_path, 'w')

          
            if job.cancelled:
                logger.info(f"[Job {job.job_id}][{node}] Cancelled before connect")
                transcript_file.write("\n[CANCELLED]\n")
                transcript_file.close()
                job.update_node_status(node, NodeStatus.CANCELLED)
                return

            # Update progress
            job.update_node_status(
                node,
                NodeStatus.RUNNING,
                step="preparing",
                message="Creating directories for artifacts",
                percent=10
            )

            # Use attempt-specific directory for artifacts
            # Format: {job_id}/{node}/attempt_{N}
            node_status = job.node_statuses[node]
            attempt_num = node_status.current_attempt
            attempt_dir = f"attempt_{attempt_num}"

            # Prepare SFTP directory for this node
            # If base_dir is empty, SFTP chroots directly to storage/received
            if self.settings.sftp_remote_base_dir:
                sftp_directory = f"{self.settings.sftp_remote_base_dir}/{job.job_id}/{node}/{attempt_dir}"
            else:
                sftp_directory = f"{job.job_id}/{node}/{attempt_dir}"

            # FIX: Pre-create directory for CUCM to upload to
            # CUCM's file get activelog does NOT create directories
            # With bind mount, create directories locally - they appear on SFTP automatically
            try:
                local_dir = self.settings.artifacts_dir / job.job_id / node / attempt_dir
                local_dir.mkdir(parents=True, exist_ok=True)
                # Set permissions so SFTP user can write (via bind mount)
                local_dir.chmod(0o777)  # World-writable for SFTP user access
                logger.info(f"Created directory for SFTP uploads: {local_dir}")
                transcript_file.write(f"SFTP directory ready: {sftp_directory}\n")
                transcript_file.flush()
            except Exception as e:
                error_msg = f"Failed to create directory for job {job.job_id} node {node}: {e}"
                logger.error(f"[Job {job.job_id}][{node}] {error_msg}")
                transcript_file.write(f"\nERROR: {error_msg}\n")
                transcript_file.flush()
                job.update_node_status(node, NodeStatus.FAILED, error=error_msg)
                return

            # Update progress - connecting
            job.update_node_status(
                node,
                NodeStatus.RUNNING,
                step="connecting",
                message=f"Connecting to {node}",
                percent=20
            )

            # Connect to CUCM
            async with CUCMSSHClient(
                host=node,
                port=job.port,
                username=job.username,
                password=job.password,
                connect_timeout=float(self.settings.job_connect_timeout_sec)
            ) as client:

                transcript_file.write(f"Connected to {node}\n")
                transcript_file.flush()
                transcript_lines.append(f"Connected to {node}\n")

              
                if job.cancelled:
                    logger.info(f"[Job {job.job_id}][{node}] Cancelled after connect")
                    transcript_file.write("\n[CANCELLED]\n")
                    transcript_file.flush()
                    transcript_lines.append("\n[CANCELLED]\n")
                    job.update_node_status(node, NodeStatus.CANCELLED)
                    return

                # Update progress - collecting
                job.update_node_status(
                    node,
                    NodeStatus.RUNNING,
                    step="collecting",
                    message="Collecting log files",
                    percent=40
                )

                # Process each path in the profile
                for path in job.profile.paths:
                  
                    if job.cancelled:
                        logger.info(f"[Job {job.job_id}][{node}] Cancelled during path processing")
                        msg = f"\n[CANCELLED before processing {path}]\n"
                        transcript_file.write(msg)
                        transcript_file.flush()
                        transcript_lines.append(msg)
                        job.update_node_status(node, NodeStatus.CANCELLED)
                        return

                    #  Use pre-computed time window from job
                    # (computed once per job in execute_job for consistency)
                    reltime_unit = job.computed_reltime_unit
                    reltime_value = job.computed_reltime_value

                    # Variables to store time range metadata for artifacts
                    collection_start_time = job.requested_start_time
                    collection_end_time = job.requested_end_time
                    reltime_used_str = f"{reltime_unit} {reltime_value}"

                    logger.info(
                        f"[Job {job.job_id}][{node}] Using computed reltime: {reltime_used_str}"
                    )

                    # Determine other options (use overrides if provided)
                    compress = job.options.compress if job.options.compress is not None else job.profile.compress
                    recurs = job.options.recurs if job.options.recurs is not None else job.profile.recurs
                    match = job.options.match or job.profile.match

                    # Build command with dynamic time unit
                    command = build_file_get_command(
                        path=path,
                        reltime_value=reltime_value,
                        reltime_unit=reltime_unit,
                        compress=compress,
                        recurs=recurs,
                        match=match
                    )

                    # Write command info to transcript
                    header = f"\n{'='*60}\nCollecting: {path}\nCommand: {command}\n{'='*60}\n\n"
                    transcript_file.write(header)
                    transcript_file.flush()
                    transcript_lines.append(header)

                    logger.info(f"[Job {job.job_id}][{node}] Executing: {command}")

                    # Get stdin/stdout from the session
                    if not client._session:
                        raise CUCMSSHClientError("No active session")

                    # Send command
                    client._session.stdin.write(command + '\n')
                    await client._session.stdin.drain()

                    # Create prompt responder
                    responder = PromptResponder(
                        sftp_host=self.settings.effective_sftp_host,
                        sftp_port=self.settings.sftp_port,
                        sftp_username=self.settings.sftp_username,
                        sftp_password=self.settings.sftp_password,
                        sftp_directory=sftp_directory
                    )

                    # FIX: Respond to prompts with incremental transcript writing
                    output = await responder.respond_to_prompts(
                        stdin=client._session.stdin,
                        stdout=client._session.stdout,
                        timeout=float(self.settings.job_command_timeout_sec),
                        prompt=client.prompt,
                        transcript_file=transcript_file
                    )

                    transcript_lines.append(output)
                    transcript_file.write("\n")
                    transcript_file.flush()

            #  Check if CUCM reported "No files matched filter criteria"
            full_transcript = ''.join(transcript_lines)
            if "No files matched filter criteria" in full_transcript:
                error_msg = "No files matched filter criteria. Check path pattern, reltime window, and verify logs exist for the time range."
                logger.warning(f"[Job {job.job_id}][{node}] {error_msg}")
                job.update_node_status(
                    node,
                    NodeStatus.FAILED,
                    error=error_msg,
                    failure_classification=FailureClassification.CUCM_COMMAND_ERROR
                )
                return

            # Update progress - discovering artifacts
            job.update_node_status(
                node,
                NodeStatus.RUNNING,
                step="discovering",
                message="Discovering collected artifacts",
                percent=80
            )

            # Discover artifacts with time range metadata
            artifacts = self._discover_artifacts(
                job.job_id,
                node,
                collection_start_time=collection_start_time,
                collection_end_time=collection_end_time,
                reltime_used=reltime_used_str
            )
            job.node_statuses[node].artifacts = artifacts

            #  If no artifacts collected, also consider it a failure
            if len(artifacts) == 0:
                error_msg = "No artifacts collected (0 files transferred). Check SFTP server connectivity and permissions."
                logger.warning(f"[Job {job.job_id}][{node}] {error_msg}")
                job.update_node_status(
                    node,
                    NodeStatus.FAILED,
                    error=error_msg,
                    failure_classification=FailureClassification.SFTP_TIMEOUT
                )
                return

            # Mark as succeeded (percent will be set to 100 automatically)
            job.update_node_status(
                node,
                NodeStatus.SUCCEEDED,
                step="completed",
                message=f"Collected {len(artifacts)} artifacts"
            )
            logger.info(f"[Job {job.job_id}][{node}] Completed successfully - {len(artifacts)} artifacts collected")

        except asyncio.CancelledError:
          
            logger.info(f"[Job {job.job_id}][{node}] Task cancelled")
            msg = "\n[TASK CANCELLED]\n"
            transcript_lines.append(msg)
            if transcript_file and not transcript_file.closed:
                transcript_file.write(msg)
                transcript_file.flush()

            # Mark node as cancelled with completed timestamp
            job.update_node_status(node, NodeStatus.CANCELLED)
            # Re-raise to propagate cancellation
            raise

        except Exception as e:
            logger.error(f"[Job {job.job_id}][{node}] Failed: {e}")

            # Classify the failure and generate actionable error message
            full_transcript = ''.join(transcript_lines)
            classification, error_msg = _classify_failure(e, error_context=full_transcript)

            # Write error to transcript
            msg = f"\n\nERROR: {error_msg}\n"
            transcript_lines.append(msg)
            if transcript_file and not transcript_file.closed:
                transcript_file.write(msg)
                transcript_file.flush()

            job.update_node_status(
                node,
                NodeStatus.FAILED,
                error=error_msg,
                failure_classification=classification
            )

        finally:
            # FIX: Ensure transcript file is always closed
            if transcript_file and not transcript_file.closed:
                transcript_file.close()

    def _discover_artifacts(
        self,
        job_id: str,
        node: str,
        collection_start_time: Optional[datetime] = None,
        collection_end_time: Optional[datetime] = None,
        reltime_used: Optional[str] = None
    ) -> List[Artifact]:
        """
        Discover artifacts that were collected for a node.

        Uses artifact_manager to generate stable artifact IDs.
        Enriches artifacts with time range collection metadata.

        Args:
            job_id: Job identifier
            node: Node name
            collection_start_time: Start time of the collection range
            collection_end_time: End time of the collection range
            reltime_used: The reltime value used in CUCM command

        Returns:
            List of discovered artifacts with artifact_id and time metadata populated
        """
        # Use artifact_manager which includes stable artifact_id generation
        artifacts = list_artifacts_for_job(job_id)

        # Filter to this specific node
        node_artifacts = [a for a in artifacts if a.node == node]

        # Enrich artifacts with time range metadata
        for artifact in node_artifacts:
            artifact.collection_start_time = collection_start_time
            artifact.collection_end_time = collection_end_time
            artifact.reltime_used = reltime_used

        logger.info(f"Discovered {len(node_artifacts)} artifacts for job {job_id}, node {node}")

        return node_artifacts


# Global job manager instance
_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    """
    Get or create the global job manager instance.

    Returns:
        JobManager instance
    """
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager
