"""Job management and execution for CUCM log collection"""

import asyncio
import json
import logging
import os
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
    CollectionOptions
)
from app.profiles import CollectionProfile, get_profile_catalog
from app.prompt_responder import PromptResponder, build_file_get_command
from app.ssh_client import CUCMSSHClient, CUCMSSHClientError
from app.artifact_manager import list_artifacts_for_job


logger = logging.getLogger(__name__)


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
        self.cancelled = False  # v0.3: cancellation flag

        # Node states
        self.node_statuses: Dict[str, NodeJobStatus] = {}
        for node in nodes:
            self.node_statuses[node] = NodeJobStatus(
                node=node,
                status=NodeStatus.PENDING
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
            "cancelled": self.cancelled,  # v0.3
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "node_statuses": {
                node: status.model_dump(mode='json')  # BE-016: mode='json' serializes datetime properly
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

        # Restore node statuses
        job.node_statuses = {}
        for node, status_data in data["node_statuses"].items():
            job.node_statuses[node] = NodeJobStatus(**status_data)

        return job

    def save(self):
        """
        Persist job state to disk atomically.

        Uses atomic write (temp file + rename) to prevent corruption if process
        crashes during write (BE-016).
        """
        settings = get_settings()
        job_file = settings.jobs_dir / f"{self.job_id}.json"
        temp_file = settings.jobs_dir / f"{self.job_id}.json.tmp"

        try:
            # Ensure jobs directory exists
            settings.jobs_dir.mkdir(parents=True, exist_ok=True)

            # Write to temp file first
            with open(temp_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)

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
        if new_status == JobStatus.RUNNING and not self.started_at:
            self.started_at = datetime.utcnow()
        elif new_status in [JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.PARTIAL, JobStatus.CANCELLED]:
            self.completed_at = datetime.utcnow()
        self.save()

    def update_node_status(self, node: str, status: NodeStatus, error: Optional[str] = None):
        """Update status for a specific node"""
        if node in self.node_statuses:
            self.node_statuses[node].status = status
            if error:
                self.node_statuses[node].error = error
            if status == NodeStatus.RUNNING:
                self.node_statuses[node].started_at = datetime.utcnow()
            elif status in [NodeStatus.SUCCEEDED, NodeStatus.FAILED, NodeStatus.CANCELLED]:
                self.node_statuses[node].completed_at = datetime.utcnow()
            self.save()


class JobManager:
    """
    Manages job lifecycle: creation, execution, status tracking.

    Singleton pattern - one instance per application.
    """

    def __init__(self):
        """Initialize job manager"""
        self.jobs: Dict[str, Job] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}  # v0.3: track tasks for cancellation
        self.node_tasks: Dict[str, Dict[str, asyncio.Task]] = {}  # v0.3.3: track per-node tasks
        self.settings = get_settings()
        self._load_existing_jobs()

    def _load_existing_jobs(self):
        """Load existing jobs from disk on startup (BE-016)"""
        jobs_dir = self.settings.jobs_dir
        if not jobs_dir.exists():
            logger.info("Jobs directory does not exist yet - no jobs to load")
            return

        logger.info(f"Loading existing jobs from {jobs_dir}")
        profile_catalog = get_profile_catalog()
        loaded_count = 0

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
                logger.error(f"Error loading job from {job_file}: {e}")

        logger.info(f"Loaded {loaded_count} existing jobs from disk")

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

        Jobs are loaded from disk at startup (BE-016), so all jobs are in memory.

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

        v0.3.3: Immediately finalizes node and job status for fast visibility.

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

        # v0.3.3: Cancel job-level task (if running)
        if job_id in self.running_tasks:
            task = self.running_tasks[job_id]
            if not task.done():
                task.cancel()
                logger.info(f"Job {job_id} main task cancelled")

        # v0.3.3: Cancel all per-node tasks immediately (if running)
        if job_id in self.node_tasks:
            for node, task in self.node_tasks[job_id].items():
                if not task.done():
                    task.cancel()
                    logger.info(f"Job {job_id} node {node} task cancelled")

        # v0.3.3: Immediately mark PENDING and RUNNING nodes as CANCELLED
        # This ensures UI sees cancellation immediately
        for node, node_status in job.node_statuses.items():
            if node_status.status in [NodeStatus.PENDING, NodeStatus.RUNNING]:
                job.update_node_status(node, NodeStatus.CANCELLED)
                logger.info(f"Job {job_id} node {node} marked CANCELLED")

        # v0.3.3: Determine final job status immediately
        node_statuses = [ns.status for ns in job.node_statuses.values()]
        if any(s == NodeStatus.SUCCEEDED for s in node_statuses):
            job.update_status(JobStatus.PARTIAL)
        else:
            job.update_status(JobStatus.CANCELLED)

        job.save()
        logger.info(f"Job {job_id} cancelled - status: {job.status}")
        return True

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

        try:
            # Process nodes with concurrency limit
            semaphore = asyncio.Semaphore(self.settings.max_concurrency_per_job)

            async def process_with_semaphore(node):
                # Check cancellation before processing
                if job.cancelled:
                    job.update_node_status(node, NodeStatus.CANCELLED)
                    return
                async with semaphore:
                    await self._process_node(job, node)

            # v0.3.3: Track per-node tasks for immediate cancellation
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
            # v0.3.2: Mark any non-completed nodes as cancelled
            for node, ns in job.node_statuses.items():
                if ns.status in [NodeStatus.PENDING, NodeStatus.RUNNING]:
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
            # v0.3.3: Clean up task tracking
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
        logger.info(f"Pre-creating SFTP directory: {directory_path} on {self.settings.sftp_host}:{self.settings.sftp_port}")

        try:
            async with asyncssh.connect(
                host=self.settings.sftp_host,
                port=self.settings.sftp_port,
                username=self.settings.sftp_username,
                password=self.settings.sftp_password,
                known_hosts=None  # Accept any host key (same as CUCM behavior)
            ) as conn:
                logger.debug(f"Connected to SFTP server {self.settings.sftp_host}")

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
                            logger.debug(f"Created directory: {current_path}")
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
            error_msg = f"SSH/SFTP connection failed to {self.settings.sftp_host}:{self.settings.sftp_port}: {type(e).__name__}: {str(e)}"
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
        # v0.3.3: Check cancellation BEFORE setting node to RUNNING
        # This prevents race where cancel() is called but node still becomes RUNNING
        if job.cancelled:
            logger.info(f"[Job {job.job_id}][{node}] Cancelled before start")
            job.update_node_status(node, NodeStatus.CANCELLED)
            return

        logger.info(f"[Job {job.job_id}] Processing node: {node}")
        job.update_node_status(node, NodeStatus.RUNNING)

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

            # v0.3.2: Check cancellation before connecting
            if job.cancelled:
                logger.info(f"[Job {job.job_id}][{node}] Cancelled before connect")
                transcript_file.write("\n[CANCELLED]\n")
                transcript_file.close()
                job.update_node_status(node, NodeStatus.CANCELLED)
                return

            # Prepare SFTP directory for this node
            sftp_directory = f"{self.settings.sftp_remote_base_dir}/{job.job_id}/{node}"

            # FIX: Pre-create directory on SFTP server before CUCM tries to push files
            # CUCM's file get activelog does NOT create directories - it will fail if they don't exist
            try:
                await self._ensure_sftp_directory(sftp_directory)
                transcript_file.write(f"SFTP directory created: {sftp_directory}\n")
                transcript_file.flush()
            except Exception as e:
                error_msg = f"Failed to create SFTP directory {sftp_directory}: {e}"
                logger.error(f"[Job {job.job_id}][{node}] {error_msg}")
                transcript_file.write(f"\nERROR: {error_msg}\n")
                transcript_file.flush()
                job.update_node_status(node, NodeStatus.FAILED, error=error_msg)
                return

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

                # v0.3.2: Check cancellation after connect
                if job.cancelled:
                    logger.info(f"[Job {job.job_id}][{node}] Cancelled after connect")
                    transcript_file.write("\n[CANCELLED]\n")
                    transcript_file.flush()
                    transcript_lines.append("\n[CANCELLED]\n")
                    job.update_node_status(node, NodeStatus.CANCELLED)
                    return

                # Process each path in the profile
                for path in job.profile.paths:
                    # v0.3.2: Check cancellation before each path
                    if job.cancelled:
                        logger.info(f"[Job {job.job_id}][{node}] Cancelled during path processing")
                        msg = f"\n[CANCELLED before processing {path}]\n"
                        transcript_file.write(msg)
                        transcript_file.flush()
                        transcript_lines.append(msg)
                        job.update_node_status(node, NodeStatus.CANCELLED)
                        return

                    # Determine options (use overrides if provided)
                    reltime = job.options.reltime_minutes or job.profile.reltime_minutes
                    compress = job.options.compress if job.options.compress is not None else job.profile.compress
                    recurs = job.options.recurs if job.options.recurs is not None else job.profile.recurs
                    match = job.options.match or job.profile.match

                    # Build command
                    command = build_file_get_command(
                        path=path,
                        reltime_minutes=reltime,
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
                        sftp_host=self.settings.sftp_host,
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

            # BE-017: Check if CUCM reported "No files matched filter criteria"
            full_transcript = ''.join(transcript_lines)
            if "No files matched filter criteria" in full_transcript:
                error_msg = "No files matched filter criteria (check path/pattern/reltime)"
                logger.warning(f"[Job {job.job_id}][{node}] {error_msg}")
                job.update_node_status(node, NodeStatus.FAILED, error=error_msg)
                return

            # Discover artifacts
            artifacts = self._discover_artifacts(job.job_id, node)
            job.node_statuses[node].artifacts = artifacts

            # BE-017: If no artifacts collected, also consider it a failure
            if len(artifacts) == 0:
                error_msg = "No artifacts collected (0 files transferred)"
                logger.warning(f"[Job {job.job_id}][{node}] {error_msg}")
                job.update_node_status(node, NodeStatus.FAILED, error=error_msg)
                return

            # Mark as succeeded
            job.update_node_status(node, NodeStatus.SUCCEEDED)
            logger.info(f"[Job {job.job_id}][{node}] Completed successfully - {len(artifacts)} artifacts collected")

        except asyncio.CancelledError:
            # v0.3.2: Handle task cancellation gracefully
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
            error_msg = f"{type(e).__name__}: {str(e)}"

            # Write error to transcript
            msg = f"\n\nERROR: {error_msg}\n"
            transcript_lines.append(msg)
            if transcript_file and not transcript_file.closed:
                transcript_file.write(msg)
                transcript_file.flush()

            job.update_node_status(node, NodeStatus.FAILED, error=error_msg)

        finally:
            # FIX: Ensure transcript file is always closed
            if transcript_file and not transcript_file.closed:
                transcript_file.close()

    def _discover_artifacts(self, job_id: str, node: str) -> List[Artifact]:
        """
        Discover artifacts that were collected for a node.

        Uses artifact_manager to generate stable artifact IDs (v0.3).

        Args:
            job_id: Job identifier
            node: Node name

        Returns:
            List of discovered artifacts with artifact_id populated
        """
        # Use artifact_manager which includes stable artifact_id generation
        artifacts = list_artifacts_for_job(job_id)

        # Filter to this specific node
        node_artifacts = [a for a in artifacts if a.node == node]

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
