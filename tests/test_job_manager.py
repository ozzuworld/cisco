"""Tests for job manager persistence (BE-016)"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from app.job_manager import JobManager, Job
from app.models import CreateJobRequest, JobStatus, NodeStatus, CollectionOptions
from app.config import reload_settings
from app.profiles import CollectionProfile


@pytest.fixture
def temp_storage():
    """Create temporary storage directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir)

        # Create subdirectories
        (storage_path / "jobs").mkdir(parents=True, exist_ok=True)
        (storage_path / "transcripts").mkdir(parents=True, exist_ok=True)
        (storage_path / "received").mkdir(parents=True, exist_ok=True)

        yield storage_path


@pytest.fixture
def configured_env(temp_storage, monkeypatch):
    """Set up environment for testing"""
    monkeypatch.setenv("STORAGE_ROOT", str(temp_storage))
    monkeypatch.setenv("SFTP_HOST", "test.example.com")
    monkeypatch.setenv("SFTP_USERNAME", "testuser")
    monkeypatch.setenv("SFTP_PASSWORD", "testpass")
    monkeypatch.setenv("PROFILES_PATH", "./profiles.yaml")

    # Reload settings to pick up env changes
    reload_settings()

    # Reset job manager singleton
    JobManager._instance = None


@pytest.fixture
def mock_profile():
    """Create a mock collection profile"""
    return CollectionProfile(
        name="test-profile",
        description="Test profile",
        paths=["/var/log/active/platform/log/"],
        reltime_minutes=60,
        compress=True,
        recurs=True,
        match="*.log"
    )


def test_job_saves_to_disk(configured_env, temp_storage, mock_profile):
    """BE-016: Verify job is saved to disk when created"""
    from app.config import get_settings

    # Mock profile catalog
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Create job manager
        job_manager = JobManager()

        # Create a job
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="secret123",
            nodes=["node1.example.com", "node2.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # Verify job file exists
        settings = get_settings()
        job_file = settings.jobs_dir / f"{job.job_id}.json"
        assert job_file.exists(), f"Job file should exist at {job_file}"

        # Verify job file content
        with open(job_file, 'r') as f:
            data = json.load(f)

        assert data["job_id"] == job.job_id
        assert data["publisher_host"] == "10.1.1.1"
        assert data["username"] == "admin"
        assert "password" not in data, "Password should not be persisted"
        assert data["nodes"] == ["node1.example.com", "node2.example.com"]
        assert data["profile"] == "test-profile"
        assert data["status"] == "queued"


def test_job_persists_status_changes(configured_env, temp_storage, mock_profile):
    """BE-016: Verify status changes are persisted to disk"""
    from app.config import get_settings

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()

        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="secret123",
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        settings = get_settings()
        job_file = settings.jobs_dir / f"{job.job_id}.json"

        # Change status to RUNNING
        job.update_status(JobStatus.RUNNING)

        # Verify updated status in file
        with open(job_file, 'r') as f:
            data = json.load(f)

        assert data["status"] == "running"
        assert data["started_at"] is not None

        # Change status to SUCCEEDED
        job.update_status(JobStatus.SUCCEEDED)

        # Verify final status in file
        with open(job_file, 'r') as f:
            data = json.load(f)

        assert data["status"] == "succeeded"
        assert data["completed_at"] is not None


def test_job_persists_node_status_changes(configured_env, temp_storage, mock_profile):
    """BE-016: Verify node status changes are persisted"""
    from app.config import get_settings

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()

        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="secret123",
            nodes=["node1.example.com", "node2.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        settings = get_settings()
        job_file = settings.jobs_dir / f"{job.job_id}.json"

        # Update node status
        job.update_node_status("node1.example.com", NodeStatus.RUNNING)
        job.update_node_status("node2.example.com", NodeStatus.SUCCEEDED)

        # Verify node statuses in file
        with open(job_file, 'r') as f:
            data = json.load(f)

        assert data["node_statuses"]["node1.example.com"]["status"] == "running"
        assert data["node_statuses"]["node2.example.com"]["status"] == "succeeded"


def test_jobs_loaded_on_startup(configured_env, temp_storage, mock_profile):
    """BE-016: Verify jobs are loaded from disk on JobManager startup"""
    from app.config import get_settings

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Create first job manager and create jobs
        job_manager1 = JobManager()

        request1 = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="secret123",
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        request2 = CreateJobRequest(
            publisher_host="10.1.1.2",
            port=22,
            username="admin",
            password="secret456",
            nodes=["node2.example.com"],
            profile="test-profile"
        )

        job1 = job_manager1.create_job(request1)
        job2 = job_manager1.create_job(request2)

        # Update statuses
        job1.update_status(JobStatus.SUCCEEDED)
        job2.update_status(JobStatus.RUNNING)

        # Simulate restart: create new JobManager instance
        # Reset singleton first
        JobManager._instance = None

        # Create new job manager - should load jobs from disk
        job_manager2 = JobManager()

        # Verify both jobs are loaded
        assert len(job_manager2.jobs) == 2
        assert job1.job_id in job_manager2.jobs
        assert job2.job_id in job_manager2.jobs

        # Verify job details are correct
        loaded_job1 = job_manager2.get_job(job1.job_id)
        assert loaded_job1 is not None
        assert loaded_job1.publisher_host == "10.1.1.1"
        assert loaded_job1.status == JobStatus.SUCCEEDED
        assert loaded_job1.nodes_list == ["node1.example.com"]

        loaded_job2 = job_manager2.get_job(job2.job_id)
        assert loaded_job2 is not None
        assert loaded_job2.publisher_host == "10.1.1.2"
        assert loaded_job2.status == JobStatus.RUNNING
        assert loaded_job2.nodes_list == ["node2.example.com"]


def test_get_job_after_restart(configured_env, temp_storage, mock_profile):
    """BE-016: Verify GET /jobs/{id} returns job after restart"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Create job
        job_manager1 = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="secret123",
            nodes=["node1.example.com"],
            profile="test-profile"
        )
        job = job_manager1.create_job(request)
        job_id = job.job_id

        # Simulate restart
        JobManager._instance = None
        job_manager2 = JobManager()

        # Verify get_job works
        loaded_job = job_manager2.get_job(job_id)
        assert loaded_job is not None
        assert loaded_job.job_id == job_id
        assert loaded_job.publisher_host == "10.1.1.1"


def test_list_jobs_after_restart(configured_env, temp_storage, mock_profile):
    """BE-016: Verify GET /jobs?limit=... lists jobs after restart"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Create multiple jobs
        job_manager1 = JobManager()

        job_ids = []
        for i in range(5):
            request = CreateJobRequest(
                publisher_host=f"10.1.1.{i}",
                port=22,
                username="admin",
                password="secret",
                nodes=[f"node{i}.example.com"],
                profile="test-profile"
            )
            job = job_manager1.create_job(request)
            job_ids.append(job.job_id)

        # Simulate restart
        JobManager._instance = None
        job_manager2 = JobManager()

        # Verify list_jobs works
        jobs = job_manager2.list_jobs(limit=10)
        assert len(jobs) == 5

        # Verify jobs are sorted by created_at (newest first)
        assert jobs[0].created_at >= jobs[-1].created_at

        # Verify limit works
        limited_jobs = job_manager2.list_jobs(limit=3)
        assert len(limited_jobs) == 3


def test_job_from_dict_reconstruction(configured_env, temp_storage, mock_profile):
    """BE-016: Verify Job.from_dict() correctly reconstructs jobs"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        catalog = MagicMock()
        catalog.get_profile.return_value = mock_profile

        # Create sample job data
        data = {
            "job_id": "test-job-123",
            "publisher_host": "10.1.1.1",
            "port": 22,
            "username": "admin",
            "nodes": ["node1.example.com", "node2.example.com"],
            "profile": "test-profile",
            "status": "succeeded",
            "cancelled": False,
            "created_at": "2024-01-01T12:00:00",
            "started_at": "2024-01-01T12:00:05",
            "completed_at": "2024-01-01T12:10:00",
            "node_statuses": {
                "node1.example.com": {
                    "node": "node1.example.com",
                    "status": "succeeded",
                    "started_at": "2024-01-01T12:00:05",
                    "completed_at": "2024-01-01T12:05:00",
                    "error": None,
                    "transcript_path": None,
                    "artifacts": []
                },
                "node2.example.com": {
                    "node": "node2.example.com",
                    "status": "succeeded",
                    "started_at": "2024-01-01T12:05:00",
                    "completed_at": "2024-01-01T12:10:00",
                    "error": None,
                    "transcript_path": None,
                    "artifacts": []
                }
            }
        }

        # Reconstruct job
        job = Job.from_dict(data, catalog)

        # Verify all fields
        assert job.job_id == "test-job-123"
        assert job.publisher_host == "10.1.1.1"
        assert job.port == 22
        assert job.username == "admin"
        assert job.password == ""  # Password not persisted
        assert job.nodes_list == ["node1.example.com", "node2.example.com"]
        assert job.profile.name == "test-profile"
        assert job.status == JobStatus.SUCCEEDED
        assert job.cancelled == False
        assert job.created_at == datetime.fromisoformat("2024-01-01T12:00:00")
        assert job.started_at == datetime.fromisoformat("2024-01-01T12:00:05")
        assert job.completed_at == datetime.fromisoformat("2024-01-01T12:10:00")

        # Verify node statuses
        assert len(job.node_statuses) == 2
        assert job.node_statuses["node1.example.com"].status == NodeStatus.SUCCEEDED
        assert job.node_statuses["node2.example.com"].status == NodeStatus.SUCCEEDED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
