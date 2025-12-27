"""Tests for BE-021.2: Single artifact download endpoint"""

import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.config import reload_settings
from app.job_manager import JobManager, get_job_manager
from app.models import CreateJobRequest, NodeStatus
from app.profiles import CollectionProfile


@pytest.fixture
def temp_storage():
    """Create temporary storage directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir)
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
    reload_settings()
    # Reset singleton before and after
    JobManager._instance = None
    yield
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


@pytest.fixture
def client(configured_env):
    """Test client"""
    with TestClient(app) as c:
        yield c


# ============================================================================
# BE-021.2: Single Artifact Download Tests
# ============================================================================


def test_download_single_artifact_hierarchical_route(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Download single artifact via /jobs/{job_id}/artifacts/{artifact_id}/download"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id
    from app.job_manager import get_job_manager

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Use get_job_manager() to ensure singleton consistency
        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.100"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.100"

        # Create artifact files
        artifact_dir = settings.artifacts_dir / job.job_id / node
        artifact_dir.mkdir(parents=True, exist_ok=True)
        test_file = artifact_dir / "test_artifact.tgz"
        test_content = b"test artifact data"
        test_file.write_bytes(test_content)

        # Discover artifacts
        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.node_statuses[node].status = NodeStatus.SUCCEEDED
        job.save()

        # Get artifact ID
        artifact_id = generate_artifact_id(job.job_id, node, "test_artifact.tgz")

        # Test hierarchical route: /jobs/{job_id}/artifacts/{artifact_id}/download
        response = client.get(f"/jobs/{job.job_id}/artifacts/{artifact_id}/download")

        assert response.status_code == 200
        assert response.content == test_content
        assert "test_artifact.tgz" in response.headers.get("content-disposition", "")


def test_download_single_artifact_flat_route(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Download single artifact via /artifacts/{artifact_id}/download (backward compat)"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.101"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.101"

        # Create artifact
        artifact_dir = settings.artifacts_dir / job.job_id / node
        artifact_dir.mkdir(parents=True, exist_ok=True)
        test_file = artifact_dir / "legacy_test.tgz"
        test_content = b"legacy artifact"
        test_file.write_bytes(test_content)

        # Discover and save
        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.save()

        artifact_id = generate_artifact_id(job.job_id, node, "legacy_test.tgz")

        # Test flat route: /artifacts/{artifact_id}/download
        response = client.get(f"/artifacts/{artifact_id}/download")

        assert response.status_code == 200
        assert response.content == test_content


def test_download_artifact_job_not_found(client):
    """BE-021.2: Helpful error when job doesn't exist"""
    fake_job_id = "nonexistent-job"
    fake_artifact_id = "fake-artifact-id"

    response = client.get(f"/jobs/{fake_job_id}/artifacts/{fake_artifact_id}/download")

    assert response.status_code == 404
    data = response.json()
    assert data["error"] == "JOB_NOT_FOUND"
    assert fake_job_id in data["message"]
    assert "artifact_id" in data
    assert data["artifact_id"] == fake_artifact_id


def test_download_artifact_not_found_helpful_error(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Helpful error message when artifact doesn't exist"""
    from app.config import get_settings

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.102"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.102"

        # Create one real artifact
        artifact_dir = settings.artifacts_dir / job.job_id / node
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "real_file.tgz").write_bytes(b"data")

        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.save()

        # Try to download non-existent artifact
        fake_artifact_id = "nonexistent-artifact-id"
        response = client.get(f"/jobs/{job.job_id}/artifacts/{fake_artifact_id}/download")

        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "ARTIFACT_NOT_FOUND"
        assert job.job_id in data["message"]
        assert fake_artifact_id in data["message"]
        # Should include helpful info about how many artifacts exist
        assert "total_artifacts_in_job" in data
        assert data["total_artifacts_in_job"] == 1  # We created 1 artifact


def test_download_artifact_security_check_job_mismatch(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Security check - artifact must belong to the job"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()

        # Create job 1 with artifact
        request1 = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.110"],
            profile="test-profile"
        )
        job1 = job_manager.create_job(request1)
        node1 = "10.1.1.110"

        artifact_dir1 = settings.artifacts_dir / job1.job_id / node1
        artifact_dir1.mkdir(parents=True, exist_ok=True)
        (artifact_dir1 / "job1_artifact.tgz").write_bytes(b"job1 data")

        artifacts1 = job_manager._discover_artifacts(job1.job_id, node1)
        job1.node_statuses[node1].artifacts = artifacts1
        job1.save()

        artifact_id_job1 = generate_artifact_id(job1.job_id, node1, "job1_artifact.tgz")

        # Create job 2
        request2 = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.111"],
            profile="test-profile"
        )
        job2 = job_manager.create_job(request2)

        # Try to download job1's artifact via job2's route (security violation)
        response = client.get(f"/jobs/{job2.job_id}/artifacts/{artifact_id_job1}/download")

        # Should return 404 (not exposing that the artifact exists in another job)
        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "ARTIFACT_NOT_FOUND"


def test_download_multiple_artifacts_from_same_job(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Download multiple different artifacts from the same job"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.120"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.120"

        # Create multiple artifacts
        artifact_dir = settings.artifacts_dir / job.job_id / node
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "file1.tgz").write_bytes(b"file1 content")
        (artifact_dir / "file2.tgz").write_bytes(b"file2 content")
        (artifact_dir / "file3.tgz").write_bytes(b"file3 content")

        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.save()

        # Download each artifact
        for filename in ["file1.tgz", "file2.tgz", "file3.tgz"]:
            artifact_id = generate_artifact_id(job.job_id, node, filename)
            response = client.get(f"/jobs/{job.job_id}/artifacts/{artifact_id}/download")

            assert response.status_code == 200
            assert response.content == f"{filename.replace('.tgz', '')} content".encode()


def test_download_artifact_from_nested_directory(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Download artifact from nested CUCM directory structure"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.130"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.130"

        # Create artifact in nested CUCM structure
        nested_dir = settings.artifacts_dir / job.job_id / node / node / "20251227_120000"
        nested_dir.mkdir(parents=True, exist_ok=True)
        nested_file = nested_dir / "nested_artifact.tgz"
        nested_content = b"nested artifact from CUCM"
        nested_file.write_bytes(nested_content)

        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.save()

        artifact_id = generate_artifact_id(job.job_id, node, "nested_artifact.tgz")

        # Download should work regardless of nesting
        response = client.get(f"/jobs/{job.job_id}/artifacts/{artifact_id}/download")

        assert response.status_code == 200
        assert response.content == nested_content


def test_download_artifact_content_type(client, temp_storage, configured_env, mock_profile):
    """BE-021.2: Verify correct content-type header for artifact downloads"""
    from app.config import get_settings
    from app.artifact_manager import generate_artifact_id

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = get_job_manager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.140"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        node = "10.1.1.140"

        artifact_dir = settings.artifacts_dir / job.job_id / node
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "binary.tgz").write_bytes(b"\x00\x01\x02\x03binary data")

        artifacts = job_manager._discover_artifacts(job.job_id, node)
        job.node_statuses[node].artifacts = artifacts
        job.save()

        artifact_id = generate_artifact_id(job.job_id, node, "binary.tgz")

        response = client.get(f"/jobs/{job.job_id}/artifacts/{artifact_id}/download")

        assert response.status_code == 200
        # Should serve as octet-stream for browser downloads
        assert "application/octet-stream" in response.headers.get("content-type", "")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
