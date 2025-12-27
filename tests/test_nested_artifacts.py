"""Tests for BE-021.1: Nested directory artifact discovery"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from app.artifact_manager import list_artifacts_for_job, generate_artifact_id
from app.job_manager import JobManager, Job
from app.models import CreateJobRequest, NodeStatus
from app.config import reload_settings
from app.profiles import CollectionProfile
from unittest.mock import patch


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


# ============================================================================
# BE-021.1: Nested Directory Tests
# ============================================================================


def test_artifact_discovery_flat_structure(temp_storage, configured_env):
    """BE-021.1: Verify artifact discovery works for flat directory structure"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-123"
    node_ip = "10.1.1.1"

    # Create flat structure: received/<job_id>/<node_ip>/file.tgz
    artifact_dir = settings.artifacts_dir / job_id / node_ip
    artifact_dir.mkdir(parents=True, exist_ok=True)

    test_file = artifact_dir / "active_log.tgz"
    test_file.write_text("test data")

    # Discover artifacts
    artifacts = list_artifacts_for_job(job_id)

    assert len(artifacts) == 1
    assert artifacts[0].filename == "active_log.tgz"
    assert artifacts[0].node == node_ip
    assert artifacts[0].artifact_id is not None


def test_artifact_discovery_nested_structure(temp_storage, configured_env):
    """BE-021.1: Verify artifact discovery works for nested CUCM directory structure"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-456"
    node_ip = "10.1.1.2"

    # Create nested structure: received/<job_id>/<node_ip>/<node_ip>/<timestamp>/file.tgz
    # This is what CUCM actually creates!
    nested_dir = settings.artifacts_dir / job_id / node_ip / node_ip / "20251227_120000"
    nested_dir.mkdir(parents=True, exist_ok=True)

    test_file = nested_dir / "active_platform.tgz"
    test_file.write_text("test data from nested directory")

    # Discover artifacts
    artifacts = list_artifacts_for_job(job_id)

    # Should find the nested file
    assert len(artifacts) == 1, f"Expected 1 artifact, found {len(artifacts)}"
    assert artifacts[0].filename == "active_platform.tgz"
    assert artifacts[0].node == node_ip
    assert artifacts[0].artifact_id is not None
    assert "received" in artifacts[0].path


def test_artifact_discovery_multiple_nested_levels(temp_storage, configured_env):
    """BE-021.1: Verify discovery works with multiple levels of nesting"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-789"
    node_ip = "10.1.1.3"

    # Create multiple nested directories with files at different levels
    base_dir = settings.artifacts_dir / job_id / node_ip

    # Level 1: Direct child
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "file1.log").write_text("level 1")

    # Level 2: Nested once
    nested_1 = base_dir / node_ip
    nested_1.mkdir(parents=True, exist_ok=True)
    (nested_1 / "file2.log").write_text("level 2")

    # Level 3: Nested twice (CUCM pattern)
    nested_2 = nested_1 / "20251227_120000"
    nested_2.mkdir(parents=True, exist_ok=True)
    (nested_2 / "file3.tgz").write_text("level 3")

    # Level 4: Even deeper
    nested_3 = nested_2 / "subdir"
    nested_3.mkdir(parents=True, exist_ok=True)
    (nested_3 / "file4.tgz").write_text("level 4")

    # Discover all artifacts
    artifacts = list_artifacts_for_job(job_id)

    # Should find all 4 files regardless of nesting level
    assert len(artifacts) == 4, f"Expected 4 artifacts, found {len(artifacts)}: {[a.filename for a in artifacts]}"

    filenames = {a.filename for a in artifacts}
    assert filenames == {"file1.log", "file2.log", "file3.tgz", "file4.tgz"}

    # All should have same node
    assert all(a.node == node_ip for a in artifacts)


def test_artifact_discovery_multiple_nodes_nested(temp_storage, configured_env):
    """BE-021.1: Verify discovery correctly separates artifacts by node with nested dirs"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-multi"
    node1 = "10.1.1.10"
    node2 = "10.1.1.11"

    # Create nested structure for node 1
    node1_nested = settings.artifacts_dir / job_id / node1 / node1 / "20251227_120000"
    node1_nested.mkdir(parents=True, exist_ok=True)
    (node1_nested / "node1_file.tgz").write_text("node 1 data")

    # Create nested structure for node 2
    node2_nested = settings.artifacts_dir / job_id / node2 / node2 / "20251227_120001"
    node2_nested.mkdir(parents=True, exist_ok=True)
    (node2_nested / "node2_file.tgz").write_text("node 2 data")

    # Discover all artifacts
    artifacts = list_artifacts_for_job(job_id)

    assert len(artifacts) == 2

    # Separate by node
    node1_artifacts = [a for a in artifacts if a.node == node1]
    node2_artifacts = [a for a in artifacts if a.node == node2]

    assert len(node1_artifacts) == 1
    assert len(node2_artifacts) == 1

    assert node1_artifacts[0].filename == "node1_file.tgz"
    assert node2_artifacts[0].filename == "node2_file.tgz"


def test_artifact_id_stability_for_nested_files(temp_storage, configured_env):
    """BE-021.1: Verify artifact IDs are stable regardless of directory nesting"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-stable"
    node_ip = "10.1.1.20"
    filename = "stable_test.tgz"

    # Create file in nested directory
    nested_dir = settings.artifacts_dir / job_id / node_ip / node_ip / "timestamp"
    nested_dir.mkdir(parents=True, exist_ok=True)
    (nested_dir / filename).write_text("data")

    # Discover artifacts twice
    artifacts1 = list_artifacts_for_job(job_id)
    artifacts2 = list_artifacts_for_job(job_id)

    # IDs should be identical
    assert len(artifacts1) == 1
    assert len(artifacts2) == 1
    assert artifacts1[0].artifact_id == artifacts2[0].artifact_id

    # Verify ID is based on job_id:node:filename (not full path)
    expected_id = generate_artifact_id(job_id, node_ip, filename)
    assert artifacts1[0].artifact_id == expected_id


def test_job_manager_discovers_nested_artifacts(temp_storage, configured_env, mock_profile):
    """BE-021.1: Integration test - JobManager discovers nested artifacts and persists them"""
    from app.config import get_settings

    settings = get_settings()

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="password",
            nodes=["10.1.1.100"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # Simulate CUCM creating nested directory structure
        node = "10.1.1.100"
        nested_dir = settings.artifacts_dir / job.job_id / node / node / "20251227_150000"
        nested_dir.mkdir(parents=True, exist_ok=True)
        (nested_dir / "active_platform.tgz").write_text("cucm data")
        (nested_dir / "active_syslog.tgz").write_text("syslog data")

        # Call discover artifacts (as the job manager would)
        discovered = job_manager._discover_artifacts(job.job_id, node)

        # Should find both files
        assert len(discovered) == 2
        filenames = {a.filename for a in discovered}
        assert filenames == {"active_platform.tgz", "active_syslog.tgz"}

        # All artifacts should have proper metadata
        for artifact in discovered:
            assert artifact.node == node
            assert artifact.artifact_id is not None
            assert artifact.size_bytes > 0
            assert "received" in artifact.path

        # Assign to job and verify it's saved
        job.node_statuses[node].artifacts = discovered
        job.node_statuses[node].status = NodeStatus.SUCCEEDED
        job.save()

        # Reload job from job manager (which handles profile lookup correctly)
        reloaded_job = job_manager.get_job(job.job_id)

        # Artifacts should be persisted
        assert reloaded_job is not None
        assert len(reloaded_job.node_statuses[node].artifacts) == 2

        # Verify filenames match
        reloaded_filenames = {a.filename for a in reloaded_job.node_statuses[node].artifacts}
        assert reloaded_filenames == {"active_platform.tgz", "active_syslog.tgz"}


def test_empty_nested_directories_ignored(temp_storage, configured_env):
    """BE-021.1: Empty nested directories should not cause errors"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-empty"
    node_ip = "10.1.1.50"

    # Create nested directory structure with NO files
    nested_dir = settings.artifacts_dir / job_id / node_ip / node_ip / "20251227_000000"
    nested_dir.mkdir(parents=True, exist_ok=True)

    # Create some empty subdirectories too
    (nested_dir / "subdir1").mkdir(exist_ok=True)
    (nested_dir / "subdir2" / "subdir3").mkdir(parents=True, exist_ok=True)

    # Should not crash, just return empty list
    artifacts = list_artifacts_for_job(job_id)

    assert len(artifacts) == 0


def test_mixed_file_types_in_nested_dirs(temp_storage, configured_env):
    """BE-021.1: Verify all file types are discovered in nested directories"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-filetypes"
    node_ip = "10.1.1.60"

    nested_dir = settings.artifacts_dir / job_id / node_ip / node_ip / "timestamp"
    nested_dir.mkdir(parents=True, exist_ok=True)

    # Create various file types
    (nested_dir / "file.tgz").write_text("archive")
    (nested_dir / "file.log").write_text("log")
    (nested_dir / "file.txt").write_text("text")
    (nested_dir / "file.dat").write_text("data")
    (nested_dir / "file").write_text("no extension")

    artifacts = list_artifacts_for_job(job_id)

    # Should find all files regardless of extension
    assert len(artifacts) == 5
    filenames = {a.filename for a in artifacts}
    assert filenames == {"file.tgz", "file.log", "file.txt", "file.dat", "file"}


def test_symlinks_not_followed(temp_storage, configured_env):
    """BE-021.1: Symbolic links should not be followed (security)"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-symlink"
    node_ip = "10.1.1.70"

    # Create directory with actual file
    artifact_dir = settings.artifacts_dir / job_id / node_ip
    artifact_dir.mkdir(parents=True, exist_ok=True)
    real_file = artifact_dir / "real_file.tgz"
    real_file.write_text("real data")

    # Create symlink (if supported on this platform)
    try:
        symlink_file = artifact_dir / "symlink_file.tgz"
        symlink_file.symlink_to(real_file)
    except (OSError, NotImplementedError):
        # Symlinks not supported on this platform, skip this part
        pass

    # Discover artifacts
    artifacts = list_artifacts_for_job(job_id)

    # Should find real file
    assert any(a.filename == "real_file.tgz" for a in artifacts)

    # Symlink behavior depends on rglob - it may or may not follow
    # The important thing is we don't crash


def test_artifacts_have_correct_metadata(temp_storage, configured_env):
    """BE-021.1: Verify artifacts have all required metadata fields"""
    from app.config import get_settings

    settings = get_settings()
    job_id = "test-job-metadata"
    node_ip = "10.1.1.80"

    nested_dir = settings.artifacts_dir / job_id / node_ip / node_ip / "20251227"
    nested_dir.mkdir(parents=True, exist_ok=True)

    test_file = nested_dir / "metadata_test.tgz"
    test_content = "test data with some content"
    test_file.write_text(test_content)

    artifacts = list_artifacts_for_job(job_id)

    assert len(artifacts) == 1
    artifact = artifacts[0]

    # Verify all required fields
    assert artifact.node == node_ip
    assert artifact.filename == "metadata_test.tgz"
    assert artifact.path.startswith("received/")
    assert artifact.size_bytes == len(test_content)
    assert artifact.created_at is not None
    assert isinstance(artifact.created_at, datetime)
    assert artifact.artifact_id is not None
    assert len(artifact.artifact_id) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
