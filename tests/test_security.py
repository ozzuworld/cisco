"""Security tests for BE-021: Credential handling and secrets hygiene"""

import pytest
import json
import tempfile
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

from app.job_manager import JobManager, Job
from app.models import CreateJobRequest, JobStatus, NodeStatus
from app.config import reload_settings
from app.profiles import CollectionProfile
from app.security import (
    mask_sensitive_value,
    mask_dict,
    mask_url,
    safe_repr,
    ConnectionRetryLimiter,
    validate_no_secrets_in_response,
    SENSITIVE_FIELDS
)


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
# BE-021: Password NOT in Job JSON Files
# ============================================================================


def test_password_not_persisted_in_job_json(configured_env, temp_storage, mock_profile):
    """BE-021: CUCM password must NOT be persisted in job JSON files"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="SuperSecret123!",  # This must NOT be saved
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # Read the persisted JSON file
        job_file = temp_storage / "jobs" / f"{job.job_id}.json"
        assert job_file.exists(), "Job file should be created"

        with open(job_file, 'r') as f:
            job_data = json.load(f)

        # CRITICAL: Password must NOT be in the JSON
        assert "password" not in job_data, "Password field should not exist in persisted JSON"
        assert "SuperSecret123!" not in json.dumps(job_data), "Password value must not appear anywhere in JSON"

        # Verify other fields are present
        assert job_data["username"] == "admin"
        assert job_data["publisher_host"] == "10.1.1.1"


def test_job_to_dict_excludes_password(configured_env, temp_storage, mock_profile):
    """BE-021: Job.to_dict() must explicitly exclude password"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="MySecretPassword",
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # Call to_dict() directly
        job_dict = job.to_dict()

        # Password must NOT be in the dictionary
        assert "password" not in job_dict
        assert "MySecretPassword" not in str(job_dict)


# ============================================================================
# BE-021: Password NOT in Logs
# ============================================================================


def test_password_not_logged(configured_env, temp_storage, mock_profile, caplog):
    """BE-021: Passwords must NOT appear in log output"""
    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        # Capture all log levels
        caplog.set_level(logging.DEBUG)

        job_manager = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="TopSecretPassword123",
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # Check all log records
        all_logs = "\n".join(record.message for record in caplog.records)

        # Password must NOT appear in any log message
        assert "TopSecretPassword123" not in all_logs, "Password must not appear in logs"

        # Verify some logging occurred (job creation should log)
        assert len(all_logs) > 0, "Expected some log output from job creation"


def test_sftp_password_not_in_logs(configured_env, caplog):
    """BE-021: SFTP password must not appear in logs"""
    from app.config import get_settings

    caplog.set_level(logging.DEBUG)

    settings = get_settings()

    # Log something that might accidentally include settings
    logger = logging.getLogger(__name__)
    logger.info(f"SFTP host: {settings.sftp_host}")
    logger.info(f"SFTP user: {settings.sftp_username}")

    all_logs = "\n".join(record.message for record in caplog.records)

    # SFTP password must NOT appear
    assert settings.sftp_password not in all_logs, "SFTP password must not appear in logs"


# ============================================================================
# BE-021: Password NOT in API Responses
# ============================================================================


def test_job_status_response_excludes_password(configured_env, temp_storage, mock_profile):
    """BE-021: API responses must NOT include passwords"""
    from app.models import JobStatusResponse

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()
        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password="APITestPassword",
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)
        progress = job.get_progress_metrics()

        # Build API response
        response = JobStatusResponse(
            job_id=job.job_id,
            status=job.status,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            profile=job.profile.name,
            nodes=list(job.node_statuses.values()),
            total_nodes=progress["total_nodes"],
            completed_nodes=progress["completed_nodes"],
            succeeded_nodes=progress["succeeded_nodes"],
            failed_nodes=progress["failed_nodes"],
            running_nodes=progress["running_nodes"],
            percent_complete=progress["percent_complete"],
            last_updated_at=progress["last_updated_at"]
        )

        # Convert to dict (as API would return)
        response_dict = response.model_dump(mode='json')

        # Password must NOT be in response
        assert "password" not in response_dict
        assert "APITestPassword" not in json.dumps(response_dict)


# ============================================================================
# BE-021: Security Utility Functions
# ============================================================================


def test_mask_sensitive_value():
    """BE-021: Test secret masking utility"""
    assert mask_sensitive_value("secret123") == "*** (9 chars)"
    assert mask_sensitive_value("secret123", show_length=False) == "***"
    assert mask_sensitive_value("") == "*** (empty)"
    assert mask_sensitive_value(None) == "*** (empty)"


def test_mask_dict():
    """BE-021: Test dictionary masking for sensitive fields"""
    data = {
        "username": "admin",
        "password": "secret123",
        "host": "10.1.1.1",
        "api_key": "abc123",
        "nested": {
            "token": "xyz789",
            "public_field": "visible"
        }
    }

    masked = mask_dict(data)

    # Password should be masked
    assert masked["password"] == "*** (9 chars)"
    assert masked["api_key"] == "*** (6 chars)"
    assert masked["nested"]["token"] == "*** (6 chars)"

    # Non-sensitive fields should be unchanged
    assert masked["username"] == "admin"
    assert masked["host"] == "10.1.1.1"
    assert masked["nested"]["public_field"] == "visible"


def test_mask_url():
    """BE-021: Test URL credential masking"""
    url = "sftp://user:password123@host.com/path"
    masked = mask_url(url)

    assert "password123" not in masked
    assert "***" in masked
    assert "host.com" in masked  # Host should still be visible
    assert masked == "sftp://user:***@host.com/path"


def test_safe_repr_truncates_long_strings():
    """BE-021: Test safe representation truncation"""
    long_string = "a" * 200
    safe = safe_repr(long_string, max_length=100)

    assert len(safe) <= 103  # 100 + "..."
    assert "..." in safe


# ============================================================================
# BE-021: Connection Retry Limits
# ============================================================================


def test_retry_limiter_basic():
    """BE-021: Test connection retry limiter"""
    limiter = ConnectionRetryLimiter(max_retries=3)

    # First 3 attempts should succeed
    assert limiter.check_and_increment("host1") is True
    assert limiter.check_and_increment("host1") is True
    assert limiter.check_and_increment("host1") is True

    # 4th attempt should fail (rate limited)
    assert limiter.check_and_increment("host1") is False

    # Different host should still work
    assert limiter.check_and_increment("host2") is True


def test_retry_limiter_reset():
    """BE-021: Test retry limiter reset on success"""
    limiter = ConnectionRetryLimiter(max_retries=3)

    # Use up attempts
    limiter.check_and_increment("host1")
    limiter.check_and_increment("host1")

    # Reset (simulating successful connection)
    limiter.reset("host1")

    # Should be able to connect again
    assert limiter.check_and_increment("host1") is True


def test_retry_limiter_get_attempts():
    """BE-021: Test getting attempt count"""
    limiter = ConnectionRetryLimiter(max_retries=5)

    assert limiter.get_attempts("host1") == 0

    limiter.check_and_increment("host1")
    assert limiter.get_attempts("host1") == 1

    limiter.check_and_increment("host1")
    limiter.check_and_increment("host1")
    assert limiter.get_attempts("host1") == 3


# ============================================================================
# BE-021: Response Validation
# ============================================================================


def test_validate_no_secrets_in_response_success():
    """BE-021: Test response validation passes for safe responses"""
    safe_response = {
        "job_id": "123",
        "username": "admin",
        "status": "running",
        "nodes": [
            {"node": "10.1.1.1", "status": "running"}
        ]
    }

    # Should not raise
    validate_no_secrets_in_response(safe_response)


def test_validate_no_secrets_in_response_fails_on_password():
    """BE-021: Test response validation fails if password is present"""
    unsafe_response = {
        "job_id": "123",
        "username": "admin",
        "password": "secret123",  # BAD!
        "status": "running"
    }

    # Should raise ValueError
    with pytest.raises(ValueError, match="contains sensitive field"):
        validate_no_secrets_in_response(unsafe_response)


def test_validate_no_secrets_in_nested_response():
    """BE-021: Test validation catches nested secrets"""
    unsafe_response = {
        "job_id": "123",
        "config": {
            "api_key": "abc123"  # BAD!
        }
    }

    with pytest.raises(ValueError, match="contains sensitive field"):
        validate_no_secrets_in_response(unsafe_response)


def test_validate_allows_none_password():
    """BE-021: Test validation allows None/empty password fields"""
    # Sometimes models have password fields that are explicitly None
    response_with_none = {
        "job_id": "123",
        "password": None  # OK - explicitly None
    }

    # Should not raise
    validate_no_secrets_in_response(response_with_none)

    response_with_empty = {
        "job_id": "123",
        "password": ""  # OK - explicitly empty
    }

    # Should not raise
    validate_no_secrets_in_response(response_with_empty)


# ============================================================================
# BE-021: Sensitive Fields Detection
# ============================================================================


def test_sensitive_fields_list():
    """BE-021: Verify sensitive fields list is comprehensive"""
    expected_fields = {
        "password", "passwd", "pwd", "secret", "api_key",
        "apikey", "token", "auth", "credential", "private_key",
        "sftp_password"
    }

    # All expected fields should be in SENSITIVE_FIELDS
    for field in expected_fields:
        assert field in SENSITIVE_FIELDS, f"{field} should be in SENSITIVE_FIELDS"


# ============================================================================
# BE-021: Integration Test - No Secrets in Full Workflow
# ============================================================================


def test_full_workflow_no_secret_exposure(configured_env, temp_storage, mock_profile, caplog):
    """BE-021: Integration test - secrets must not leak anywhere in job lifecycle"""
    caplog.set_level(logging.DEBUG)

    with patch('app.job_manager.get_profile_catalog') as mock_catalog:
        mock_catalog.return_value.get_profile.return_value = mock_profile

        job_manager = JobManager()
        secret_password = "IntegrationTestSecret123"

        request = CreateJobRequest(
            publisher_host="10.1.1.1",
            port=22,
            username="admin",
            password=secret_password,
            nodes=["node1.example.com"],
            profile="test-profile"
        )

        job = job_manager.create_job(request)

        # 1. Check job file on disk
        job_file = temp_storage / "jobs" / f"{job.job_id}.json"
        with open(job_file, 'r') as f:
            job_json = f.read()
        assert secret_password not in job_json, "Password in job file!"

        # 2. Check logs
        all_logs = "\n".join(record.message for record in caplog.records)
        assert secret_password not in all_logs, "Password in logs!"

        # 3. Check in-memory job object to_dict()
        job_dict = job.to_dict()
        assert secret_password not in json.dumps(job_dict), "Password in job dict!"

        # Success!


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
