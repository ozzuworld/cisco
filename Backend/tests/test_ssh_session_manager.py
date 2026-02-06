"""Tests for the SSH session manager."""

import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ssh_session_manager import (
    NodeConnection,
    SSHSession,
    SSHSessionManager,
    DEFAULT_TTL_SECONDS,
    get_ssh_session_manager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(connected: bool = True):
    """Return a mock CUCMSSHClient that looks connected."""
    client = MagicMock()
    client.connect = AsyncMock()
    client.disconnect = MagicMock()
    client.execute_command = AsyncMock(return_value="mock output")
    client.execute_command_with_confirmation = AsyncMock(return_value="confirmed")
    if not connected:
        client.connect.side_effect = Exception("Connection refused")
    return client


# ---------------------------------------------------------------------------
# TestSessionCRUD
# ---------------------------------------------------------------------------


class TestSessionCRUD:
    """Create / get / destroy basic lifecycle."""

    @pytest.mark.asyncio
    async def test_create_session(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            instance = _make_mock_client()
            MockClient.return_value = instance

            session = await mgr.create_session(
                hosts=["10.0.0.1", "10.0.0.2"],
                username="admin",
                password="pass",
                port=22,
            )

        assert session.session_id
        assert len(session.nodes) == 2
        assert all(n.connected for n in session.nodes.values())

    @pytest.mark.asyncio
    async def test_get_session_touches_timestamp(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        old_ts = session.last_used_at
        await asyncio.sleep(0.01)
        fetched = mgr.get_session(session.session_id)
        assert fetched is not None
        assert fetched.last_used_at > old_ts

    @pytest.mark.asyncio
    async def test_destroy_session(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            mock_client = _make_mock_client()
            MockClient.return_value = mock_client
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        sid = session.session_id
        result = await mgr.destroy_session(sid)
        assert result is True
        assert mgr.get_session(sid) is None
        mock_client.disconnect.assert_called()

    @pytest.mark.asyncio
    async def test_destroy_nonexistent_session(self):
        mgr = SSHSessionManager()
        result = await mgr.destroy_session("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            await mgr.create_session(hosts=["10.0.0.1"], username="a", password="b")
            await mgr.create_session(hosts=["10.0.0.2"], username="a", password="b")

        assert len(mgr.list_sessions()) == 2


# ---------------------------------------------------------------------------
# TestParallelConnect
# ---------------------------------------------------------------------------


class TestParallelConnect:
    """Verify parallel connection behaviour and partial failure."""

    @pytest.mark.asyncio
    async def test_all_nodes_connect_in_parallel(self):
        mgr = SSHSessionManager()
        hosts = [f"10.0.0.{i}" for i in range(1, 6)]

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=hosts, username="admin", password="pass"
            )

        assert len(session.nodes) == 5
        assert all(n.connected for n in session.nodes.values())

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        mgr = SSHSessionManager()
        call_count = 0

        def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock = _make_mock_client()
            if call_count == 2:
                mock.connect.side_effect = Exception("timeout")
            return mock

        with patch("app.ssh_session_manager.CUCMSSHClient", side_effect=_side_effect):
            session = await mgr.create_session(
                hosts=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                username="admin",
                password="pass",
            )

        connected = [n for n in session.nodes.values() if n.connected]
        failed = [n for n in session.nodes.values() if not n.connected]
        assert len(connected) == 2
        assert len(failed) == 1
        assert failed[0].error is not None


# ---------------------------------------------------------------------------
# TestExecuteOnAllNodes
# ---------------------------------------------------------------------------


class TestExecuteOnAllNodes:
    """Verify command execution on all nodes."""

    @pytest.mark.asyncio
    async def test_execute_on_all_connected(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1", "10.0.0.2"],
                username="admin",
                password="pass",
            )

        results = await mgr.execute_on_all_nodes(
            session.session_id, "show trace level"
        )

        assert len(results) == 2
        for host, (ok, output) in results.items():
            assert ok is True
            assert output == "mock output"

    @pytest.mark.asyncio
    async def test_execute_on_node(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        output = await mgr.execute_on_node(
            session.session_id, "10.0.0.1", "show version"
        )
        assert output == "mock output"

    @pytest.mark.asyncio
    async def test_execute_on_nonexistent_session(self):
        mgr = SSHSessionManager()
        with pytest.raises(ValueError, match="not found"):
            await mgr.execute_on_all_nodes("bad-id", "show version")

    @pytest.mark.asyncio
    async def test_execute_on_disconnected_node(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        with pytest.raises(ValueError, match="not connected"):
            await mgr.execute_on_node(
                session.session_id, "10.0.0.99", "show version"
            )


# ---------------------------------------------------------------------------
# TestAutoCleanup
# ---------------------------------------------------------------------------


class TestAutoCleanup:
    """Verify expired sessions are cleaned up."""

    @pytest.mark.asyncio
    async def test_expired_session_removed(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        # Manually expire the session
        session.ttl_seconds = 0
        session.last_used_at = datetime.now(timezone.utc) - timedelta(seconds=10)

        assert session.is_expired()
        await mgr._cleanup_expired()
        assert mgr.get_session(session.session_id) is None

    @pytest.mark.asyncio
    async def test_active_session_not_removed(self):
        mgr = SSHSessionManager()

        with patch("app.ssh_session_manager.CUCMSSHClient") as MockClient:
            MockClient.return_value = _make_mock_client()
            session = await mgr.create_session(
                hosts=["10.0.0.1"],
                username="admin",
                password="pass",
            )

        assert not session.is_expired()
        await mgr._cleanup_expired()
        assert mgr.get_session(session.session_id) is not None


# ---------------------------------------------------------------------------
# TestSessionTouchAndTTL
# ---------------------------------------------------------------------------


class TestSessionTouchAndTTL:
    """Verify TTL tracking and touch behaviour."""

    def test_ttl_remaining_fresh(self):
        session = SSHSession(
            session_id="test",
            username="admin",
            password="pass",
            port=22,
        )
        remaining = session.ttl_remaining()
        assert remaining > 0
        assert remaining <= DEFAULT_TTL_SECONDS

    def test_ttl_remaining_expired(self):
        session = SSHSession(
            session_id="test",
            username="admin",
            password="pass",
            port=22,
        )
        session.last_used_at = datetime.now(timezone.utc) - timedelta(
            seconds=DEFAULT_TTL_SECONDS + 10
        )
        assert session.ttl_remaining() == 0.0
        assert session.is_expired()

    def test_touch_resets_ttl(self):
        session = SSHSession(
            session_id="test",
            username="admin",
            password="pass",
            port=22,
        )
        session.last_used_at = datetime.now(timezone.utc) - timedelta(
            seconds=DEFAULT_TTL_SECONDS - 10
        )
        assert session.ttl_remaining() < 15

        session.touch()
        assert session.ttl_remaining() > DEFAULT_TTL_SECONDS - 5

    def test_is_expired(self):
        session = SSHSession(
            session_id="test",
            username="admin",
            password="pass",
            port=22,
        )
        assert not session.is_expired()

        session.last_used_at = datetime.now(timezone.utc) - timedelta(
            seconds=DEFAULT_TTL_SECONDS + 1
        )
        assert session.is_expired()


# ---------------------------------------------------------------------------
# Test singleton accessor
# ---------------------------------------------------------------------------


class TestSingleton:

    def test_get_ssh_session_manager_returns_same_instance(self):
        # Reset the global for a clean test
        import app.ssh_session_manager as mod
        mod._ssh_session_manager = None

        mgr1 = get_ssh_session_manager()
        mgr2 = get_ssh_session_manager()
        assert mgr1 is mgr2

        # Clean up
        mod._ssh_session_manager = None
