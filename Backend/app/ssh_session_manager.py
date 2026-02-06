"""SSH Session Manager for persistent CUCM connections.

Maintains long-lived SSH sessions across multiple API calls to avoid
the 60-120s CUCM CLI initialization overhead per connection.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from app.ssh_client import CUCMSSHClient

logger = logging.getLogger(__name__)

# Concurrency limit for parallel SSH connections
MAX_PARALLEL_CONNECTIONS = 5

# Default session TTL in seconds (15 minutes)
DEFAULT_TTL_SECONDS = 900

# Cleanup interval in seconds
CLEANUP_INTERVAL_SECONDS = 60


@dataclass
class NodeConnection:
    """Wraps a CUCMSSHClient instance for a single CUCM node."""

    host: str
    client: Optional[CUCMSSHClient] = None
    connected: bool = False
    error: Optional[str] = None


@dataclass
class SSHSession:
    """A persistent SSH session spanning multiple CUCM nodes."""

    session_id: str
    username: str
    password: str
    port: int
    nodes: Dict[str, NodeConnection] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def touch(self) -> None:
        """Update last_used_at to prevent expiration."""
        self.last_used_at = datetime.now(timezone.utc)

    def ttl_remaining(self) -> float:
        """Seconds remaining before this session expires."""
        elapsed = (datetime.now(timezone.utc) - self.last_used_at).total_seconds()
        return max(0.0, self.ttl_seconds - elapsed)

    def is_expired(self) -> bool:
        return self.ttl_remaining() <= 0


class SSHSessionManager:
    """Manages persistent SSH sessions to CUCM clusters.

    Singleton pattern — use get_ssh_session_manager() to access.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, SSHSession] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_cleanup_loop(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.ensure_future(self._cleanup_loop())
            logger.info("SSH session cleanup loop started")

    def stop_cleanup_loop(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            logger.info("SSH session cleanup loop stopped")

    async def _cleanup_loop(self) -> None:
        """Periodically destroy expired sessions."""
        try:
            while True:
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
                await self._cleanup_expired()
        except asyncio.CancelledError:
            pass

    async def _cleanup_expired(self) -> None:
        expired_ids = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]
        for sid in expired_ids:
            logger.info(f"Auto-destroying expired SSH session {sid}")
            await self.destroy_session(sid)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_session(
        self,
        hosts: List[str],
        username: str,
        password: str,
        port: int = 22,
        connect_timeout: float = 30.0,
    ) -> SSHSession:
        """Create a new session and connect to all nodes in parallel."""
        session_id = str(uuid4())
        session = SSHSession(
            session_id=session_id,
            username=username,
            password=password,
            port=port,
        )

        semaphore = asyncio.Semaphore(MAX_PARALLEL_CONNECTIONS)

        async def _connect_node(host: str) -> NodeConnection:
            async with semaphore:
                node = NodeConnection(host=host)
                try:
                    client = CUCMSSHClient(
                        host=host,
                        port=port,
                        username=username,
                        password=password,
                        connect_timeout=connect_timeout,
                    )
                    await client.connect()
                    node.client = client
                    node.connected = True
                    logger.info(f"[session={session_id[:8]}] Connected to {host}")
                except Exception as exc:
                    node.error = str(exc)
                    logger.warning(
                        f"[session={session_id[:8]}] Failed to connect to {host}: {exc}"
                    )
                return node

        results = await asyncio.gather(
            *[_connect_node(h) for h in hosts],
            return_exceptions=False,
        )

        for node in results:
            session.nodes[node.host] = node

        self._sessions[session_id] = session
        logger.info(
            f"SSH session {session_id[:8]} created with "
            f"{sum(1 for n in session.nodes.values() if n.connected)}/{len(hosts)} nodes connected"
        )
        return session

    def get_session(self, session_id: str) -> Optional[SSHSession]:
        """Retrieve a session and touch its last_used_at."""
        session = self._sessions.get(session_id)
        if session:
            session.touch()
        return session

    async def destroy_session(self, session_id: str) -> bool:
        """Disconnect all nodes and remove session."""
        session = self._sessions.pop(session_id, None)
        if not session:
            return False

        for node in session.nodes.values():
            if node.client and node.connected:
                try:
                    await node.client.disconnect()
                    logger.info(f"[session={session_id[:8]}] Disconnected from {node.host}")
                except Exception as exc:
                    logger.warning(
                        f"[session={session_id[:8]}] Error disconnecting from {node.host}: {exc}"
                    )
                node.connected = False

        logger.info(f"SSH session {session_id[:8]} destroyed")
        return True

    def list_sessions(self) -> List[SSHSession]:
        """Return all active sessions."""
        return list(self._sessions.values())

    # ------------------------------------------------------------------
    # Command execution helpers
    # ------------------------------------------------------------------

    async def execute_on_node(
        self,
        session_id: str,
        host: str,
        command: str,
        timeout: float = 120.0,
    ) -> str:
        """Execute a command on a specific node using an existing connection."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        node = session.nodes.get(host)
        if not node or not node.connected or not node.client:
            raise ValueError(f"Node {host} is not connected in session {session_id}")

        async with session.lock:
            return await node.client.execute_command(command, timeout=timeout)

    async def execute_on_all_nodes(
        self,
        session_id: str,
        command: str,
        timeout: float = 120.0,
    ) -> Dict[str, Tuple[bool, str]]:
        """Execute a command on all connected nodes in parallel.

        Returns dict of {host: (success, output_or_error)}.
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        connected_nodes = [
            n for n in session.nodes.values()
            if n.connected and n.client
        ]

        async def _run(node: NodeConnection) -> Tuple[str, bool, str]:
            try:
                output = await node.client.execute_command(command, timeout=timeout)
                return (node.host, True, output)
            except Exception as exc:
                return (node.host, False, str(exc))

        results = await asyncio.gather(*[_run(n) for n in connected_nodes])
        return {host: (ok, out) for host, ok, out in results}


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_ssh_session_manager: Optional[SSHSessionManager] = None


def get_ssh_session_manager() -> SSHSessionManager:
    global _ssh_session_manager
    if _ssh_session_manager is None:
        _ssh_session_manager = SSHSessionManager()
    return _ssh_session_manager
