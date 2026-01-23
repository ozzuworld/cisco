"""Capture Session Service - Multi-device capture orchestration"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path
import uuid

from app.models import (
    StartCaptureSessionRequest,
    CaptureSessionInfo,
    CaptureSessionStatus,
    CaptureTargetInfo,
    CaptureTargetStatus,
    StartCaptureRequest,
    CaptureDeviceType,
)
from app.capture_service import get_capture_manager
from app.config import get_settings

logger = logging.getLogger(__name__)


# Default ports by device type
DEFAULT_PORTS = {
    CaptureDeviceType.CUCM: 22,
    CaptureDeviceType.CUBE: 22,
    CaptureDeviceType.CSR1000V: 22,
    CaptureDeviceType.EXPRESSWAY: 443,
}

# Default interfaces by device type
DEFAULT_INTERFACES = {
    CaptureDeviceType.CUCM: "eth0",
    CaptureDeviceType.CUBE: "GigabitEthernet1",
    CaptureDeviceType.CSR1000V: "GigabitEthernet1",
    CaptureDeviceType.EXPRESSWAY: "eth0",
}


class CaptureSession:
    """Represents an orchestrated multi-device capture session"""

    def __init__(
        self,
        session_id: str,
        name: Optional[str],
        duration_sec: int,
        filter_config: Optional[dict],
        targets: List[CaptureTargetInfo],
    ):
        self.session_id = session_id
        self.name = name or f"Session {session_id[:8]}"
        self.status = CaptureSessionStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.capture_started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.duration_sec = duration_sec
        self.filter_config = filter_config
        self.targets = targets
        self.bundle_filename: Optional[str] = None

        # Track underlying capture IDs
        self.capture_ids: Dict[str, str] = {}  # host -> capture_id

    def to_info(self) -> CaptureSessionInfo:
        """Convert to CaptureSessionInfo model"""
        return CaptureSessionInfo(
            session_id=self.session_id,
            name=self.name,
            status=self.status,
            created_at=self.created_at,
            capture_started_at=self.capture_started_at,
            completed_at=self.completed_at,
            duration_sec=self.duration_sec,
            targets=self.targets,
            bundle_filename=self.bundle_filename,
        )

    def update_target_status(
        self,
        host: str,
        status: CaptureTargetStatus,
        message: Optional[str] = None,
        error: Optional[str] = None,
        **kwargs,
    ):
        """Update status of a specific target"""
        for target in self.targets:
            if target.host == host:
                target.status = status
                if message:
                    target.message = message
                if error:
                    target.error = error
                for key, value in kwargs.items():
                    if hasattr(target, key):
                        setattr(target, key, value)
                break

    def update_overall_status(self):
        """Update overall session status based on target statuses"""
        if not self.targets:
            self.status = CaptureSessionStatus.FAILED
            return

        statuses = [t.status for t in self.targets]

        # All targets completed successfully
        if all(s == CaptureTargetStatus.COMPLETED for s in statuses):
            self.status = CaptureSessionStatus.COMPLETED
            if not self.completed_at:
                self.completed_at = datetime.now(timezone.utc)
            return

        # Some completed, some failed
        completed_count = sum(1 for s in statuses if s == CaptureTargetStatus.COMPLETED)
        failed_count = sum(
            1 for s in statuses if s in [CaptureTargetStatus.FAILED, CaptureTargetStatus.CANCELLED]
        )

        if completed_count > 0 and failed_count > 0:
            # All targets finished, some succeeded
            if completed_count + failed_count == len(statuses):
                self.status = CaptureSessionStatus.PARTIAL
                if not self.completed_at:
                    self.completed_at = datetime.now(timezone.utc)
            return

        # All targets failed
        if all(s in [CaptureTargetStatus.FAILED, CaptureTargetStatus.CANCELLED] for s in statuses):
            self.status = CaptureSessionStatus.FAILED
            if not self.completed_at:
                self.completed_at = datetime.now(timezone.utc)
            return

        # Check for in-progress statuses
        if any(s == CaptureTargetStatus.CAPTURING for s in statuses):
            self.status = CaptureSessionStatus.CAPTURING
        elif any(s == CaptureTargetStatus.CONFIGURING for s in statuses):
            self.status = CaptureSessionStatus.CONFIGURING
        elif any(s in [CaptureTargetStatus.STOPPING, CaptureTargetStatus.COLLECTING] for s in statuses):
            self.status = CaptureSessionStatus.STOPPING


class CaptureSessionManager:
    """Manages orchestrated capture sessions"""

    def __init__(self):
        self.sessions: Dict[str, CaptureSession] = {}
        self.capture_manager = get_capture_manager()
        self.settings = get_settings()

    def create_session(self, request: StartCaptureSessionRequest) -> CaptureSession:
        """Create a new capture session"""
        session_id = str(uuid.uuid4())

        # Initialize targets
        targets = []
        for target_req in request.targets:
            # Determine credentials (target-specific or global fallback)
            username = target_req.username or request.username
            password = target_req.password or request.password

            if not username or not password:
                raise ValueError(
                    f"No credentials provided for target {target_req.host}. "
                    "Provide either per-target or global credentials."
                )

            # Determine port (target-specific or default by device type)
            port = target_req.port or DEFAULT_PORTS.get(target_req.device_type, 22)

            # Determine interface (target-specific or default by device type)
            interface = target_req.interface or DEFAULT_INTERFACES.get(target_req.device_type, "eth0")

            target_info = CaptureTargetInfo(
                device_type=target_req.device_type,
                host=target_req.host,
                port=port,
                interface=interface,
                status=CaptureTargetStatus.PENDING,
            )
            targets.append(target_info)

        # Create session
        session = CaptureSession(
            session_id=session_id,
            name=request.name,
            duration_sec=request.duration_sec,
            filter_config=request.filter.model_dump() if request.filter else None,
            targets=targets,
        )

        self.sessions[session_id] = session
        logger.info(f"Created capture session {session_id} with {len(targets)} targets")

        return session

    async def start_session(
        self, session: CaptureSession, request: StartCaptureSessionRequest
    ) -> CaptureSession:
        """Start captures on all targets in the session"""
        session.status = CaptureSessionStatus.STARTING
        session.capture_started_at = datetime.now(timezone.utc)

        # Start captures on all targets concurrently
        tasks = []
        for idx, target_req in enumerate(request.targets):
            target_info = session.targets[idx]
            task = self._start_target_capture(session, target_req, target_info)
            tasks.append(task)

        # Wait for all captures to start
        await asyncio.gather(*tasks, return_exceptions=True)

        # Update overall session status
        session.update_overall_status()

        return session

    async def _start_target_capture(
        self,
        session: CaptureSession,
        target_req,
        target_info: CaptureTargetInfo,
    ):
        """Start capture on a single target"""
        try:
            # Update target status
            session.update_target_status(
                target_info.host,
                CaptureTargetStatus.CONFIGURING,
                message="Starting capture...",
            )

            # Determine credentials
            username = target_req.username
            password = target_req.password

            if not username or not password:
                raise ValueError(f"Missing credentials for {target_info.host}")

            # Build capture request
            from app.models import CaptureFilter as ModelCaptureFilter

            capture_filter = None
            if session.filter_config:
                capture_filter = ModelCaptureFilter(**session.filter_config)

            capture_req = StartCaptureRequest(
                device_type=target_info.device_type,
                host=target_info.host,
                port=target_info.port,
                username=username,
                password=password,
                duration_sec=session.duration_sec,
                interface=target_info.interface,
                filter=capture_filter,
                packet_count=100000,
                connect_timeout_sec=30,
            )

            # Create the capture using existing capture service
            capture = self.capture_manager.create_capture(capture_req)

            # Start execution in background
            asyncio.create_task(self.capture_manager.execute_capture(capture.capture_id))

            # Update target with capture info
            session.capture_ids[target_info.host] = capture.capture_id
            session.update_target_status(
                target_info.host,
                CaptureTargetStatus.CAPTURING,
                message="Capture running",
                capture_id=capture.capture_id,
                capture_started_at=datetime.now(timezone.utc),
                filename=capture.filename,
            )

            logger.info(
                f"Started capture {capture.capture_id} for target {target_info.host} "
                f"in session {session.session_id}"
            )

        except Exception as e:
            logger.error(f"Failed to start capture for target {target_info.host}: {e}")
            session.update_target_status(
                target_info.host,
                CaptureTargetStatus.FAILED,
                error=str(e),
                message="Failed to start capture",
            )

    def get_session(self, session_id: str) -> Optional[CaptureSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)

    def list_sessions(self, limit: int = 50) -> List[CaptureSession]:
        """List recent sessions"""
        sessions = sorted(
            self.sessions.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return sessions[:limit]

    async def stop_session(self, session_id: str) -> Optional[CaptureSession]:
        """Stop all captures in a session"""
        session = self.get_session(session_id)
        if not session:
            return None

        session.status = CaptureSessionStatus.STOPPING

        # Stop all running captures
        tasks = []
        for target in session.targets:
            if target.status == CaptureTargetStatus.CAPTURING and target.capture_id:
                task = self._stop_target_capture(session, target)
                tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        session.update_overall_status()
        return session

    async def _stop_target_capture(self, session: CaptureSession, target: CaptureTargetInfo):
        """Stop capture on a single target"""
        try:
            session.update_target_status(
                target.host,
                CaptureTargetStatus.STOPPING,
                message="Stopping capture...",
            )

            await self.capture_manager.stop_capture(target.capture_id)

            session.update_target_status(
                target.host,
                CaptureTargetStatus.COMPLETED,
                message="Capture stopped",
                capture_stopped_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as e:
            logger.error(f"Failed to stop capture for target {target.host}: {e}")
            session.update_target_status(
                target.host,
                CaptureTargetStatus.FAILED,
                error=str(e),
                message="Failed to stop capture",
            )

    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Deleted capture session {session_id}")
            return True
        return False

    def get_session_bundle_path(self, session_id: str) -> Optional[Path]:
        """Get path to session bundle ZIP file (if it exists)"""
        session = self.get_session(session_id)
        if not session or not session.bundle_filename:
            return None

        bundle_path = Path(self.settings.artifacts_dir) / session.bundle_filename
        if bundle_path.exists():
            return bundle_path
        return None

    async def update_session_status(self, session_id: str):
        """Update session status by checking underlying captures"""
        session = self.get_session(session_id)
        if not session:
            return

        # Update each target's status from its underlying capture
        for target in session.targets:
            if target.capture_id:
                try:
                    capture = self.capture_manager.get_capture(target.capture_id)
                    if capture:
                        # Map capture status to target status
                        status_mapping = {
                            "pending": CaptureTargetStatus.PENDING,
                            "running": CaptureTargetStatus.CAPTURING,
                            "stopping": CaptureTargetStatus.STOPPING,
                            "completed": CaptureTargetStatus.COMPLETED,
                            "failed": CaptureTargetStatus.FAILED,
                            "cancelled": CaptureTargetStatus.CANCELLED,
                        }
                        new_status = status_mapping.get(capture.status, target.status)

                        session.update_target_status(
                            target.host,
                            new_status,
                            packets_captured=capture.packets_captured,
                            file_size_bytes=capture.file_size_bytes,
                            message=capture.message,
                            error=capture.error,
                        )
                except Exception as e:
                    logger.error(f"Error updating target {target.host} status: {e}")

        # Update overall session status
        session.update_overall_status()


# Singleton instance
_session_manager: Optional[CaptureSessionManager] = None


def get_session_manager() -> CaptureSessionManager:
    """Get the singleton capture session manager"""
    global _session_manager
    if _session_manager is None:
        _session_manager = CaptureSessionManager()
    return _session_manager
