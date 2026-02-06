"""Investigation orchestration service"""

import asyncio
import json
import logging
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import get_settings
from app.environment_service import get_environment_manager
from app.models import (
    CreateInvestigationRequest,
    DeviceEntryCreate,
    InvestigationDevice,
    InvestigationDeviceStatus,
    InvestigationEvent,
    InvestigationPhase,
    InvestigationStatus,
    InvestigationStatusResponse,
    EnvironmentDeviceType,
)
from app.environment_service import DEVICE_DEFAULTS

logger = logging.getLogger(__name__)


class CredentialCache:
    """In-memory credential cache keyed by investigation_id. Never persisted."""

    TTL = 1800  # 30 minutes

    def __init__(self):
        self._store: Dict[str, Tuple[dict, datetime]] = {}

    def store(self, inv_id: str, credentials: dict):
        self._store[inv_id] = (credentials, datetime.now(timezone.utc))

    def get(self, inv_id: str) -> Optional[dict]:
        entry = self._store.get(inv_id)
        if not entry:
            return None
        creds, last_used = entry
        elapsed = (datetime.now(timezone.utc) - last_used).total_seconds()
        if elapsed > self.TTL:
            self.clear(inv_id)
            return None
        # Touch
        self._store[inv_id] = (creds, datetime.now(timezone.utc))
        return creds

    def clear(self, inv_id: str):
        self._store.pop(inv_id, None)

    def cleanup_expired(self):
        now = datetime.now(timezone.utc)
        expired = [
            k for k, (_, last_used) in self._store.items()
            if (now - last_used).total_seconds() > self.TTL
        ]
        for k in expired:
            del self._store[k]


class Investigation:
    """Represents a single investigation session"""

    def __init__(self, investigation_id: str, name: str, scenario: str,
                 environment_id: str, devices: List[InvestigationDevice],
                 operations: List[str], active_phases: List[str],
                 phases: Optional[List[InvestigationPhase]] = None,
                 status: InvestigationStatus = InvestigationStatus.CREATED,
                 # Operation config
                 cucm_profile: Optional[str] = None,
                 expressway_profile: Optional[str] = None,
                 trace_level: Optional[str] = None,
                 capture_mode: Optional[str] = None,
                 capture_duration_sec: Optional[int] = None,
                 capture_filter: Optional[dict] = None,
                 health_checks: Optional[List[str]] = None,
                 # Sub-operation references
                 capture_session_id: Optional[str] = None,
                 job_ids: Optional[List[str]] = None,
                 log_collection_ids: Optional[List[str]] = None,
                 health_results: Optional[dict] = None,
                 bundle_path: Optional[str] = None,
                 # Timestamps
                 created_at: Optional[datetime] = None,
                 started_at: Optional[datetime] = None,
                 completed_at: Optional[datetime] = None,
                 events: Optional[List[InvestigationEvent]] = None):
        self.investigation_id = investigation_id
        self.name = name
        self.scenario = scenario
        self.status = status
        self.environment_id = environment_id
        self.devices = devices
        self.operations = operations
        self.active_phases = active_phases
        self.phases = phases or self._build_phases(active_phases)
        # Config
        self.cucm_profile = cucm_profile
        self.expressway_profile = expressway_profile
        self.trace_level = trace_level
        self.capture_mode = capture_mode
        self.capture_duration_sec = capture_duration_sec
        self.capture_filter = capture_filter
        self.health_checks = health_checks or []
        # Sub-operation references
        self.capture_session_id = capture_session_id
        self.job_ids = job_ids or []
        self.log_collection_ids = log_collection_ids or []
        self.health_results = health_results
        self.bundle_path = bundle_path
        # Timestamps
        now = datetime.now(timezone.utc)
        self.created_at = created_at or now
        self.started_at = started_at
        self.completed_at = completed_at
        self.recording_started_at: Optional[datetime] = None
        self.events = events or []

    @staticmethod
    def _build_phases(active_phases: List[str]) -> List[InvestigationPhase]:
        all_phases = ["prepare", "record", "collect"]
        return [
            InvestigationPhase(
                name=p,
                status="pending" if p in active_phases else "skipped",
            )
            for p in all_phases
        ]

    def add_event(self, message: str, level: str = "info"):
        self.events.append(InvestigationEvent(
            timestamp=datetime.now(timezone.utc),
            message=message,
            level=level,
        ))

    def get_phase(self, name: str) -> Optional[InvestigationPhase]:
        for p in self.phases:
            if p.name == name:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "name": self.name,
            "scenario": self.scenario,
            "status": self.status.value,
            "environment_id": self.environment_id,
            "devices": [d.model_dump(mode="json") for d in self.devices],
            "operations": self.operations,
            "active_phases": self.active_phases,
            "phases": [p.model_dump(mode="json") for p in self.phases],
            "cucm_profile": self.cucm_profile,
            "expressway_profile": self.expressway_profile,
            "trace_level": self.trace_level,
            "capture_mode": self.capture_mode,
            "capture_duration_sec": self.capture_duration_sec,
            "capture_filter": self.capture_filter,
            "health_checks": self.health_checks,
            "capture_session_id": self.capture_session_id,
            "job_ids": self.job_ids,
            "log_collection_ids": self.log_collection_ids,
            "health_results": self.health_results,
            "bundle_path": self.bundle_path,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "events": [e.model_dump(mode="json") for e in self.events],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Investigation":
        devices = [InvestigationDevice(**d) for d in data.get("devices", [])]
        phases = [InvestigationPhase(**p) for p in data.get("phases", [])]
        events = [InvestigationEvent(**e) for e in data.get("events", [])]
        return cls(
            investigation_id=data["investigation_id"],
            name=data["name"],
            scenario=data["scenario"],
            status=InvestigationStatus(data["status"]),
            environment_id=data["environment_id"],
            devices=devices,
            operations=data.get("operations", []),
            active_phases=data.get("active_phases", []),
            phases=phases,
            cucm_profile=data.get("cucm_profile"),
            expressway_profile=data.get("expressway_profile"),
            trace_level=data.get("trace_level"),
            capture_mode=data.get("capture_mode"),
            capture_duration_sec=data.get("capture_duration_sec"),
            capture_filter=data.get("capture_filter"),
            health_checks=data.get("health_checks", []),
            capture_session_id=data.get("capture_session_id"),
            job_ids=data.get("job_ids", []),
            log_collection_ids=data.get("log_collection_ids", []),
            health_results=data.get("health_results"),
            bundle_path=data.get("bundle_path"),
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            events=events,
        )

    def save(self):
        settings = get_settings()
        file_path = settings.investigations_dir / f"{self.investigation_id}.json"
        tmp_path = file_path.with_suffix(".json.tmp")
        try:
            data = json.dumps(self.to_dict(), indent=2, default=str)
            with open(tmp_path, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(str(tmp_path), str(file_path))
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    def to_status_response(self) -> InvestigationStatusResponse:
        return InvestigationStatusResponse(
            investigation_id=self.investigation_id,
            name=self.name,
            scenario=self.scenario,
            status=self.status,
            environment_id=self.environment_id,
            devices=self.devices,
            phases=self.phases,
            active_phases=self.active_phases,
            operations=self.operations,
            capture_session_id=self.capture_session_id,
            job_ids=self.job_ids,
            log_collection_ids=self.log_collection_ids,
            health_results=self.health_results,
            capture_duration_sec=self.capture_duration_sec,
            recording_started_at=self.recording_started_at,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            bundle_path=self.bundle_path,
            download_available=self.bundle_path is not None,
            events=self.events,
        )


def _compute_active_phases(operations: List[str]) -> List[str]:
    """Determine which phases are active based on selected operations"""
    phases = []
    has_trace = "trace" in operations
    has_health = "health" in operations
    has_capture = "capture" in operations
    has_logs = "logs" in operations

    # Prepare phase: if traces or health are selected
    if has_trace or has_health:
        phases.append("prepare")

    # Record phase: if captures are selected
    if has_capture:
        phases.append("record")

    # Collect phase: if logs or captures are selected (need to collect files)
    if has_logs or has_capture:
        phases.append("collect")

    return phases


class InvestigationManager:
    """Manages investigations with delegation to existing services"""

    def __init__(self):
        self.investigations: Dict[str, Investigation] = {}
        self.credential_cache = CredentialCache()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        # Pooled CUCM SSH connections: inv_id -> {host -> CUCMSSHClient}
        # Reused across trace set (prepare) and trace reset (collect) to avoid
        # redundant SSH handshakes + CLI startup (~5-7s each)
        self._cucm_clients: Dict[str, Dict[str, 'CUCMSSHClient']] = {}
        self._load_existing()

    def _load_existing(self):
        settings = get_settings()
        inv_dir = settings.investigations_dir
        if not inv_dir.exists():
            return

        loaded = 0
        for file_path in sorted(inv_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            if file_path.name.endswith(".tmp"):
                continue
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                inv = Investigation.from_dict(data)
                self.investigations[inv.investigation_id] = inv
                loaded += 1
            except Exception as e:
                logger.error(f"Error loading investigation {file_path.name}: {e}")
                continue

        if loaded:
            logger.info(f"Loaded {loaded} investigation(s) from disk")

    def create(self, request: CreateInvestigationRequest) -> Investigation:
        devices = []
        environment_id = request.environment_id or ""

        if request.inline_devices:
            # Mode 2: Inline devices — create devices directly from the request
            for idx, inline_dev in enumerate(request.inline_devices):
                dev_id = str(uuid.uuid4())[:8]
                defaults = DEVICE_DEFAULTS.get(inline_dev.device_type, {"port": 22, "interface": "eth0"})
                devices.append(InvestigationDevice(
                    device_id=dev_id,
                    name=inline_dev.name,
                    host=inline_dev.host,
                    device_type=inline_dev.device_type,
                    port=inline_dev.port or defaults["port"],
                    interface=inline_dev.interface or defaults["interface"],
                ))
            environment_id = "inline"
        elif request.environment_id and request.device_ids:
            # Mode 1: Environment-based — select from existing environment
            env_mgr = get_environment_manager()
            env = env_mgr.get(request.environment_id)
            if not env:
                raise ValueError(f"Environment {request.environment_id} not found")

            env_device_ids = {d.id for d in env.devices}
            for did in request.device_ids:
                if did not in env_device_ids:
                    raise ValueError(f"Device {did} not found in environment {request.environment_id}")

            for did in request.device_ids:
                dev = env.get_device(did)
                if dev:
                    devices.append(InvestigationDevice(
                        device_id=dev.id,
                        name=dev.name,
                        host=dev.host,
                        device_type=dev.device_type,
                        port=dev.port,
                        interface=dev.interface,
                    ))
        else:
            raise ValueError("Must provide either inline_devices or environment_id + device_ids")

        # Determine active phases
        operations = request.operations or []
        active_phases = _compute_active_phases(operations)

        inv_id = str(uuid.uuid4())[:12]
        inv = Investigation(
            investigation_id=inv_id,
            name=request.name,
            scenario=request.scenario,
            environment_id=environment_id,
            devices=devices,
            operations=operations,
            active_phases=active_phases,
            cucm_profile=request.cucm_profile,
            expressway_profile=request.expressway_profile,
            trace_level=request.trace_level,
            capture_mode=request.capture_mode,
            capture_duration_sec=request.capture_duration_sec,
            capture_filter=request.capture_filter.model_dump() if request.capture_filter else None,
            health_checks=request.health_checks,
        )

        # Cache credentials in memory (never saved to disk)
        # Remap index-based keys (device_0, device_1, ...) to actual device IDs
        remapped_creds = {}
        for key, value in request.credentials.items():
            if key.startswith("device_") and key[len("device_"):].isdigit():
                idx = int(key[len("device_"):])
                if idx < len(devices):
                    remapped_creds[devices[idx].device_id] = value
            else:
                remapped_creds[key] = value  # keep "global" and other keys
        self.credential_cache.store(inv_id, remapped_creds)

        inv.add_event(f"Investigation '{inv.name}' created with scenario '{inv.scenario}'")
        inv.save()
        self.investigations[inv_id] = inv
        logger.info(f"Created investigation: {inv.name} ({inv_id})")
        return inv

    def get(self, inv_id: str) -> Optional[Investigation]:
        return self.investigations.get(inv_id)

    def list_all(self) -> List[Investigation]:
        return sorted(
            self.investigations.values(),
            key=lambda i: i.created_at,
            reverse=True,
        )

    def delete(self, inv_id: str) -> bool:
        inv = self.investigations.pop(inv_id, None)
        if not inv:
            return False
        self.credential_cache.clear(inv_id)
        settings = get_settings()
        # Remove JSON file
        file_path = settings.investigations_dir / f"{inv_id}.json"
        if file_path.exists():
            file_path.unlink()
        # Remove investigation directory (bundle etc.)
        inv_dir = settings.investigations_dir / inv_id
        if inv_dir.exists():
            shutil.rmtree(inv_dir, ignore_errors=True)
        logger.info(f"Deleted investigation: {inv.name} ({inv_id})")
        return True

    def _get_device_creds(self, inv_id: str, device_id: str) -> Optional[Tuple[str, str]]:
        """Get username/password for a device from the credential cache"""
        creds = self.credential_cache.get(inv_id)
        if not creds:
            return None
        # Check device-specific credentials first
        if device_id in creds:
            dc = creds[device_id]
            return (dc.get("username", ""), dc.get("password", ""))
        # Fall back to global credentials
        if "global" in creds:
            gc = creds["global"]
            return (gc.get("username", ""), gc.get("password", ""))
        return None

    async def _get_cucm_client(self, inv_id: str, device: 'InvestigationDevice',
                               creds: tuple) -> 'CUCMSSHClient':
        """Get or create a pooled CUCM SSH client for this investigation.

        Connections are reused across phases (trace set → trace reset) to avoid
        the 5-7 second SSH handshake + CLI startup overhead per connection.
        """
        from app.ssh_client import CUCMSSHClient

        if inv_id not in self._cucm_clients:
            self._cucm_clients[inv_id] = {}

        clients = self._cucm_clients[inv_id]
        host = device.host

        if host in clients:
            client = clients[host]
            # Verify the connection is still usable
            if client._connection is not None and client._session is not None:
                return client
            # Connection dropped — clean up stale entry
            try:
                await client.disconnect()
            except Exception:
                pass
            del clients[host]

        # Create new connection
        client = CUCMSSHClient(
            host=device.host,
            username=creds[0],
            password=creds[1],
            port=device.port or 22,
        )
        await client.connect()
        clients[host] = client
        logger.info(f"Opened pooled CUCM connection to {host} for investigation {inv_id[:8]}")
        return client

    async def _disconnect_cucm_clients(self, inv_id: str):
        """Disconnect all pooled CUCM SSH clients for an investigation."""
        clients = self._cucm_clients.pop(inv_id, {})
        for host, client in clients.items():
            try:
                await client.disconnect()
                logger.info(f"Closed pooled CUCM connection to {host}")
            except Exception as e:
                logger.warning(f"Error closing pooled SSH to {host}: {e}")

    async def _set_trace_on_device(self, inv: 'Investigation', device: 'InvestigationDevice',
                                   creds: tuple, trace_level: str):
        """Set trace levels on a single CUCM device (runs in parallel).
        Uses pooled SSH connection that persists until trace reset."""
        try:
            from app.job_manager import build_trace_set_commands

            commands = build_trace_set_commands(trace_level)
            client = await self._get_cucm_client(inv.investigation_id, device, creds)
            for cmd in commands:
                await client.execute_command(cmd)
            inv.add_event(f"Trace level set to {trace_level} on {device.name}")
            device.current_operation = "Traces configured"
        except Exception as e:
            device.status = InvestigationDeviceStatus.FAILED
            device.error = str(e)
            inv.add_event(f"Trace setup failed for {device.name}: {e}", level="error")
            logger.error(f"Trace setup failed for {device.name}: {e}")

    async def _run_health_checks(self, inv: 'Investigation'):
        """Run health checks on all devices (runs in parallel with traces)"""
        inv.add_event("Running health checks")
        # Update non-CUCM devices to show health check activity
        for device in inv.devices:
            if device.device_type != EnvironmentDeviceType.CUCM:
                device.current_operation = "Running health check"
        inv.save()
        try:
            from app.device_health_service import check_device_health
            from app.models import DeviceHealthRequest, DeviceHealthTarget, DeviceType

            device_type_map = {
                EnvironmentDeviceType.CUCM: DeviceType.CUCM,
                EnvironmentDeviceType.CUBE: DeviceType.CUBE,
                EnvironmentDeviceType.EXPRESSWAY: DeviceType.EXPRESSWAY,
            }
            targets = []
            for device in inv.devices:
                dt = device_type_map.get(device.device_type)
                if not dt:
                    continue
                creds = self._get_device_creds(inv.investigation_id, device.device_id)
                if not creds:
                    continue
                targets.append(DeviceHealthTarget(
                    device_type=dt,
                    host=device.host,
                    username=creds[0],
                    password=creds[1],
                ))

            if targets:
                health_req = DeviceHealthRequest(devices=targets)
                result = await check_device_health(health_req)
                inv.health_results = result.model_dump(mode="json")
                inv.add_event(f"Health checks completed: {result.overall_status.value}")
                # Update device statuses from health results
                for device in inv.devices:
                    if device.current_operation == "Running health check":
                        device.current_operation = "Health check done"
                inv.save()
        except Exception as e:
            inv.add_event(f"Health checks failed: {e}", level="error")
            logger.error(f"Health checks failed: {e}")

    async def start_preparation(self, inv_id: str):
        """Phase 1: Set traces, run health baseline"""
        inv = self.get(inv_id)
        if not inv:
            return

        inv.status = InvestigationStatus.PREPARING
        inv.started_at = datetime.now(timezone.utc)
        phase = inv.get_phase("prepare")
        if phase:
            phase.status = "in_progress"
            phase.started_at = datetime.now(timezone.utc)
        inv.add_event("Preparation phase started")
        inv.save()

        try:
            # Mark ALL devices as preparing up-front so UI shows activity on all
            for device in inv.devices:
                device.status = InvestigationDeviceStatus.PREPARING
                if "trace" in inv.operations and device.device_type == EnvironmentDeviceType.CUCM:
                    device.current_operation = "Setting trace levels"
                elif "health" in inv.operations:
                    device.current_operation = "Running health check"
                else:
                    device.current_operation = "Preparing"
            inv.save()

            # Build parallel preparation tasks
            prep_tasks: list[asyncio.Task] = []

            # Set trace levels on CUCM devices if trace operation selected
            if "trace" in inv.operations and inv.trace_level:
                cucm_devices = [d for d in inv.devices if d.device_type == EnvironmentDeviceType.CUCM]
                for device in cucm_devices:
                    creds = self._get_device_creds(inv_id, device.device_id)
                    if not creds:
                        device.status = InvestigationDeviceStatus.FAILED
                        device.error = "No credentials available"
                        inv.add_event(f"Trace setup failed for {device.name}: no credentials", level="error")
                        continue

                    task = asyncio.create_task(
                        self._set_trace_on_device(inv, device, creds, inv.trace_level)
                    )
                    prep_tasks.append(task)

            # Run health checks in parallel with traces
            if "health" in inv.operations:
                task = asyncio.create_task(self._run_health_checks(inv))
                prep_tasks.append(task)

            inv.save()

            # Wait for all preparation tasks to finish in parallel
            if prep_tasks:
                await asyncio.gather(*prep_tasks, return_exceptions=True)

            # Mark prepare phase complete
            if phase:
                phase.status = "completed"
                phase.completed_at = datetime.now(timezone.utc)

            # Mark all pending devices as ready
            for device in inv.devices:
                if device.status in (InvestigationDeviceStatus.PENDING, InvestigationDeviceStatus.PREPARING):
                    device.status = InvestigationDeviceStatus.READY
                    device.current_operation = None

            # Determine next status
            if "record" in inv.active_phases:
                inv.status = InvestigationStatus.READY
                inv.add_event("Preparation complete. Ready for recording.")
            elif "collect" in inv.active_phases:
                inv.status = InvestigationStatus.READY
                inv.add_event("Preparation complete. Ready for collection.")
            else:
                inv.status = InvestigationStatus.COMPLETED
                inv.completed_at = datetime.now(timezone.utc)
                inv.add_event("Investigation completed (prepare-only)")
                await self._disconnect_cucm_clients(inv_id)
                self.credential_cache.clear(inv_id)

        except Exception as e:
            inv.status = InvestigationStatus.FAILED
            inv.completed_at = datetime.now(timezone.utc)
            inv.add_event(f"Preparation failed: {e}", level="error")
            if phase:
                phase.status = "failed"
                phase.completed_at = datetime.now(timezone.utc)
            await self._disconnect_cucm_clients(inv_id)
            self.credential_cache.clear(inv_id)
            logger.error(f"Investigation {inv_id} preparation failed: {e}")

        inv.save()

    def signal_ready(self, inv_id: str):
        """User confirms ready to proceed"""
        inv = self.get(inv_id)
        if not inv:
            raise ValueError(f"Investigation {inv_id} not found")
        if inv.status not in (InvestigationStatus.PREPARING, InvestigationStatus.READY):
            raise ValueError(f"Cannot signal ready from status {inv.status.value}")
        inv.status = InvestigationStatus.READY
        inv.add_event("Ready signal received")
        inv.save()

    async def start_recording(self, inv_id: str):
        """Phase 2: Start capture sessions"""
        inv = self.get(inv_id)
        if not inv:
            return

        inv.status = InvestigationStatus.RECORDING
        inv.recording_started_at = datetime.now(timezone.utc)
        phase = inv.get_phase("record")
        if phase:
            phase.status = "in_progress"
            phase.started_at = datetime.now(timezone.utc)
        inv.add_event("Recording phase started")
        inv.save()

        try:
            if "capture" in inv.operations:
                from app.capture_session_service import get_session_manager
                from app.models import (
                    StartCaptureSessionRequest,
                    CaptureTargetRequest,
                    CaptureMode,
                    CaptureDeviceType,
                    CaptureFilter,
                )

                # Map environment device types to capture device types
                type_map = {
                    EnvironmentDeviceType.CUCM: CaptureDeviceType.CUCM,
                    EnvironmentDeviceType.CUBE: CaptureDeviceType.CUBE,
                    EnvironmentDeviceType.CSR1000V: CaptureDeviceType.CSR1000V,
                    EnvironmentDeviceType.EXPRESSWAY: CaptureDeviceType.EXPRESSWAY,
                }

                targets = []
                global_creds = self._get_device_creds(inv_id, "__global__")
                for device in inv.devices:
                    cdt = type_map.get(device.device_type)
                    if not cdt:
                        continue
                    creds = self._get_device_creds(inv_id, device.device_id)
                    if not creds:
                        continue
                    targets.append(CaptureTargetRequest(
                        device_type=cdt,
                        host=device.host,
                        port=device.port,
                        interface=device.interface,
                        username=creds[0],
                        password=creds[1],
                    ))

                if targets:
                    capture_mode = CaptureMode.STANDARD
                    if inv.capture_mode == "rotating":
                        capture_mode = CaptureMode.ROTATING

                    cap_filter = None
                    if inv.capture_filter:
                        cap_filter = CaptureFilter(**inv.capture_filter)

                    session_req = StartCaptureSessionRequest(
                        name=f"inv-{inv.investigation_id}",
                        mode=capture_mode,
                        duration_sec=inv.capture_duration_sec or 120,
                        filter=cap_filter,
                        targets=targets,
                    )

                    session_mgr = get_session_manager()
                    session = session_mgr.create_session(session_req)
                    inv.capture_session_id = session.session_id
                    inv.add_event(f"Capture session created: {session.session_id}")

                    # Actually start captures on all targets
                    await session_mgr.start_session(session, session_req)
                    inv.add_event(f"Capture session started on {len(session.capture_ids)} device(s)")

                    for device in inv.devices:
                        device.status = InvestigationDeviceStatus.RECORDING
                        device.current_operation = "Capturing"
                    inv.save()

                    # Auto-transition: wait for capture duration then collect
                    duration = inv.capture_duration_sec or 120
                    inv.add_event(f"Captures running for {duration}s, will auto-collect when done")
                    inv.save()
                    asyncio.create_task(self._auto_collect_after_recording(inv_id, duration))

            if phase:
                phase.status = "completed"
                phase.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            inv.status = InvestigationStatus.FAILED
            inv.completed_at = datetime.now(timezone.utc)
            inv.add_event(f"Recording failed: {e}", level="error")
            if phase:
                phase.status = "failed"
                phase.completed_at = datetime.now(timezone.utc)
            self.credential_cache.clear(inv_id)
            logger.error(f"Investigation {inv_id} recording failed: {e}")

        inv.save()

    async def _auto_collect_after_recording(self, inv_id: str, duration_sec: int):
        """Background task: monitor captures and auto-trigger collection when all done"""
        try:
            from app.capture_session_service import get_session_manager
            from app.models import CaptureSessionStatus as CSStat

            # Wait for the capture duration first
            await asyncio.sleep(duration_sec)

            inv = self.get(inv_id)
            if not inv or inv.status != InvestigationStatus.RECORDING:
                logger.info(f"Skipping auto-collect for {inv_id}: status changed")
                return

            # Now poll the capture session until all captures finish their file retrieval
            # (different devices take different times to download their pcaps)
            terminal = {CSStat.COMPLETED, CSStat.PARTIAL, CSStat.FAILED, CSStat.CANCELLED}
            if inv.capture_session_id:
                session_mgr = get_session_manager()
                inv.add_event("Capture duration elapsed, waiting for file retrieval...")
                inv.save()
                for _ in range(60):  # max 120s extra wait
                    session = session_mgr.get_session(inv.capture_session_id)
                    if not session:
                        break
                    session.update_overall_status()
                    if session.status in terminal:
                        logger.info(f"All captures completed for {inv_id}: {session.status.value}")
                        break
                    await asyncio.sleep(2)

            inv = self.get(inv_id)
            if inv and inv.status == InvestigationStatus.RECORDING:
                logger.info(f"Auto-collecting investigation {inv_id}")
                inv.add_event("All captures complete, auto-transitioning to collection")
                await self.stop_and_collect(inv_id)
        except Exception as e:
            logger.error(f"Auto-collect failed for {inv_id}: {e}")
            await self._disconnect_cucm_clients(inv_id)

    async def stop_and_collect(self, inv_id: str):
        """Phase 3: Stop captures, collect logs, create bundle"""
        inv = self.get(inv_id)
        if not inv:
            return

        inv.status = InvestigationStatus.COLLECTING
        phase = inv.get_phase("collect")
        if phase:
            phase.status = "in_progress"
            phase.started_at = datetime.now(timezone.utc)
        inv.add_event("Collection phase started")
        inv.save()

        try:
            # Stop capture session if active and wait for file retrieval
            if inv.capture_session_id:
                try:
                    from app.capture_session_service import get_session_manager
                    from app.models import CaptureSessionStatus as CSStat
                    session_mgr = get_session_manager()
                    await session_mgr.stop_session(inv.capture_session_id)
                    inv.add_event("Capture session stop signal sent, waiting for files...")
                    inv.save()

                    # Poll until captures reach terminal state (max 120s)
                    terminal = {CSStat.COMPLETED, CSStat.PARTIAL, CSStat.FAILED, CSStat.CANCELLED}
                    for _ in range(60):
                        session = session_mgr.get_session(inv.capture_session_id)
                        if not session:
                            break
                        session.update_overall_status()
                        if session.status in terminal:
                            break
                        await asyncio.sleep(2)

                    inv.add_event("Capture session stopped and files retrieved")
                except Exception as e:
                    inv.add_event(f"Error stopping captures: {e}", level="warning")

            # Track async tasks we need to wait for before bundling
            pending_tasks: list[asyncio.Task] = []

            # Collect CUCM logs if selected
            if "logs" in inv.operations:
                cucm_devices = [d for d in inv.devices if d.device_type == EnvironmentDeviceType.CUCM]
                if cucm_devices and inv.cucm_profile:
                    for device in cucm_devices:
                        device.status = InvestigationDeviceStatus.COLLECTING
                        device.current_operation = "Collecting logs"

                    inv.save()
                    inv.add_event("CUCM log collection started")

                    # Use job manager to collect CUCM logs
                    try:
                        from app.job_manager import get_job_manager

                        # Find a publisher device
                        publisher = next(
                            (d for d in cucm_devices if d.device_type == EnvironmentDeviceType.CUCM),
                            cucm_devices[0] if cucm_devices else None,
                        )
                        if publisher:
                            creds = self._get_device_creds(inv_id, publisher.device_id)
                            if creds:
                                from app.models import CreateJobRequest
                                job_mgr = get_job_manager()
                                nodes = [d.host for d in cucm_devices]
                                job_req = CreateJobRequest(
                                    publisher_host=publisher.host,
                                    port=publisher.port or 22,
                                    username=creds[0],
                                    password=creds[1],
                                    nodes=nodes,
                                    profile=inv.cucm_profile or "callmanager_full",
                                )
                                job = job_mgr.create_job(job_req)
                                inv.job_ids.append(job.job_id)
                                inv.add_event(f"CUCM log job created: {job.job_id}")

                                # Start the job and track it
                                task = asyncio.create_task(job_mgr.execute_job(job.job_id))
                                pending_tasks.append(task)
                    except Exception as e:
                        inv.add_event(f"CUCM log collection failed: {e}", level="error")
                        logger.error(f"CUCM log collection failed: {e}")

                # Collect CUBE/Expressway logs
                non_cucm_devices = [
                    d for d in inv.devices
                    if d.device_type in (EnvironmentDeviceType.CUBE, EnvironmentDeviceType.EXPRESSWAY)
                ]
                for device in non_cucm_devices:
                    device.status = InvestigationDeviceStatus.COLLECTING
                    device.current_operation = "Collecting logs"
                    inv.save()

                    creds = self._get_device_creds(inv_id, device.device_id)
                    if not creds:
                        device.error = "No credentials"
                        continue

                    try:
                        from app.log_service import get_log_collection_manager
                        from app.models import StartLogCollectionRequest, LogDeviceType

                        log_device_type = (
                            LogDeviceType.CUBE if device.device_type == EnvironmentDeviceType.CUBE
                            else LogDeviceType.EXPRESSWAY
                        )
                        profile = (
                            inv.expressway_profile
                            if device.device_type == EnvironmentDeviceType.EXPRESSWAY
                            else None
                        )

                        log_req = StartLogCollectionRequest(
                            device_type=log_device_type,
                            host=device.host,
                            username=creds[0],
                            password=creds[1],
                            profile=profile,
                        )
                        log_mgr = get_log_collection_manager()
                        collection = log_mgr.create_collection(log_req)
                        inv.log_collection_ids.append(collection.collection_id)
                        # Start the actual collection and track it
                        task = asyncio.create_task(log_mgr.execute_collection(collection.collection_id))
                        pending_tasks.append(task)
                        inv.add_event(f"Log collection started for {device.name}: {collection.collection_id}")
                    except Exception as e:
                        device.error = str(e)
                        inv.add_event(f"Log collection failed for {device.name}: {e}", level="error")

            # Wait for all sub-operations to complete before bundling
            if pending_tasks:
                inv.add_event(f"Waiting for {len(pending_tasks)} collection task(s) to complete")
                inv.save()
                results = await asyncio.gather(*pending_tasks, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        inv.add_event(f"Collection task {i} failed: {result}", level="warning")
                        logger.error(f"Collection task {i} failed for {inv_id}: {result}")
                inv.add_event("All collection tasks completed")

            # Mark phase complete
            if phase:
                phase.status = "completed"
                phase.completed_at = datetime.now(timezone.utc)

            # Reset trace levels on CUCM devices (reuses pooled SSH connections)
            if "trace" in inv.operations:
                cucm_devices = [d for d in inv.devices if d.device_type == EnvironmentDeviceType.CUCM]
                for device in cucm_devices:
                    creds = self._get_device_creds(inv_id, device.device_id)
                    if not creds:
                        continue
                    try:
                        from app.job_manager import build_trace_reset_commands

                        commands = build_trace_reset_commands()
                        client = await self._get_cucm_client(inv_id, device, creds)
                        for cmd in commands:
                            await client.execute_command(cmd)
                        inv.add_event(f"Trace levels reset on {device.name}")
                    except Exception as e:
                        inv.add_event(f"Trace reset failed for {device.name}: {e}", level="warning")

            # Start bundling
            inv.status = InvestigationStatus.BUNDLING
            inv.add_event("Creating artifact bundle")
            inv.save()

            try:
                bundle_path = await self._create_bundle(inv)
                if bundle_path:
                    inv.bundle_path = str(bundle_path)
                    inv.add_event(f"Bundle created: {bundle_path.name}")
            except Exception as e:
                inv.add_event(f"Bundle creation failed: {e}", level="warning")
                logger.error(f"Bundle creation failed for {inv_id}: {e}")

            # Mark devices complete
            for device in inv.devices:
                if device.status not in (InvestigationDeviceStatus.FAILED, InvestigationDeviceStatus.SKIPPED):
                    device.status = InvestigationDeviceStatus.COMPLETED
                    device.current_operation = None

            # Determine final status
            failed = [d for d in inv.devices if d.status == InvestigationDeviceStatus.FAILED]
            completed = [d for d in inv.devices if d.status == InvestigationDeviceStatus.COMPLETED]
            if len(failed) == len(inv.devices):
                inv.status = InvestigationStatus.FAILED
            elif failed:
                inv.status = InvestigationStatus.PARTIAL
            else:
                inv.status = InvestigationStatus.COMPLETED

            inv.completed_at = datetime.now(timezone.utc)
            inv.add_event(f"Investigation {inv.status.value}")

        except Exception as e:
            inv.status = InvestigationStatus.FAILED
            inv.completed_at = datetime.now(timezone.utc)
            inv.add_event(f"Collection failed: {e}", level="error")
            if phase:
                phase.status = "failed"
                phase.completed_at = datetime.now(timezone.utc)
            logger.error(f"Investigation {inv_id} collection failed: {e}")

        # Clean up pooled SSH connections and credentials
        await self._disconnect_cucm_clients(inv_id)
        self.credential_cache.clear(inv_id)
        inv.save()

    async def _create_bundle(self, inv: Investigation) -> Optional[Path]:
        """Create a ZIP bundle of all artifacts"""
        settings = get_settings()
        inv_dir = settings.investigations_dir / inv.investigation_id
        inv_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = inv_dir / "bundle.zip"

        has_content = False
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add capture session files - look up per-device capture IDs from session
            if inv.capture_session_id:
                try:
                    from app.capture_session_service import get_session_manager
                    from app.capture_service import CaptureManager
                    session_mgr = get_session_manager()
                    capture_mgr = CaptureManager.get_instance()
                    session = session_mgr.get_session(inv.capture_session_id)
                    if session:
                        for host, capture_id in session.capture_ids.items():
                            found = False
                            # Check directory-based storage (Expressway in captures/, CUCM in received/)
                            for search_dir in [
                                settings.storage_root / "captures" / capture_id,
                                settings.artifacts_dir / capture_id,
                            ]:
                                if search_dir.exists() and search_dir.is_dir():
                                    for f in search_dir.rglob("*"):
                                        if f.is_file():
                                            arcname = f"captures/{host}/{f.name}"
                                            zf.write(f, arcname)
                                            has_content = True
                                            found = True
                                            logger.info(f"Bundle: added capture {f.name} for {host}")

                            # If not found in directory, check the capture's local_file_path
                            # (CUBE/CSR exports via SCP to uploads/ as flat files)
                            if not found:
                                capture = capture_mgr.get_capture(capture_id)
                                if capture and capture.local_file_path and capture.local_file_path.exists():
                                    zf.write(capture.local_file_path, f"captures/{host}/{capture.local_file_path.name}")
                                    has_content = True
                                    found = True
                                    logger.info(f"Bundle: added capture {capture.local_file_path.name} for {host}")
                                # Also check rotating captures (multiple files)
                                if capture and capture.local_file_paths:
                                    for fp in capture.local_file_paths:
                                        if fp.exists():
                                            zf.write(fp, f"captures/{host}/{fp.name}")
                                            has_content = True
                                            found = True
                                            logger.info(f"Bundle: added capture {fp.name} for {host}")

                            if not found:
                                logger.warning(f"Bundle: no capture files found for {host} (capture_id={capture_id})")
                except Exception as e:
                    logger.error(f"Bundle: error adding captures: {e}")

            # Add job artifacts (CUCM logs via SFTP land in received/{job_id}/...)
            for job_id in inv.job_ids:
                job_dir = settings.artifacts_dir / job_id
                if job_dir.exists():
                    for f in job_dir.rglob("*"):
                        if f.is_file():
                            arcname = f"cucm_logs/{f.relative_to(job_dir)}"
                            zf.write(f, arcname)
                            has_content = True
                            logger.info(f"Bundle: added CUCM log {f.name}")

            # Add log collection files (stored in logs/{collection_id}/...)
            for coll_id in inv.log_collection_ids:
                coll_dir = settings.storage_root / "logs" / coll_id
                if coll_dir.exists() and coll_dir.is_dir():
                    for f in coll_dir.rglob("*"):
                        if f.is_file():
                            zf.write(f, f"device_logs/{coll_id}/{f.name}")
                            has_content = True
                            logger.info(f"Bundle: added device log {f.name}")

            # Add health results
            if inv.health_results:
                health_json = json.dumps(inv.health_results, indent=2, default=str)
                zf.writestr("health_results.json", health_json)
                has_content = True

            # Add investigation metadata
            meta = {
                "investigation_id": inv.investigation_id,
                "name": inv.name,
                "scenario": inv.scenario,
                "operations": inv.operations,
                "devices": [d.model_dump(mode="json") for d in inv.devices],
                "created_at": inv.created_at.isoformat(),
                "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
                "events": [e.model_dump(mode="json") for e in inv.events],
            }
            zf.writestr("investigation.json", json.dumps(meta, indent=2, default=str))
            has_content = True

        if not has_content:
            bundle_path.unlink(missing_ok=True)
            return None

        logger.info(f"Bundle created for {inv.investigation_id}: {bundle_path}")
        return bundle_path

    def cancel(self, inv_id: str):
        """Cancel a running investigation"""
        inv = self.get(inv_id)
        if not inv:
            return

        inv.status = InvestigationStatus.CANCELLED
        inv.completed_at = datetime.now(timezone.utc)
        inv.add_event("Investigation cancelled")

        # Cancel running tasks
        task = self._running_tasks.pop(inv_id, None)
        if task and not task.done():
            task.cancel()

        # Cancel sub-operations
        if inv.capture_session_id:
            try:
                from app.capture_session_service import get_session_manager
                session_mgr = get_session_manager()
                asyncio.create_task(session_mgr.stop_session(inv.capture_session_id))
            except Exception:
                pass

        for device in inv.devices:
            if device.status not in (InvestigationDeviceStatus.COMPLETED, InvestigationDeviceStatus.FAILED):
                device.status = InvestigationDeviceStatus.FAILED
                device.current_operation = None
                device.error = "Investigation cancelled"

        # Clean up pooled SSH connections (async, fire-and-forget)
        try:
            asyncio.get_running_loop().create_task(self._disconnect_cucm_clients(inv_id))
        except RuntimeError:
            pass  # No running event loop

        self.credential_cache.clear(inv_id)
        inv.save()


# Singleton
_inv_manager: Optional[InvestigationManager] = None


def get_investigation_manager() -> InvestigationManager:
    global _inv_manager
    if _inv_manager is None:
        _inv_manager = InvestigationManager()
    return _inv_manager
