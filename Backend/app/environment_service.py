"""Environment (Device Inventory) management service"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from app.config import get_settings
from app.models import (
    DeviceEntry,
    DeviceEntryCreate,
    EnvironmentDeviceType,
    EnvironmentResponse,
)

logger = logging.getLogger(__name__)

# Default ports and interfaces by device type
DEVICE_DEFAULTS = {
    EnvironmentDeviceType.CUCM: {"port": 22, "interface": "eth0"},
    EnvironmentDeviceType.CUBE: {"port": 22, "interface": "GigabitEthernet1"},
    EnvironmentDeviceType.CSR1000V: {"port": 22, "interface": "GigabitEthernet1"},
    EnvironmentDeviceType.EXPRESSWAY: {"port": 443, "interface": "eth0"},
}


class Environment:
    """Represents a device environment/inventory"""

    def __init__(self, env_id: str, name: str, description: Optional[str] = None,
                 devices: Optional[List[DeviceEntry]] = None,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None):
        self.id = env_id
        self.name = name
        self.description = description
        self.devices: List[DeviceEntry] = devices or []
        now = datetime.now(timezone.utc)
        self.created_at = created_at or now
        self.updated_at = updated_at or now

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "devices": [d.model_dump(mode="json") for d in self.devices],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Environment":
        devices = [DeviceEntry(**d) for d in data.get("devices", [])]
        return cls(
            env_id=data["id"],
            name=data["name"],
            description=data.get("description"),
            devices=devices,
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
        )

    def to_response(self) -> EnvironmentResponse:
        return EnvironmentResponse(
            id=self.id,
            name=self.name,
            description=self.description,
            devices=self.devices,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def save(self):
        settings = get_settings()
        file_path = settings.environments_dir / f"{self.id}.json"
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

    def add_device(self, create: DeviceEntryCreate) -> DeviceEntry:
        defaults = DEVICE_DEFAULTS.get(create.device_type, {"port": 22, "interface": "eth0"})
        device = DeviceEntry(
            id=str(uuid.uuid4())[:8],
            name=create.name,
            device_type=create.device_type,
            host=create.host,
            port=create.port or defaults["port"],
            interface=create.interface or defaults["interface"],
            role=create.role,
            tags=create.tags,
        )
        self.devices.append(device)
        self.updated_at = datetime.now(timezone.utc)
        return device

    def remove_device(self, device_id: str) -> bool:
        before = len(self.devices)
        self.devices = [d for d in self.devices if d.id != device_id]
        if len(self.devices) < before:
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def get_device(self, device_id: str) -> Optional[DeviceEntry]:
        for d in self.devices:
            if d.id == device_id:
                return d
        return None


class EnvironmentManager:
    """Manages device environments with JSON persistence"""

    def __init__(self):
        self.environments: Dict[str, Environment] = {}
        self._load_existing()

    def _load_existing(self):
        settings = get_settings()
        env_dir = settings.environments_dir
        if not env_dir.exists():
            return

        loaded = 0
        for file_path in sorted(env_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            if file_path.name.endswith(".tmp"):
                continue
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                env = Environment.from_dict(data)
                self.environments[env.id] = env
                loaded += 1
            except Exception as e:
                logger.error(f"Error loading environment {file_path.name}: {e}")
                continue

        if loaded:
            logger.info(f"Loaded {loaded} environment(s) from disk")

    def create(self, name: str, description: Optional[str] = None,
               devices: Optional[List[DeviceEntryCreate]] = None) -> Environment:
        env_id = str(uuid.uuid4())[:12]
        env = Environment(env_id=env_id, name=name, description=description)

        if devices:
            for d in devices:
                env.add_device(d)

        env.save()
        self.environments[env_id] = env
        logger.info(f"Created environment: {name} ({env_id}) with {len(env.devices)} device(s)")
        return env

    def get(self, env_id: str) -> Optional[Environment]:
        return self.environments.get(env_id)

    def list_all(self) -> List[Environment]:
        return sorted(self.environments.values(), key=lambda e: e.created_at, reverse=True)

    def update(self, env_id: str, name: Optional[str] = None,
               description: Optional[str] = None) -> Optional[Environment]:
        env = self.environments.get(env_id)
        if not env:
            return None
        if name is not None:
            env.name = name
        if description is not None:
            env.description = description
        env.updated_at = datetime.now(timezone.utc)
        env.save()
        return env

    def delete(self, env_id: str) -> bool:
        env = self.environments.pop(env_id, None)
        if not env:
            return False
        settings = get_settings()
        file_path = settings.environments_dir / f"{env_id}.json"
        if file_path.exists():
            file_path.unlink()
        logger.info(f"Deleted environment: {env.name} ({env_id})")
        return True

    def add_device(self, env_id: str, create: DeviceEntryCreate) -> Optional[Environment]:
        env = self.environments.get(env_id)
        if not env:
            return None
        env.add_device(create)
        env.save()
        return env

    def remove_device(self, env_id: str, device_id: str) -> Optional[Environment]:
        env = self.environments.get(env_id)
        if not env:
            return None
        if not env.remove_device(device_id):
            return None
        env.save()
        return env


# Singleton
_env_manager: Optional[EnvironmentManager] = None


def get_environment_manager() -> EnvironmentManager:
    global _env_manager
    if _env_manager is None:
        _env_manager = EnvironmentManager()
    return _env_manager
