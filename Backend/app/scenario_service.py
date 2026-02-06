"""Scenario template management"""

import logging
from pathlib import Path
from typing import List, Optional

import yaml

from app.models import ScenarioTemplate

logger = logging.getLogger(__name__)

SCENARIOS_PATH = Path(__file__).parent.parent / "scenarios.yaml"


class ScenarioManager:
    """Loads and manages scenario templates from YAML"""

    def __init__(self, path: Optional[Path] = None):
        self._scenarios: List[ScenarioTemplate] = []
        self._path = path or SCENARIOS_PATH
        self._load()

    def _load(self):
        if not self._path.exists():
            logger.warning(f"Scenarios file not found: {self._path}")
            return
        try:
            with open(self._path, "r") as f:
                data = yaml.safe_load(f)
            if not data or "scenarios" not in data:
                logger.warning("No scenarios found in file")
                return
            for item in data["scenarios"]:
                try:
                    self._scenarios.append(ScenarioTemplate(**item))
                except Exception as e:
                    logger.error(f"Error loading scenario: {e}")
            logger.info(f"Loaded {len(self._scenarios)} scenario template(s)")
        except Exception as e:
            logger.error(f"Error loading scenarios: {e}")

    def list_all(self) -> List[ScenarioTemplate]:
        return list(self._scenarios)

    def get(self, name: str) -> Optional[ScenarioTemplate]:
        for s in self._scenarios:
            if s.name == name:
                return s
        return None


_scenario_manager: Optional[ScenarioManager] = None


def get_scenario_manager() -> ScenarioManager:
    global _scenario_manager
    if _scenario_manager is None:
        _scenario_manager = ScenarioManager()
    return _scenario_manager
