"""Profile management for CUCM log collection"""

import logging
from pathlib import Path
from typing import List, Optional, Dict
import yaml
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)


class CollectionProfile(BaseModel):
    """
    Defines a log collection profile with paths and default options.

    A profile specifies which log files to collect and default collection parameters.
    """

    name: str = Field(..., description="Profile identifier (unique)")
    description: str = Field(..., description="Human-readable description")
    paths: List[str] = Field(..., description="List of activelog paths to collect")

    # Default collection options (can be overridden per job)
    reltime_minutes: int = Field(
        default=60,
        description="Default relative time window in minutes",
        ge=1,
        le=10080  # 1 week max
    )
    compress: bool = Field(
        default=True,
        description="Whether to compress collected logs"
    )
    recurs: bool = Field(
        default=False,
        description="Whether to collect logs recursively"
    )
    match: Optional[str] = Field(
        default=None,
        description="Optional regex pattern to match filenames"
    )
    trace_services: List[str] = Field(
        default_factory=list,
        description="CUCM services to configure trace levels for (used by Trace Level page)"
    )


class CubeProfile(BaseModel):
    """
    Defines a log collection profile for CUBE devices.

    Supports VoIP Trace and Debug collection methods.
    """

    name: str = Field(..., description="Profile identifier (unique)")
    description: str = Field(..., description="Human-readable description")
    device_type: str = Field(default="cube", description="Device type")
    method: str = Field(..., description="Collection method (voip_trace, debug, config)")
    commands: List[str] = Field(
        default_factory=list,
        description="List of commands to execute"
    )
    include_debug: bool = Field(
        default=False,
        description="Whether to enable debug (CPU intensive)"
    )
    duration_sec: int = Field(
        default=30,
        description="Duration for debug capture in seconds",
        ge=5,
        le=300
    )


class ExpresswayProfile(BaseModel):
    """
    Defines a log collection profile for Expressway devices.

    Supports diagnostic logging and event log collection.
    """

    name: str = Field(..., description="Profile identifier (unique)")
    description: str = Field(..., description="Human-readable description")
    device_type: str = Field(default="expressway", description="Device type")
    method: str = Field(..., description="Collection method (diagnostic, event_log)")
    tcpdump: bool = Field(
        default=False,
        description="Include packet capture in diagnostic logs"
    )


class ProfileCatalog:
    """
    Manages the catalog of available collection profiles.

    Loads profiles from a YAML file and provides lookup functionality.
    Supports CUCM, CUBE, and Expressway profiles.
    """

    def __init__(self, profiles_path: Path):
        """
        Initialize profile catalog.

        Args:
            profiles_path: Path to profiles YAML file
        """
        self.profiles_path = profiles_path
        self._profiles: Dict[str, CollectionProfile] = {}
        self._cube_profiles: Dict[str, CubeProfile] = {}
        self._expressway_profiles: Dict[str, ExpresswayProfile] = {}
        self._load_profiles()

    def _load_profiles(self):
        """Load profiles from YAML file"""
        if not self.profiles_path.exists():
            logger.warning(f"Profiles file not found: {self.profiles_path}")
            return

        try:
            with open(self.profiles_path, 'r') as f:
                data = yaml.safe_load(f)

            if not data:
                logger.warning("Empty profiles file")
                return

            # Load CUCM profiles
            if 'profiles' in data:
                profiles_data = data['profiles']
                for profile_dict in profiles_data:
                    try:
                        profile = CollectionProfile(**profile_dict)
                        self._profiles[profile.name] = profile
                        logger.info(f"Loaded CUCM profile: {profile.name}")
                    except Exception as e:
                        logger.error(f"Error loading CUCM profile: {e}")
                        continue
                logger.info(f"Loaded {len(self._profiles)} CUCM profile(s)")

            # Load CUBE profiles
            if 'cube_profiles' in data:
                cube_data = data['cube_profiles']
                for profile_dict in cube_data:
                    try:
                        profile = CubeProfile(**profile_dict)
                        self._cube_profiles[profile.name] = profile
                        logger.info(f"Loaded CUBE profile: {profile.name}")
                    except Exception as e:
                        logger.error(f"Error loading CUBE profile: {e}")
                        continue
                logger.info(f"Loaded {len(self._cube_profiles)} CUBE profile(s)")

            # Load Expressway profiles
            if 'expressway_profiles' in data:
                exp_data = data['expressway_profiles']
                for profile_dict in exp_data:
                    try:
                        profile = ExpresswayProfile(**profile_dict)
                        self._expressway_profiles[profile.name] = profile
                        logger.info(f"Loaded Expressway profile: {profile.name}")
                    except Exception as e:
                        logger.error(f"Error loading Expressway profile: {e}")
                        continue
                logger.info(f"Loaded {len(self._expressway_profiles)} Expressway profile(s)")

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading profiles: {e}")
            raise

    def get_profile(self, name: str) -> Optional[CollectionProfile]:
        """
        Get a CUCM profile by name.

        Args:
            name: Profile name

        Returns:
            CollectionProfile if found, None otherwise
        """
        return self._profiles.get(name)

    def get_cube_profile(self, name: str) -> Optional[CubeProfile]:
        """
        Get a CUBE profile by name.

        Args:
            name: Profile name

        Returns:
            CubeProfile if found, None otherwise
        """
        return self._cube_profiles.get(name)

    def get_expressway_profile(self, name: str) -> Optional[ExpresswayProfile]:
        """
        Get an Expressway profile by name.

        Args:
            name: Profile name

        Returns:
            ExpresswayProfile if found, None otherwise
        """
        return self._expressway_profiles.get(name)

    def list_profiles(self) -> List[CollectionProfile]:
        """
        Get all available CUCM profiles.

        Returns:
            List of all CUCM profiles
        """
        return list(self._profiles.values())

    def list_cube_profiles(self) -> List[CubeProfile]:
        """
        Get all available CUBE profiles.

        Returns:
            List of all CUBE profiles
        """
        return list(self._cube_profiles.values())

    def list_expressway_profiles(self) -> List[ExpresswayProfile]:
        """
        Get all available Expressway profiles.

        Returns:
            List of all Expressway profiles
        """
        return list(self._expressway_profiles.values())

    def profile_exists(self, name: str) -> bool:
        """
        Check if a CUCM profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists, False otherwise
        """
        return name in self._profiles

    def cube_profile_exists(self, name: str) -> bool:
        """
        Check if a CUBE profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists, False otherwise
        """
        return name in self._cube_profiles

    def expressway_profile_exists(self, name: str) -> bool:
        """
        Check if an Expressway profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists, False otherwise
        """
        return name in self._expressway_profiles

    def reload(self):
        """Reload profiles from disk"""
        self._profiles.clear()
        self._cube_profiles.clear()
        self._expressway_profiles.clear()
        self._load_profiles()


# Global profile catalog instance
_catalog: Optional[ProfileCatalog] = None


def get_profile_catalog(profiles_path: Optional[Path] = None) -> ProfileCatalog:
    """
    Get or create the global profile catalog instance.

    Args:
        profiles_path: Optional path to profiles file (uses default if not provided)

    Returns:
        ProfileCatalog instance
    """
    global _catalog
    if _catalog is None:
        if profiles_path is None:
            from app.config import get_settings
            profiles_path = get_settings().profiles_path
        _catalog = ProfileCatalog(profiles_path)
    return _catalog


def reload_profiles():
    """Force reload profiles from disk"""
    global _catalog
    if _catalog:
        _catalog.reload()
