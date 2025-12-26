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


class ProfileCatalog:
    """
    Manages the catalog of available collection profiles.

    Loads profiles from a YAML file and provides lookup functionality.
    """

    def __init__(self, profiles_path: Path):
        """
        Initialize profile catalog.

        Args:
            profiles_path: Path to profiles YAML file
        """
        self.profiles_path = profiles_path
        self._profiles: Dict[str, CollectionProfile] = {}
        self._load_profiles()

    def _load_profiles(self):
        """Load profiles from YAML file"""
        if not self.profiles_path.exists():
            logger.warning(f"Profiles file not found: {self.profiles_path}")
            return

        try:
            with open(self.profiles_path, 'r') as f:
                data = yaml.safe_load(f)

            if not data or 'profiles' not in data:
                logger.warning("No profiles found in profiles file")
                return

            profiles_data = data['profiles']
            for profile_dict in profiles_data:
                try:
                    profile = CollectionProfile(**profile_dict)
                    self._profiles[profile.name] = profile
                    logger.info(f"Loaded profile: {profile.name}")
                except Exception as e:
                    logger.error(f"Error loading profile: {e}")
                    continue

            logger.info(f"Loaded {len(self._profiles)} profile(s)")

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading profiles: {e}")
            raise

    def get_profile(self, name: str) -> Optional[CollectionProfile]:
        """
        Get a profile by name.

        Args:
            name: Profile name

        Returns:
            CollectionProfile if found, None otherwise
        """
        return self._profiles.get(name)

    def list_profiles(self) -> List[CollectionProfile]:
        """
        Get all available profiles.

        Returns:
            List of all profiles
        """
        return list(self._profiles.values())

    def profile_exists(self, name: str) -> bool:
        """
        Check if a profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists, False otherwise
        """
        return name in self._profiles

    def reload(self):
        """Reload profiles from disk"""
        self._profiles.clear()
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
