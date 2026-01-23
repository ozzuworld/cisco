"""Unit tests for profile management"""

import pytest
from pathlib import Path
import tempfile
import yaml

from app.profiles import ProfileCatalog, CollectionProfile


# Sample profiles for testing
SAMPLE_PROFILES_DATA = {
    "profiles": [
        {
            "name": "test_basic",
            "description": "Basic test profile",
            "paths": ["platform/log/syslog", "install"],
            "reltime_minutes": 60,
            "compress": True,
            "recurs": False,
            "match": None
        },
        {
            "name": "test_advanced",
            "description": "Advanced test profile",
            "paths": ["cm/trace/ccm", "cm/trace/sdl"],
            "reltime_minutes": 120,
            "compress": True,
            "recurs": True,
            "match": ".*\\.txt$"
        }
    ]
}


@pytest.fixture
def temp_profiles_file():
    """Create a temporary profiles YAML file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(SAMPLE_PROFILES_DATA, f)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


def test_collection_profile_creation():
    """Test creating a CollectionProfile"""
    profile = CollectionProfile(
        name="test",
        description="Test profile",
        paths=["path1", "path2"],
        reltime_minutes=60,
        compress=True,
        recurs=False
    )

    assert profile.name == "test"
    assert profile.description == "Test profile"
    assert len(profile.paths) == 2
    assert profile.reltime_minutes == 60
    assert profile.compress is True
    assert profile.recurs is False
    assert profile.match is None


def test_collection_profile_defaults():
    """Test CollectionProfile default values"""
    profile = CollectionProfile(
        name="test",
        description="Test",
        paths=["path1"]
    )

    assert profile.reltime_minutes == 60  # Default
    assert profile.compress is True  # Default
    assert profile.recurs is False  # Default
    assert profile.match is None  # Default


def test_profile_catalog_load(temp_profiles_file):
    """Test loading profiles from YAML file"""
    catalog = ProfileCatalog(temp_profiles_file)

    # Should have loaded 2 profiles
    profiles = catalog.list_profiles()
    assert len(profiles) == 2

    # Check profile names
    profile_names = {p.name for p in profiles}
    assert profile_names == {"test_basic", "test_advanced"}


def test_profile_catalog_get_profile(temp_profiles_file):
    """Test retrieving a specific profile"""
    catalog = ProfileCatalog(temp_profiles_file)

    # Get existing profile
    profile = catalog.get_profile("test_basic")
    assert profile is not None
    assert profile.name == "test_basic"
    assert profile.description == "Basic test profile"
    assert len(profile.paths) == 2
    assert profile.reltime_minutes == 60

    # Get non-existent profile
    missing = catalog.get_profile("nonexistent")
    assert missing is None


def test_profile_catalog_profile_exists(temp_profiles_file):
    """Test checking if profile exists"""
    catalog = ProfileCatalog(temp_profiles_file)

    assert catalog.profile_exists("test_basic") is True
    assert catalog.profile_exists("test_advanced") is True
    assert catalog.profile_exists("nonexistent") is False


def test_profile_catalog_profile_details(temp_profiles_file):
    """Test that profile details are correctly loaded"""
    catalog = ProfileCatalog(temp_profiles_file)

    # Check advanced profile
    advanced = catalog.get_profile("test_advanced")
    assert advanced is not None
    assert advanced.reltime_minutes == 120
    assert advanced.compress is True
    assert advanced.recurs is True
    assert advanced.match == ".*\\.txt$"
    assert "cm/trace/ccm" in advanced.paths
    assert "cm/trace/sdl" in advanced.paths


def test_profile_catalog_missing_file():
    """Test catalog behavior with missing file"""
    nonexistent_path = Path("/tmp/nonexistent_profiles.yaml")

    # Should not raise exception, just warn
    catalog = ProfileCatalog(nonexistent_path)

    # Should return empty list
    assert len(catalog.list_profiles()) == 0


def test_profile_catalog_invalid_yaml():
    """Test catalog behavior with invalid YAML"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("invalid: yaml: content: [")
        temp_path = Path(f.name)

    try:
        # Should raise YAMLError
        with pytest.raises(yaml.YAMLError):
            ProfileCatalog(temp_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_profile_catalog_empty_profiles():
    """Test catalog with empty profiles section"""
    empty_data = {"profiles": []}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(empty_data, f)
        temp_path = Path(f.name)

    try:
        catalog = ProfileCatalog(temp_path)
        assert len(catalog.list_profiles()) == 0
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_profile_validation():
    """Test profile validation"""
    # Missing required fields should raise error
    with pytest.raises(ValueError):
        CollectionProfile(name="test")  # Missing description and paths

    # Invalid reltime_minutes
    with pytest.raises(ValueError):
        CollectionProfile(
            name="test",
            description="Test",
            paths=["path1"],
            reltime_minutes=0  # Must be >= 1
        )

    with pytest.raises(ValueError):
        CollectionProfile(
            name="test",
            description="Test",
            paths=["path1"],
            reltime_minutes=20000  # Must be <= 10080 (1 week)
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
