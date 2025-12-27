#!/usr/bin/env python3
"""BE-024: Test time range log collection functionality"""

import sys
from datetime import datetime, timedelta, timezone
from app.models import CollectionOptions
from app.prompt_responder import compute_reltime_from_range, build_file_get_command


def test_collection_options_validation():
    """Test CollectionOptions model validation"""
    print("Testing CollectionOptions validation...")

    # Test 1: Valid range mode
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=3)
        end = now - timedelta(minutes=5)

        options = CollectionOptions(
            time_mode="range",
            start_time=start,
            end_time=end
        )
        print("✓ Valid range mode accepted")
    except Exception as e:
        print(f"✗ Valid range mode failed: {e}")
        return False

    # Test 2: Invalid - start >= end
    try:
        now = datetime.now(timezone.utc)
        start = now
        end = now - timedelta(hours=1)

        options = CollectionOptions(
            time_mode="range",
            start_time=start,
            end_time=end
        )
        print("✗ Should have rejected start >= end")
        return False
    except ValueError as e:
        if "start_time must be before end_time" in str(e):
            print("✓ Correctly rejected start >= end")
        else:
            print(f"✗ Wrong error message: {e}")
            return False

    # Test 3: Invalid - future end_time
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)

        options = CollectionOptions(
            time_mode="range",
            start_time=start,
            end_time=end
        )
        print("✗ Should have rejected future end_time")
        return False
    except ValueError as e:
        if "cannot be in the future" in str(e):
            print("✓ Correctly rejected future end_time")
        else:
            print(f"✗ Wrong error message: {e}")
            return False

    # Test 4: Invalid - missing start_time
    try:
        now = datetime.now(timezone.utc)
        options = CollectionOptions(
            time_mode="range",
            end_time=now
        )
        print("✗ Should have rejected missing start_time")
        return False
    except ValueError as e:
        if "requires both start_time and end_time" in str(e):
            print("✓ Correctly rejected missing start_time")
        else:
            print(f"✗ Wrong error message: {e}")
            return False

    # Test 5: Valid relative mode (backward compatibility)
    try:
        options = CollectionOptions(
            time_mode="relative",
            reltime_minutes=120
        )
        print("✓ Valid relative mode accepted (backward compatibility)")
    except Exception as e:
        print(f"✗ Relative mode failed: {e}")
        return False

    return True


def test_compute_reltime():
    """Test reltime computation from time ranges"""
    print("\nTesting reltime computation...")

    tests = [
        # (hours_ago, expected_unit, expected_value, description)
        (3, "hours", 3, "3 hours"),
        (24, "days", 1, "1 day"),
        (48, "days", 2, "2 days"),
        (168, "weeks", 1, "1 week (7 days)"),
        (0.5, "minutes", 30, "30 minutes"),
        (1.5, "minutes", 90, "90 minutes (non-whole hours)"),
    ]

    for hours_ago, expected_unit, expected_value, description in tests:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_ago)
        end = now

        unit, value = compute_reltime_from_range(start, end)

        if unit == expected_unit and value == expected_value:
            print(f"✓ {description}: {unit} {value}")
        else:
            print(f"✗ {description}: expected {expected_unit} {expected_value}, got {unit} {value}")
            return False

    return True


def test_build_command():
    """Test command building with dynamic units"""
    print("\nTesting command building...")

    # Test 1: Minutes (backward compatibility)
    cmd = build_file_get_command("syslog/messages*", 60, "minutes", compress=True)
    expected = "file get activelog syslog/messages* reltime minutes 60 compress"
    if cmd == expected:
        print(f"✓ Minutes command: {cmd}")
    else:
        print(f"✗ Expected: {expected}")
        print(f"  Got:      {cmd}")
        return False

    # Test 2: Hours
    cmd = build_file_get_command("cm/trace/sdl*", 3, "hours", compress=True)
    expected = "file get activelog cm/trace/sdl* reltime hours 3 compress"
    if cmd == expected:
        print(f"✓ Hours command: {cmd}")
    else:
        print(f"✗ Expected: {expected}")
        print(f"  Got:      {cmd}")
        return False

    # Test 3: Days
    cmd = build_file_get_command("platform/log/*", 7, "days", compress=True, recurs=True)
    expected = "file get activelog platform/log/* reltime days 7 recurs compress"
    if cmd == expected:
        print(f"✓ Days command: {cmd}")
    else:
        print(f"✗ Expected: {expected}")
        print(f"  Got:      {cmd}")
        return False

    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("BE-024: Time Range Log Collection - Implementation Tests")
    print("=" * 60)

    all_passed = True

    if not test_collection_options_validation():
        all_passed = False

    if not test_compute_reltime():
        all_passed = False

    if not test_build_command():
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
    else:
        print("✗ Some tests failed")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
