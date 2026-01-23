"""Unit tests for CUCM packet capture service"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from app.capture_service import (
    build_cucm_capture_command,
    parse_capture_output,
    Capture,
    CaptureManager,
)
from app.models import (
    StartCaptureRequest,
    CaptureFilter,
    CaptureStatus,
    CaptureDeviceType,
)


# ============================================================================
# Test Data
# ============================================================================

CAPTURE_OUTPUT_WITH_STATS = """Capturing on eth0
capturing to file capture_20260102.cap
1234 packets captured
1250 packets received by filter
5 packets dropped by kernel
"""

CAPTURE_OUTPUT_MINIMAL = """Capturing on eth0
capturing to file capture_20260102.cap
"""

CAPTURE_OUTPUT_SINGLE_PACKET = """Capturing on eth0
1 packet captured
1 packet received by filter
0 packet dropped by kernel
"""


# ============================================================================
# Test build_cucm_capture_command
# ============================================================================

class TestBuildCaptureCommand:
    """Tests for build_cucm_capture_command function"""

    def test_basic_command(self):
        """Test basic capture command without filters"""
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="test_capture",
            count=1000,
            capture_filter=None,
        )

        assert cmd == "utils network capture eth0 file test_capture count 1000 size all"

    def test_command_with_port_filter(self):
        """Test capture command with port filter"""
        filter = CaptureFilter(port=5060)
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="sip_capture",
            count=5000,
            capture_filter=filter,
        )

        assert "port 5060" in cmd
        assert cmd.startswith("utils network capture eth0 file sip_capture count 5000 size all")

    def test_command_with_host_filter(self):
        """Test capture command with host filter"""
        filter = CaptureFilter(host="10.0.0.1")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="host_capture",
            count=1000,
            capture_filter=filter,
        )

        # Default protocol should be "ip"
        assert "host ip 10.0.0.1" in cmd

    def test_command_with_host_and_protocol(self):
        """Test capture command with host and protocol filter"""
        filter = CaptureFilter(host="10.0.0.1", protocol="arp")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="arp_capture",
            count=1000,
            capture_filter=filter,
        )

        assert "host arp 10.0.0.1" in cmd

    def test_command_with_src_filter(self):
        """Test capture command with source address filter"""
        filter = CaptureFilter(src="192.168.1.100")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="src_capture",
            count=1000,
            capture_filter=filter,
        )

        assert "src 192.168.1.100" in cmd

    def test_command_with_dest_filter(self):
        """Test capture command with destination address filter"""
        filter = CaptureFilter(dest="192.168.1.200")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="dest_capture",
            count=1000,
            capture_filter=filter,
        )

        assert "dest 192.168.1.200" in cmd

    def test_command_with_src_and_dest(self):
        """Test capture command with both src and dest filters"""
        filter = CaptureFilter(src="192.168.1.100", dest="192.168.1.200")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="src_dest_capture",
            count=1000,
            capture_filter=filter,
        )

        assert "src 192.168.1.100" in cmd
        assert "dest 192.168.1.200" in cmd

    def test_command_with_port_and_host(self):
        """Test capture command with port and host filters"""
        filter = CaptureFilter(port=5060, host="10.0.0.1")
        cmd = build_cucm_capture_command(
            interface="eth0",
            filename="sip_host_capture",
            count=1000,
            capture_filter=filter,
        )

        assert "port 5060" in cmd
        assert "host ip 10.0.0.1" in cmd

    def test_host_with_src_dest_validation(self):
        """Test that host filter cannot be combined with src/dest"""
        # The CaptureFilter model should reject this combination
        with pytest.raises(ValueError):
            CaptureFilter(host="10.0.0.1", src="192.168.1.100", dest="192.168.1.200")

    def test_different_interface(self):
        """Test capture on different interface"""
        cmd = build_cucm_capture_command(
            interface="eth1",
            filename="test",
            count=1000,
        )

        assert "eth1" in cmd


# ============================================================================
# Test parse_capture_output
# ============================================================================

class TestParseCaptureOutput:
    """Tests for parse_capture_output function"""

    def test_parse_with_stats(self):
        """Test parsing output with packet statistics"""
        stats = parse_capture_output(CAPTURE_OUTPUT_WITH_STATS)

        assert stats["packets_captured"] == 1234
        assert stats["packets_received"] == 1250
        assert stats["packets_dropped"] == 5

    def test_parse_minimal_output(self):
        """Test parsing output without statistics"""
        stats = parse_capture_output(CAPTURE_OUTPUT_MINIMAL)

        assert stats["packets_captured"] is None
        assert stats["packets_received"] is None
        assert stats["packets_dropped"] is None

    def test_parse_single_packet(self):
        """Test parsing output with single packet (singular form)"""
        stats = parse_capture_output(CAPTURE_OUTPUT_SINGLE_PACKET)

        assert stats["packets_captured"] == 1
        assert stats["packets_received"] == 1
        assert stats["packets_dropped"] == 0

    def test_parse_empty_output(self):
        """Test parsing empty output"""
        stats = parse_capture_output("")

        assert stats["packets_captured"] is None
        assert stats["packets_received"] is None
        assert stats["packets_dropped"] is None


# ============================================================================
# Test Capture Class
# ============================================================================

class TestCaptureClass:
    """Tests for Capture class"""

    def test_capture_initialization(self):
        """Test Capture object initialization"""
        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
            interface="eth0",
        )

        capture = Capture(
            capture_id="test-id-123",
            request=request,
            filename="test_capture",
        )

        assert capture.capture_id == "test-id-123"
        assert capture.filename == "test_capture"
        assert capture.status == CaptureStatus.PENDING
        assert capture.device_type == CaptureDeviceType.CUCM
        assert capture.started_at is None
        assert capture.completed_at is None
        assert capture.error is None

    def test_capture_to_info(self):
        """Test converting Capture to CaptureInfo"""
        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
            interface="eth0",
        )

        capture = Capture(
            capture_id="test-id-123",
            request=request,
            filename="test_capture",
        )
        capture.status = CaptureStatus.RUNNING
        capture.started_at = datetime.now(timezone.utc)
        capture.packets_captured = 500
        capture.file_size_bytes = 102400

        info = capture.to_info()

        assert info.capture_id == "test-id-123"
        assert info.status == CaptureStatus.RUNNING
        assert info.host == "10.0.0.1"
        assert info.interface == "eth0"
        assert info.filename == "test_capture"
        assert info.packets_captured == 500
        assert info.file_size_bytes == 102400

    def test_capture_cancel(self):
        """Test cancelling a capture"""
        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        capture = Capture(
            capture_id="test-id-123",
            request=request,
            filename="test_capture",
        )

        assert capture._cancelled is False
        capture.cancel()
        assert capture._cancelled is True


# ============================================================================
# Test CaptureManager Class
# ============================================================================

class TestCaptureManager:
    """Tests for CaptureManager class"""

    def setup_method(self):
        """Reset singleton before each test"""
        CaptureManager._instance = None

    def test_singleton(self):
        """Test CaptureManager is a singleton"""
        manager1 = CaptureManager.get_instance()
        manager2 = CaptureManager.get_instance()

        assert manager1 is manager2

    def test_create_capture(self):
        """Test creating a new capture"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
            interface="eth0",
        )

        capture = manager.create_capture(request)

        assert capture.capture_id is not None
        assert len(capture.capture_id) == 36  # UUID format
        assert capture.request == request
        assert capture.status == CaptureStatus.PENDING

    def test_create_capture_with_custom_filename(self):
        """Test creating capture with custom filename"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
            filename="my_custom_capture",
        )

        capture = manager.create_capture(request)

        assert capture.filename == "my_custom_capture"

    def test_create_capture_auto_filename(self):
        """Test creating capture with auto-generated filename"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        capture = manager.create_capture(request)

        assert capture.filename.startswith("capture_")
        assert len(capture.filename) > 8  # capture_ + timestamp

    def test_get_capture(self):
        """Test getting a capture by ID"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        capture = manager.create_capture(request)
        retrieved = manager.get_capture(capture.capture_id)

        assert retrieved is capture

    def test_get_capture_not_found(self):
        """Test getting a non-existent capture"""
        manager = CaptureManager()

        retrieved = manager.get_capture("non-existent-id")

        assert retrieved is None

    def test_list_captures(self):
        """Test listing captures"""
        manager = CaptureManager()

        # Create multiple captures
        for i in range(5):
            request = StartCaptureRequest(
                host=f"10.0.0.{i}",
                username="admin",
                password="password123",
                duration_sec=60,
            )
            manager.create_capture(request)

        captures = manager.list_captures()

        assert len(captures) == 5

    def test_list_captures_with_limit(self):
        """Test listing captures with limit"""
        manager = CaptureManager()

        # Create multiple captures
        for i in range(10):
            request = StartCaptureRequest(
                host=f"10.0.0.{i}",
                username="admin",
                password="password123",
                duration_sec=60,
            )
            manager.create_capture(request)

        captures = manager.list_captures(limit=3)

        assert len(captures) == 3

    def test_delete_capture(self):
        """Test deleting a capture"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        capture = manager.create_capture(request)
        capture_id = capture.capture_id

        result = manager.delete_capture(capture_id)

        assert result is True
        assert manager.get_capture(capture_id) is None

    def test_delete_capture_not_found(self):
        """Test deleting a non-existent capture"""
        manager = CaptureManager()

        result = manager.delete_capture("non-existent-id")

        assert result is False

    def test_stop_capture_not_found(self):
        """Test stopping a non-existent capture"""
        manager = CaptureManager()

        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            manager.stop_capture("non-existent-id")
        )

        assert result is False

    def test_stop_capture_not_running(self):
        """Test stopping a capture that's not running"""
        manager = CaptureManager()

        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        capture = manager.create_capture(request)
        capture.status = CaptureStatus.COMPLETED

        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            manager.stop_capture(capture.capture_id)
        )

        assert result is False


# ============================================================================
# Test CaptureFilter Model
# ============================================================================

class TestCaptureFilter:
    """Tests for CaptureFilter model"""

    def test_empty_filter(self):
        """Test empty filter"""
        filter = CaptureFilter()

        assert filter.host is None
        assert filter.src is None
        assert filter.dest is None
        assert filter.port is None
        assert filter.protocol is None

    def test_filter_with_host_and_port(self):
        """Test filter with host, port, and protocol"""
        filter = CaptureFilter(
            host="10.0.0.1",
            port=5060,
            protocol="ip",
        )

        assert filter.host == "10.0.0.1"
        assert filter.port == 5060
        assert filter.protocol == "ip"

    def test_filter_with_src_dest(self):
        """Test filter with src and dest"""
        filter = CaptureFilter(
            src="192.168.1.1",
            dest="192.168.1.2",
            port=5060,
        )

        assert filter.src == "192.168.1.1"
        assert filter.dest == "192.168.1.2"
        assert filter.port == 5060


# ============================================================================
# Test StartCaptureRequest Model
# ============================================================================

class TestStartCaptureRequest:
    """Tests for StartCaptureRequest model"""

    def test_minimal_request(self):
        """Test minimal request with required fields only"""
        request = StartCaptureRequest(
            host="10.0.0.1",
            username="admin",
            password="password123",
            duration_sec=60,
        )

        assert request.host == "10.0.0.1"
        assert request.port == 22  # Default
        assert request.interface == "eth0"  # Default
        assert request.packet_count == 100000  # Default
        assert request.connect_timeout_sec == 30  # Default

    def test_request_with_all_fields(self):
        """Test request with all fields"""
        filter = CaptureFilter(port=5060)
        request = StartCaptureRequest(
            host="10.0.0.1",
            port=2222,
            username="admin",
            password="password123",
            duration_sec=120,
            interface="eth1",
            filename="my_capture",
            filter=filter,
            packet_count=50000,
            connect_timeout_sec=60,
        )

        assert request.host == "10.0.0.1"
        assert request.port == 2222
        assert request.duration_sec == 120
        assert request.interface == "eth1"
        assert request.filename == "my_capture"
        assert request.filter.port == 5060
        assert request.packet_count == 50000
        assert request.connect_timeout_sec == 60

    def test_duration_validation_min(self):
        """Test duration minimum validation"""
        with pytest.raises(ValueError):
            StartCaptureRequest(
                host="10.0.0.1",
                username="admin",
                password="password123",
                duration_sec=5,  # Below minimum of 10
            )

    def test_duration_validation_max(self):
        """Test duration maximum validation"""
        with pytest.raises(ValueError):
            StartCaptureRequest(
                host="10.0.0.1",
                username="admin",
                password="password123",
                duration_sec=700,  # Above maximum of 600
            )

    def test_packet_count_validation(self):
        """Test packet count validation"""
        with pytest.raises(ValueError):
            StartCaptureRequest(
                host="10.0.0.1",
                username="admin",
                password="password123",
                duration_sec=60,
                packet_count=50,  # Below minimum of 100
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
