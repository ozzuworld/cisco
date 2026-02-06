"""FastAPI application for CUCM Log Collector"""

import asyncio
import logging
import os
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

from app.models import (
    DiscoverNodesRequest,
    DiscoverNodesResponse,
    ErrorResponse,
    ClusterNode,
    CreateJobRequest,
    CreateJobResponse,
    JobStatusResponse,
    ArtifactsResponse,
    ProfilesResponse,
    ProfileResponse,
    JobsListResponse,
    JobSummary,
    JobStatus as JobStatusEnum,
    CancelJobResponse,
    RetryJobResponse,
    EstimateResponse,
    NodeEstimate,
    CommandEstimate,
    ClusterHealthRequest,  # Health Status
    ClusterHealthResponse,  # Health Status
    StartCaptureRequest,  # Packet Capture
    StartCaptureResponse,  # Packet Capture
    CaptureStatusResponse,  # Packet Capture
    CaptureListResponse,  # Packet Capture
    StopCaptureResponse,  # Packet Capture
    CaptureStatus as CaptureStatusEnum,  # Packet Capture
    StartCaptureSessionRequest,  # Capture Sessions
    StartCaptureSessionResponse,  # Capture Sessions
    CaptureSessionStatusResponse,  # Capture Sessions
    CaptureSessionListResponse,  # Capture Sessions
    StopCaptureSessionResponse,  # Capture Sessions
    CaptureSessionStatus as CaptureSessionStatusEnum,  # Capture Sessions
    StartLogCollectionRequest,  # Log Collection
    StartLogCollectionResponse,  # Log Collection
    LogCollectionStatusResponse,  # Log Collection
    LogCollectionListResponse,  # Log Collection
    LogCollectionStatus as LogCollectionStatusEnum,  # Log Collection
    LogProfilesResponse,  # Log Collection Profiles
    CubeProfileResponse,  # Log Collection Profiles
    ExpresswayProfileResponse,  # Log Collection Profiles
    CreateSSHSessionRequest,  # SSH Sessions
    CreateSSHSessionResponse,  # SSH Sessions
    SSHNodeInfo,  # SSH Sessions
    SSHSessionInfoResponse,  # SSH Sessions
    SSHSessionListResponse,  # SSH Sessions
    DeleteSSHSessionResponse,  # SSH Sessions
    SSHSessionStatus as SSHSessionStatusEnum,  # SSH Sessions
    CubeDebugStatusRequest,  # CUBE Debug
    CubeDebugStatusResponse,  # CUBE Debug
    CubeDebugCategory,  # CUBE Debug
    CubeDebugEnableRequest,  # CUBE Debug
    CubeDebugEnableResponse,  # CUBE Debug
    CubeDebugClearResponse,  # CUBE Debug
    DeviceHealthRequest,  # Device Health
    DeviceHealthResponse,  # Device Health
    EnvironmentCreate,  # Environments
    EnvironmentUpdate,  # Environments
    EnvironmentResponse,  # Environments
    EnvironmentListResponse,  # Environments
    DeviceEntryCreate,  # Environments
    ScenarioListResponse,  # Scenarios
    CreateInvestigationRequest,  # Investigations
    CreateInvestigationResponse,  # Investigations
    InvestigationStatusResponse,  # Investigations
    InvestigationListResponse,  # Investigations
    InvestigationStatus as InvestigationStatusEnum,  # Investigations
)
from app.ssh_client import (
    run_show_network_cluster,
    CUCMAuthError,
    CUCMConnectionError,
    CUCMCommandTimeoutError,
    CUCMSSHClientError,
    CUCMSSHClient
)
from app.csr_client import (
    CSRSSHClient,
    CSRAuthError,
    CSRConnectionError,
    CSRCommandTimeoutError,
    CSRSSHClientError,
)
from app.parsers import parse_show_network_cluster
from app.profiles import get_profile_catalog
from app.job_manager import get_job_manager
from app.middleware import RequestIDMiddleware, APIKeyAuthMiddleware, get_request_id
from app.artifact_manager import (
    get_artifact_path,
    get_transcript_path,
    create_zip_archive,
    generate_manifest,
    generate_zip_filename
)
from app.config import get_settings
from app.prompt_responder import compute_reltime_from_range, build_file_get_command
from app.health_service import check_cluster_health  # Health Status
from app.device_health_service import check_device_health  # Device Health
from app.capture_service import get_capture_manager  # Packet Capture
from app.capture_session_service import get_session_manager  # Capture Sessions
from app.log_service import get_log_collection_manager  # Log Collection
from app.sftp_server import start_sftp_server, stop_sftp_server, get_sftp_server  # Embedded SFTP
from app.ssh_session_manager import get_ssh_session_manager  # SSH Sessions
from app.environment_service import get_environment_manager  # Environments


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Reduce AsyncSSH library noise
logging.getLogger('asyncssh').setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Starts the embedded SFTP server on startup (if enabled) and
    stops it on shutdown.
    """
    # Startup
    settings = get_settings()

    if settings.sftp_server_enabled:
        logger.info("Starting embedded SFTP server...")
        try:
            await start_sftp_server(
                host=settings.sftp_server_host,
                port=settings.sftp_server_port,
                root_path=settings.artifacts_dir,
                username=settings.sftp_username,
                password=settings.sftp_password,
                host_key_path=settings.ssh_host_key_path
            )
            logger.info(
                f"Embedded SFTP server running on port {settings.sftp_server_port}"
            )
        except Exception as e:
            logger.error(f"Failed to start SFTP server: {e}")
            # Continue without SFTP server - don't crash the app
    else:
        logger.info("Embedded SFTP server disabled (SFTP_SERVER_ENABLED=false)")

    # Start SSH session manager cleanup loop
    ssh_session_mgr = get_ssh_session_manager()
    ssh_session_mgr.start_cleanup_loop()

    yield  # Application runs here

    # Shutdown
    ssh_session_mgr.stop_cleanup_loop()

    if settings.sftp_server_enabled:
        logger.info("Stopping embedded SFTP server...")
        await stop_sftp_server()


# Create FastAPI app
app = FastAPI(
    title="CUCM Log Collector API",
    description="Backend service for discovering and collecting logs from CUCM clusters",
    version="0.5.0",
    lifespan=lifespan  # Enable SFTP server lifecycle
)

# Wire up middleware
# CORS middleware must be first
# Use environment variable directly to avoid loading full settings at import time
cors_allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    # Default: allow all origins for ease of deployment
    # For production with specific domain requirements, set CORS_ALLOWED_ORIGINS env var
    r".*"
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=cors_allowed_origins,  # Configurable CORS origins
    allow_methods=["*"],  # Allow all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allow all headers (including Authorization, Content-Type)
    expose_headers=["X-Request-ID", "Content-Disposition"],  # Expose headers for downloads
    allow_credentials=True  # Allow cookies/auth headers
)
app.add_middleware(RequestIDMiddleware)  # Adds request_id
app.add_middleware(APIKeyAuthMiddleware)  # Auth (if API_KEY env set)


# ============================================================================
# Exception Handlers
# ============================================================================


@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Handle Starlette HTTP exceptions (e.g., 404 Not Found).

    Ensures consistent error format with request_id.
    """
    request_id = get_request_id(request)

    # Map status code to error code
    error_code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": error_code,
            "message": exc.detail or "An error occurred",
            "request_id": request_id
        },
        headers={"X-Request-ID": request_id}
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Handle FastAPI HTTP exceptions.

    Ensures consistent error format with request_id.
    """
    request_id = get_request_id(request)

    # If detail is already a dict with our format, use it
    if isinstance(exc.detail, dict):
        detail = exc.detail
        # Ensure request_id is set
        if "request_id" not in detail:
            detail["request_id"] = request_id
        return JSONResponse(
            status_code=exc.status_code,
            content=detail,
            headers={"X-Request-ID": request_id}
        )

    # Otherwise, wrap string detail in our format
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP_ERROR",
            "message": str(exc.detail),
            "request_id": request_id
        },
        headers={"X-Request-ID": request_id}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle Pydantic validation errors (422 Unprocessable Entity).

    Ensures consistent error format with request_id.
    """
    request_id = get_request_id(request)

    # Extract first error for simplicity
    first_error = exc.errors()[0] if exc.errors() else {}
    field = " -> ".join(str(loc) for loc in first_error.get("loc", []))
    message = first_error.get("msg", "Validation error")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": f"Validation failed for {field}: {message}" if field else message,
            "request_id": request_id,
            "details": exc.errors()  # Include full validation errors
        },
        headers={"X-Request-ID": request_id}
    )


# Maximum size for raw output in responses (40KB)
MAX_RAW_OUTPUT_SIZE = 40 * 1024


# ============================================================================
# Frontend Static Files - Mount Assets Only
# ============================================================================
# Note: Catch-all SPA routes are defined at the END of this file after all API routes

# Check if frontend build exists and mount static assets
FRONTEND_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIR.exists() and FRONTEND_DIR.is_dir():
    logger.info(f"Mounting frontend static files from {FRONTEND_DIR}")

    # Mount static assets (JS, CSS, images) with caching
    app.mount(
        "/assets",
        StaticFiles(directory=str(FRONTEND_DIR / "assets")),
        name="static"
    )
else:
    logger.warning(f"Frontend build not found at {FRONTEND_DIR}, serving API only")


# ============================================================================
# API Endpoints Start Here
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint - serve frontend or return service info"""
    # Serve frontend if available
    if FRONTEND_DIR.exists() and FRONTEND_DIR.is_dir():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)

    # Fallback to API info if no frontend
    return {
        "service": "CUCM Log Collector",
        "version": "0.5.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    settings = get_settings()
    sftp_server = get_sftp_server()

    response = {"status": "healthy"}

    # Include SFTP server status if enabled
    if settings.sftp_server_enabled:
        response["sftp_server"] = {
            "enabled": True,
            "running": sftp_server.is_running if sftp_server else False,
            "port": settings.sftp_server_port
        }

    return response


@app.post(
    "/discover-nodes",
    response_model=DiscoverNodesResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Nodes discovered successfully",
            "model": DiscoverNodesResponse
        },
        401: {
            "description": "Authentication failed",
            "model": ErrorResponse
        },
        502: {
            "description": "Network error (host unreachable, connection refused, etc)",
            "model": ErrorResponse
        },
        504: {
            "description": "Connection or command timeout",
            "model": ErrorResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def discover_nodes(req_body: DiscoverNodesRequest, request: Request):
    """
    Discover nodes in a CUCM cluster.

    Connects to the CUCM Publisher via SSH, executes 'show network cluster',
    and parses the output to extract cluster node information.

    Args:
        req_body: DiscoverNodesRequest with connection parameters
        request: FastAPI request object

    Returns:
        DiscoverNodesResponse with list of nodes

    Raises:
        HTTPException: With appropriate status code and error details
    """
    request_id = get_request_id(request)
    logger.info(
        f"Node discovery request for {req_body.publisher_host}:{req_body.port} "
        f"as user {req_body.username} (request_id={request_id})"
    )
    # NEVER log the password

    # Safe debug logging (only when DEBUG_HTTP=true)
    settings = get_settings()
    if settings.debug_http:
        password_len = len(req_body.password) if req_body.password else 0
        logger.debug(
            f"[DEBUG_HTTP] discover-nodes request details: "
            f"request_id={request_id}, "
            f"publisher_host={req_body.publisher_host}, "
            f"username={req_body.username}, "
            f"password_len={password_len}, "
            f"port={req_body.port}, "
            f"connect_timeout={req_body.connect_timeout_sec}s, "
            f"command_timeout={req_body.command_timeout_sec}s"
        )

    raw_output: Optional[str] = None
    nodes: list[ClusterNode] = []

    try:
        # Run the SSH command
        raw_output = await run_show_network_cluster(
            host=req_body.publisher_host,
            port=req_body.port,
            username=req_body.username,
            password=req_body.password,
            connect_timeout=float(req_body.connect_timeout_sec),
            command_timeout=float(req_body.command_timeout_sec)
        )

        logger.debug(f"Raw output length: {len(raw_output)} bytes")

        # Parse the output
        nodes = parse_show_network_cluster(raw_output)

        logger.info(f"Discovered {len(nodes)} nodes")

        # IMPORTANT: Replace Publisher node's IP with user-provided publisher_host
        # This ensures we use the IP the user knows works (e.g., private IP) rather than
        # CUCM's internally configured IP (which might be a public IP unreachable from Docker)
        for node in nodes:
            if node.role == "Publisher":
                original_ip = node.ip
                if original_ip != req_body.publisher_host:
                    logger.info(
                        f"Replacing Publisher IP {original_ip} with user-provided IP {req_body.publisher_host} "
                        f"(ensures connectivity from Docker/private network)"
                    )
                    node.ip = req_body.publisher_host
                break

        # Prepare response
        response = DiscoverNodesResponse(nodes=nodes)

        # If no nodes found, include raw output for debugging
        if len(nodes) == 0:
            truncated_output, is_truncated = _truncate_output(raw_output)
            response.raw_output = truncated_output
            response.raw_output_truncated = is_truncated
            logger.warning("No nodes parsed from output. Including raw output in response.")

        return response

    except CUCMAuthError as e:
        logger.error(f"Authentication failed: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": "Authentication failed. Please check username and password.",
                "request_id": request_id
            }
        )

    except CUCMCommandTimeoutError as e:
        logger.error(f"Command timeout: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "COMMAND_TIMEOUT",
                "message": f"Command execution timed out after {req_body.command_timeout_sec}s",
                "request_id": request_id
            }
        )

    except CUCMConnectionError as e:
        error_msg = str(e).lower()

        # Check if it's a timeout
        if "timeout" in error_msg:
            logger.error(f"Connection timeout: {str(e)} (request_id={request_id})")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "CONNECT_TIMEOUT",
                    "message": f"Connection timeout to {req_body.publisher_host}:{req_body.port}",
                    "request_id": request_id
                }
            )
        else:
            # Other network errors (unreachable, refused, etc)
            logger.error(f"Connection error: {str(e)} (request_id={request_id})")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "NETWORK_ERROR",
                    "message": f"Cannot connect to {req_body.publisher_host}:{req_body.port}. "
                               f"Please check host is reachable and SSH is available.",
                    "request_id": request_id
                }
            )

    except CUCMSSHClientError as e:
        logger.error(f"SSH client error: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SSH_ERROR",
                "message": "SSH client error occurred",
                "request_id": request_id
            }
        )

    except Exception as e:
        logger.exception(f"Unexpected error during node discovery: {str(e)} (request_id={request_id})")
        # In production, don't expose internal error details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred during node discovery",
                "request_id": request_id
            }
        )


# ============================================================================
# Cluster Health Status Endpoint
# ============================================================================


@app.post(
    "/cluster/health",
    response_model=ClusterHealthResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Cluster health status retrieved successfully",
            "model": ClusterHealthResponse
        },
        401: {
            "description": "Authentication failed",
            "model": ErrorResponse
        },
        502: {
            "description": "Network error (host unreachable, connection refused, etc)",
            "model": ErrorResponse
        },
        504: {
            "description": "Connection or command timeout",
            "model": ErrorResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def get_cluster_health(req_body: ClusterHealthRequest, request: Request):
    """
    Get health status of a CUCM cluster.

    Connects to CUCM nodes via SSH and runs health check commands to assess:
    - Database replication status (utils dbreplication runtimestate)
    - Service status (utils service list)
    - NTP synchronization (utils ntp status)
    - System diagnostics (utils diagnose test)
    - Core files / crash dumps (utils core active list)

    If nodes list is not provided, discovers nodes from the publisher first.

    Args:
        req_body: ClusterHealthRequest with connection parameters and check options
        request: FastAPI request object

    Returns:
        ClusterHealthResponse with health status for all nodes

    Raises:
        HTTPException: With appropriate status code and error details
    """
    request_id = get_request_id(request)
    checks_str = ", ".join([c.value for c in req_body.checks])
    logger.info(
        f"Cluster health check request for {req_body.publisher_host}:{req_body.port} "
        f"checks=[{checks_str}] (request_id={request_id})"
    )

    try:
        response = await check_cluster_health(req_body)
        logger.info(
            f"Cluster health check complete: {response.cluster_status.value} "
            f"({response.healthy_nodes} healthy, {response.degraded_nodes} degraded, "
            f"{response.critical_nodes} critical, {response.unreachable_nodes} unreachable) "
            f"(request_id={request_id})"
        )
        return response

    except CUCMAuthError as e:
        logger.error(f"Authentication failed: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": "Authentication failed. Please check username and password.",
                "request_id": request_id
            }
        )

    except CUCMCommandTimeoutError as e:
        logger.error(f"Command timeout: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "COMMAND_TIMEOUT",
                "message": f"Command execution timed out: {str(e)}",
                "request_id": request_id
            }
        )

    except CUCMConnectionError as e:
        error_msg = str(e).lower()
        if "timeout" in error_msg:
            logger.error(f"Connection timeout: {str(e)} (request_id={request_id})")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "CONNECT_TIMEOUT",
                    "message": f"Connection timeout to {req_body.publisher_host}:{req_body.port}",
                    "request_id": request_id
                }
            )
        else:
            logger.error(f"Connection error: {str(e)} (request_id={request_id})")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "NETWORK_ERROR",
                    "message": f"Cannot connect to {req_body.publisher_host}:{req_body.port}. "
                               f"Please check host is reachable and SSH is available.",
                    "request_id": request_id
                }
            )

    except CUCMSSHClientError as e:
        logger.error(f"SSH client error: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SSH_ERROR",
                "message": "SSH client error occurred",
                "request_id": request_id
            }
        )

    except Exception as e:
        logger.exception(f"Unexpected error during cluster health check: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred during cluster health check",
                "request_id": request_id
            }
        )


# ============================================================================
# Multi-Device Health Check Endpoint
# ============================================================================


@app.post(
    "/health/device",
    response_model=DeviceHealthResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Device health status retrieved successfully",
            "model": DeviceHealthResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def get_device_health(req_body: DeviceHealthRequest, request: Request):
    """
    Check health of multiple devices (CUCM, CUBE/IOS-XE, Expressway).

    Supports concurrent health checks across different device types:
    - CUCM: SSH-based checks (services, NTP, replication, diagnostics, core files)
    - CUBE: SSH-based checks (system, interfaces, voice calls, SIP, NTP, environment, redundancy)
    - Expressway: REST API checks (cluster, licensing, alarms, NTP)

    Each device is checked independently and errors are isolated per-device.
    """
    request_id = get_request_id(request)
    device_types = [d.device_type.value for d in req_body.devices]
    logger.info(
        f"Device health check request for {len(req_body.devices)} device(s): "
        f"{device_types} (request_id={request_id})"
    )

    try:
        response = await check_device_health(req_body)
        logger.info(
            f"Device health check complete: {response.overall_status.value} "
            f"({response.healthy_devices} healthy, {response.degraded_devices} degraded, "
            f"{response.critical_devices} critical, {response.unknown_devices} unknown) "
            f"(request_id={request_id})"
        )
        return response

    except Exception as e:
        logger.exception(f"Unexpected error during device health check: {str(e)} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred during device health check",
                "request_id": request_id
            }
        )


# ============================================================================
# SSH Session Management Endpoints
# ============================================================================


@app.post(
    "/ssh-sessions",
    response_model=CreateSSHSessionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {
            "description": "SSH session created",
            "model": CreateSSHSessionResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def create_ssh_session(req_body: CreateSSHSessionRequest, request: Request):
    """
    Create a persistent SSH session to CUCM nodes.

    Connects to all specified nodes in parallel. The session stays alive
    for subsequent trace level operations, avoiding repeated CLI startup overhead.
    """
    request_id = get_request_id(request)
    logger.info(
        f"Creating SSH session for {len(req_body.hosts)} nodes "
        f"(request_id={request_id})"
    )

    try:
        mgr = get_ssh_session_manager()
        session = await mgr.create_session(
            hosts=req_body.hosts,
            username=req_body.username,
            password=req_body.password,
            port=req_body.port,
            connect_timeout=float(req_body.connect_timeout_sec),
        )

        connected = [h for h, n in session.nodes.items() if n.connected]
        failed = [
            SSHNodeInfo(host=h, connected=False, error=n.error)
            for h, n in session.nodes.items()
            if not n.connected
        ]

        if connected:
            session_status = SSHSessionStatusEnum.CONNECTED
        else:
            session_status = SSHSessionStatusEnum.ERROR

        logger.info(
            f"SSH session {session.session_id[:8]} ready: "
            f"{len(connected)} connected, {len(failed)} failed "
            f"(request_id={request_id})"
        )

        return CreateSSHSessionResponse(
            session_id=session.session_id,
            status=session_status,
            connected_nodes=connected,
            failed_nodes=failed,
        )

    except Exception as e:
        logger.exception(f"Error creating SSH session: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SESSION_CREATE_FAILED",
                "message": f"Failed to create SSH session: {str(e)}",
                "request_id": request_id
            }
        )


@app.get(
    "/ssh-sessions/{session_id}",
    response_model=SSHSessionInfoResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "SSH session info",
            "model": SSHSessionInfoResponse
        },
        404: {
            "description": "Session not found",
            "model": ErrorResponse
        }
    }
)
async def get_ssh_session(session_id: str, request: Request):
    """Get the status of an SSH session."""
    request_id = get_request_id(request)
    mgr = get_ssh_session_manager()
    session = mgr.get_session(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"SSH session {session_id} not found",
                "request_id": request_id
            }
        )

    nodes = [
        SSHNodeInfo(host=h, connected=n.connected, error=n.error)
        for h, n in session.nodes.items()
    ]
    any_connected = any(n.connected for n in session.nodes.values())

    return SSHSessionInfoResponse(
        session_id=session.session_id,
        status=SSHSessionStatusEnum.CONNECTED if any_connected else SSHSessionStatusEnum.DISCONNECTED,
        nodes=nodes,
        created_at=session.created_at,
        last_used_at=session.last_used_at,
        ttl_remaining=session.ttl_remaining(),
    )


@app.get(
    "/ssh-sessions",
    response_model=SSHSessionListResponse,
    status_code=status.HTTP_200_OK,
)
async def list_ssh_sessions(request: Request):
    """List all active SSH sessions."""
    mgr = get_ssh_session_manager()
    sessions = mgr.list_sessions()

    items = []
    for s in sessions:
        nodes = [
            SSHNodeInfo(host=h, connected=n.connected, error=n.error)
            for h, n in s.nodes.items()
        ]
        any_connected = any(n.connected for n in s.nodes.values())
        items.append(SSHSessionInfoResponse(
            session_id=s.session_id,
            status=SSHSessionStatusEnum.CONNECTED if any_connected else SSHSessionStatusEnum.DISCONNECTED,
            nodes=nodes,
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            ttl_remaining=s.ttl_remaining(),
        ))

    return SSHSessionListResponse(sessions=items)


@app.delete(
    "/ssh-sessions/{session_id}",
    response_model=DeleteSSHSessionResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "SSH session deleted",
            "model": DeleteSSHSessionResponse
        },
        404: {
            "description": "Session not found",
            "model": ErrorResponse
        }
    }
)
async def delete_ssh_session(session_id: str, request: Request):
    """Disconnect all nodes and destroy an SSH session."""
    request_id = get_request_id(request)
    mgr = get_ssh_session_manager()
    success = await mgr.destroy_session(session_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"SSH session {session_id} not found",
                "request_id": request_id
            }
        )

    return DeleteSSHSessionResponse(
        session_id=session_id,
        message="SSH session destroyed"
    )


# ============================================================================
# Trace Level Management Endpoints
# ============================================================================


# Import trace level models
from app.models import (
    GetTraceLevelRequest,
    GetTraceLevelResponse,
    SetTraceLevelRequest,
    SetTraceLevelResponse,
    ServiceTraceLevel,
    NodeTraceLevelResult,
    DebugLevel,
)
from app.job_manager import CUCM_TRACE_LEVELS, CUCM_TRACE_SERVICES


@app.post(
    "/trace-level/get",
    response_model=GetTraceLevelResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Current trace levels retrieved",
            "model": GetTraceLevelResponse
        },
        401: {
            "description": "Authentication failed",
            "model": ErrorResponse
        },
        502: {
            "description": "Network error",
            "model": ErrorResponse
        },
        504: {
            "description": "Connection timeout",
            "model": ErrorResponse
        }
    }
)
async def get_trace_level(req_body: GetTraceLevelRequest, request: Request):
    """
    Get current trace levels from CUCM node(s).

    Connects to each node and queries the current trace level for each service.
    Use this to check the current state before/after setting trace levels.

    If session_id is provided, reuses existing persistent connections and
    processes nodes in parallel.  Otherwise falls back to sequential new
    connections for backwards compatibility.

    Args:
        req_body: GetTraceLevelRequest with connection parameters
        request: FastAPI request object

    Returns:
        GetTraceLevelResponse with current trace levels for each node/service
    """
    from app.models import NodeTraceLevelStatus

    request_id = get_request_id(request)
    logger.info(
        f"Get trace level request for {len(req_body.hosts)} nodes "
        f"(session_id={req_body.session_id or 'none'}, request_id={request_id})"
    )

    # Use provided services or defaults
    services = req_body.services or CUCM_TRACE_SERVICES

    # Valid CUCM trace levels (from least to most verbose)
    VALID_TRACE_LEVELS = [
        "Error", "Special", "State_Transition", "Significant",
        "Entry_exit", "Arbitrary", "Detailed",
    ]

    # ── Helper: query one node using an already-connected client ──
    async def _query_node(host: str, client: CUCMSSHClient) -> NodeTraceLevelStatus:
        service_levels = []
        all_raw_output = []

        try:
            # Step 1: Get the list of trace tasks
            output = await client.execute_command("show trace level", timeout=30.0)
            logger.info(f"[{host}] show trace level output ({len(output)} chars)")
            all_raw_output.append(f"admin: show trace level\n{output.strip()}")

            valid_tasks = []
            for line in output.split('\n'):
                stripped = line.strip()
                if 'valid tasks' in stripped.lower() or 'tasks are' in stripped.lower():
                    colon_idx = stripped.find(':')
                    if colon_idx >= 0:
                        task_str = stripped[colon_idx + 1:].strip()
                        valid_tasks = [t.strip() for t in task_str.split() if t.strip()]

            if not valid_tasks:
                logger.warning(f"[{host}] Could not parse task names from output")
                combined_raw = "\n".join(all_raw_output)
                return NodeTraceLevelStatus(
                    host=host, success=False, services=[],
                    raw_output=combined_raw, error="Could not parse trace task list",
                )

            logger.info(f"[{host}] Found {len(valid_tasks)} trace tasks: {valid_tasks}")

            # Step 2: Query each task individually.
            # Try two command forms in order:
            #   1. "show trace <task>"  (Cisco docs: "show trace" lists current level)
            #   2. "show trace level <task>"  (older CUCM versions)
            # If both fail on the first task, report tasks with Unknown level.
            query_cmd_template = None
            QUERY_FORMS = ["show trace {task}", "show trace level {task}"]

            for form_idx, form in enumerate(QUERY_FORMS):
                test_cmd = form.format(task=valid_tasks[0])
                try:
                    test_output = await client.execute_command(test_cmd, timeout=15.0)
                    if "unsuccessfully" not in test_output.lower():
                        query_cmd_template = form
                        logger.info(f"[{host}] Per-task query works with: {form}")
                        # Parse this first result so we don't waste it
                        break
                    else:
                        logger.info(f"[{host}] Command '{test_cmd}' not supported")
                except Exception:
                    logger.info(f"[{host}] Command '{test_cmd}' failed")

            if query_cmd_template:
                # We found a working command form — query all tasks
                # (first task was already queried above as test_output)
                for i, task in enumerate(valid_tasks):
                    try:
                        if i == 0:
                            task_output = test_output  # reuse probe result
                        else:
                            cmd = query_cmd_template.format(task=task)
                            task_output = await client.execute_command(
                                cmd, timeout=15.0
                            )

                        if "unsuccessfully" in task_output.lower():
                            service_levels.append(ServiceTraceLevel(
                                service_name=task, current_level="Unknown",
                                raw_output=task_output.strip()[:500],
                            ))
                            continue

                        all_raw_output.append(
                            f"\nadmin: {query_cmd_template.format(task=task)}\n"
                            f"{task_output.strip()}"
                        )

                        # Parse trace level — match only valid CUCM level
                        # names, skip lines that are error messages.
                        current_level = "Unknown"
                        for tline in task_output.split('\n'):
                            tline_stripped = tline.strip()
                            if not tline_stripped:
                                continue
                            if "unsuccessfully" in tline_stripped.lower():
                                continue
                            if "error executing" in tline_stripped.lower():
                                continue
                            for level_name in VALID_TRACE_LEVELS:
                                if level_name.lower() in tline_stripped.lower():
                                    current_level = level_name
                                    break
                            if current_level != "Unknown":
                                break

                        service_levels.append(ServiceTraceLevel(
                            service_name=task,
                            current_level=current_level,
                            raw_output=task_output.strip()[:500],
                        ))
                    except Exception as te:
                        logger.warning(f"[{host}] Failed to query task {task}: {te}")
            else:
                # Neither command form works — report tasks with Unknown level
                logger.info(
                    f"[{host}] Per-task trace query not supported on this CUCM, "
                    f"reporting {len(valid_tasks)} tasks as Unknown"
                )
                for task in valid_tasks:
                    service_levels.append(ServiceTraceLevel(
                        service_name=task,
                        current_level="Unknown",
                        raw_output="",
                    ))

        except Exception as e:
            logger.warning(f"[{host}] Failed to get trace levels: {e}")
            all_raw_output.append(f"Error: {e}")
            combined_raw = "\n".join(all_raw_output)
            return NodeTraceLevelStatus(
                host=host, success=False, services=service_levels,
                raw_output=combined_raw, error=str(e),
            )

        combined_raw = "\n".join(all_raw_output)
        return NodeTraceLevelStatus(
            host=host,
            success=len(service_levels) > 0,
            services=service_levels,
            raw_output=combined_raw,
            error=None if service_levels else "No trace tasks found",
        )

    results = []
    successful = 0
    failed = 0

    # ── Path A: session-based parallel execution ──
    if req_body.session_id:
        mgr = get_ssh_session_manager()
        session = mgr.get_session(req_body.session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "SESSION_NOT_FOUND",
                    "message": f"SSH session {req_body.session_id} not found",
                    "request_id": request_id,
                }
            )

        async def _session_query(host: str) -> NodeTraceLevelStatus:
            node = session.nodes.get(host)
            if not node or not node.connected or not node.client:
                return NodeTraceLevelStatus(
                    host=host, success=False, services=[],
                    error=f"Node {host} not connected in session"
                )
            try:
                return await _query_node(host, node.client)
            except Exception as e:
                logger.exception(f"Error getting trace levels from {host}: {e}")
                return NodeTraceLevelStatus(
                    host=host, success=False, services=[], error=str(e)
                )

        node_results = await asyncio.gather(
            *[_session_query(h) for h in req_body.hosts]
        )
        for nr in node_results:
            results.append(nr)
            if nr.success:
                successful += 1
            else:
                failed += 1

    # ── Path B: legacy sequential connections ──
    else:
        for host in req_body.hosts:
            try:
                async with CUCMSSHClient(
                    host=host,
                    port=req_body.port,
                    username=req_body.username,
                    password=req_body.password,
                    connect_timeout=float(req_body.connect_timeout_sec)
                ) as client:
                    nr = await _query_node(host, client)
                    results.append(nr)
                    successful += 1

            except CUCMAuthError as e:
                logger.error(f"Authentication failed for {host}: {e}")
                results.append(NodeTraceLevelStatus(
                    host=host, success=False, services=[],
                    error="Authentication failed"
                ))
                failed += 1

            except CUCMConnectionError as e:
                logger.error(f"Connection error for {host}: {e}")
                results.append(NodeTraceLevelStatus(
                    host=host, success=False, services=[],
                    error=f"Connection error: {str(e)}"
                ))
                failed += 1

            except Exception as e:
                logger.exception(f"Error getting trace levels from {host}: {e}")
                results.append(NodeTraceLevelStatus(
                    host=host, success=False, services=[],
                    error=str(e)
                ))
                failed += 1

    response = GetTraceLevelResponse(
        results=results,
        total_nodes=len(req_body.hosts),
        successful_nodes=successful,
        failed_nodes=failed,
        checked_at=datetime.now(timezone.utc),
        message=f"Checked trace levels on {successful}/{len(req_body.hosts)} nodes"
    )
    logger.info(
        f"GET trace-level response: successful={successful}, failed={failed}, "
        f"nodes=[{', '.join(f'{r.host}:success={r.success},services={len(r.services)}' for r in results)}] "
        f"(request_id={request_id})"
    )
    return response


@app.post(
    "/trace-level/set",
    response_model=SetTraceLevelResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Trace levels set successfully",
            "model": SetTraceLevelResponse
        },
        401: {
            "description": "Authentication failed",
            "model": ErrorResponse
        },
        502: {
            "description": "Network error",
            "model": ErrorResponse
        }
    }
)
async def set_trace_level(req_body: SetTraceLevelRequest, request: Request):
    """
    Set trace level on one or more CUCM nodes.

    This allows you to set trace levels BEFORE an issue occurs, so when
    you collect logs later, they will contain the detailed information.

    Use 'detailed' or 'verbose' when troubleshooting, then set back to
    'basic' when done to avoid performance impact.

    If session_id is provided, reuses existing persistent connections and
    processes nodes in parallel.  Otherwise falls back to sequential new
    connections for backwards compatibility.

    Args:
        req_body: SetTraceLevelRequest with hosts and level
        request: FastAPI request object

    Returns:
        SetTraceLevelResponse with results for each node
    """
    request_id = get_request_id(request)
    logger.info(
        f"Set trace level request: level={req_body.level.value} "
        f"hosts={req_body.hosts} (session_id={req_body.session_id or 'none'}, "
        f"request_id={request_id})"
    )

    # Resolve the CUCM trace level name
    cucm_level = CUCM_TRACE_LEVELS.get(req_body.level.value, "Error")

    # ── Helper: set trace on one node using an already-connected client ──
    async def _set_node(host: str, client: CUCMSSHClient) -> NodeTraceLevelResult:
        services_updated = []
        node_errors = []
        raw_parts = []

        # Step 1: Discover valid task names from the node itself
        # CUCM set trace uses task names (dbl, servm, etc.) not service
        # names ("Cisco CallManager").  Query the node for its task list.
        try:
            task_output = await client.execute_command(
                "show trace level", timeout=30.0
            )
        except Exception as e:
            return NodeTraceLevelResult(
                host=host, success=False, services_updated=[],
                raw_output=f"Error discovering trace tasks: {e}",
                error=f"Could not discover trace tasks: {e}",
            )

        task_names = []
        for line in task_output.split('\n'):
            stripped = line.strip()
            if 'valid tasks' in stripped.lower() or 'tasks are' in stripped.lower():
                colon_idx = stripped.find(':')
                if colon_idx >= 0:
                    task_str = stripped[colon_idx + 1:].strip()
                    task_names = [t.strip() for t in task_str.split() if t.strip()]

        if not task_names:
            return NodeTraceLevelResult(
                host=host, success=False, services_updated=[],
                raw_output=task_output.strip(),
                error="Could not parse trace task list from CUCM",
            )

        # If specific services were requested, filter to matching tasks
        # (for now, set ALL discovered tasks to the requested level)
        logger.info(f"[{host}] Setting {len(task_names)} trace tasks to {cucm_level}")

        # Step 2: Set each task to the requested level
        for task in task_names:
            cmd = f'set trace enable {cucm_level} {task}'
            try:
                logger.info(f"[{host}] Executing: {cmd}")
                output = await client.execute_command_with_confirmation(
                    cmd, confirmation="y", timeout=60.0
                )
                # Validate CUCM didn't reject the command
                if "unsuccessfully" in output.lower() or "no valid command" in output.lower():
                    error_msg = f"CUCM rejected: {output.strip()[:200]}"
                    logger.warning(f"[{host}] {error_msg}")
                    node_errors.append(f"{task}: {error_msg}")
                    raw_parts.append(f"admin: {cmd}\n{output.strip()}")
                    continue
                services_updated.append(task)
                raw_parts.append(f"admin: {cmd}\n{output.strip()}")
                logger.info(f"[{host}] Successfully set trace level for {task}")
            except Exception as e:
                logger.warning(f"[{host}] Failed to set trace for {service}: {e}")
                node_errors.append(f"{service}: {str(e)}")
                raw_parts.append(f"admin: {cmd}\nError: {e}")

        node_raw = "\n\n".join(raw_parts)

        if services_updated:
            return NodeTraceLevelResult(
                host=host, success=True,
                services_updated=services_updated,
                raw_output=node_raw,
                error="; ".join(node_errors) if node_errors else None,
            )
        else:
            return NodeTraceLevelResult(
                host=host, success=False,
                services_updated=[],
                raw_output=node_raw,
                error="; ".join(node_errors) if node_errors else "No services updated",
            )

    results = []
    successful = 0
    failed = 0

    # ── Path A: session-based parallel execution ──
    if req_body.session_id:
        mgr = get_ssh_session_manager()
        session = mgr.get_session(req_body.session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "SESSION_NOT_FOUND",
                    "message": f"SSH session {req_body.session_id} not found",
                    "request_id": request_id,
                }
            )

        async def _session_set(host: str) -> NodeTraceLevelResult:
            node = session.nodes.get(host)
            if not node or not node.connected or not node.client:
                return NodeTraceLevelResult(
                    host=host, success=False, services_updated=[],
                    error=f"Node {host} not connected in session"
                )
            try:
                return await _set_node(host, node.client)
            except Exception as e:
                logger.exception(f"[{host}] Error setting trace level: {e}")
                return NodeTraceLevelResult(
                    host=host, success=False, services_updated=[], error=str(e)
                )

        node_results = await asyncio.gather(
            *[_session_set(h) for h in req_body.hosts]
        )
        for nr in node_results:
            results.append(nr)
            if nr.success:
                successful += 1
            else:
                failed += 1

    # ── Path B: legacy sequential connections ──
    else:
        for host in req_body.hosts:
            try:
                async with CUCMSSHClient(
                    host=host,
                    port=req_body.port,
                    username=req_body.username,
                    password=req_body.password,
                    connect_timeout=float(req_body.connect_timeout_sec)
                ) as client:
                    nr = await _set_node(host, client)
                    results.append(nr)
                    if nr.success:
                        successful += 1
                    else:
                        failed += 1

            except CUCMAuthError as e:
                logger.error(f"[{host}] Authentication failed: {e}")
                results.append(NodeTraceLevelResult(
                    host=host, success=False, services_updated=[],
                    error=f"Authentication failed: {str(e)}"
                ))
                failed += 1

            except CUCMConnectionError as e:
                logger.error(f"[{host}] Connection failed: {e}")
                results.append(NodeTraceLevelResult(
                    host=host, success=False, services_updated=[],
                    error=f"Connection failed: {str(e)}"
                ))
                failed += 1

            except Exception as e:
                logger.exception(f"[{host}] Error setting trace level: {e}")
                results.append(NodeTraceLevelResult(
                    host=host, success=False, services_updated=[],
                    error=str(e)
                ))
                failed += 1

    # Summary message
    if failed == 0:
        message = f"Successfully set trace level to {req_body.level.value} on all {successful} node(s)"
    elif successful == 0:
        message = f"Failed to set trace level on all {failed} node(s)"
    else:
        message = f"Trace level set on {successful} node(s), {failed} failed"

    logger.info(f"Set trace level complete: {message} (request_id={request_id})")

    response = SetTraceLevelResponse(
        level=req_body.level,
        results=results,
        total_nodes=len(req_body.hosts),
        successful_nodes=successful,
        failed_nodes=failed,
        completed_at=datetime.now(timezone.utc),
        message=message
    )
    logger.info(
        f"SET trace-level response: successful={successful}, failed={failed}, "
        f"nodes=[{', '.join(f'{r.host}:success={r.success},updated={r.services_updated}' for r in results)}] "
        f"(request_id={request_id})"
    )
    return response


# ============================================================================
# Job Management Endpoints
# ============================================================================


@app.get(
    "/profiles",
    response_model=ProfilesResponse,
    status_code=status.HTTP_200_OK
)
async def list_profiles():
    """
    List all available log collection profiles.

    Returns:
        ProfilesResponse with list of profiles
    """
    catalog = get_profile_catalog()
    profiles_list = catalog.list_profiles()

    profile_responses = [
        ProfileResponse(
            name=p.name,
            description=p.description,
            paths=p.paths,
            reltime_minutes=p.reltime_minutes,
            compress=p.compress,
            recurs=p.recurs,
            match=p.match,
            trace_services=p.trace_services
        )
        for p in profiles_list
    ]

    return ProfilesResponse(profiles=profile_responses)


@app.post(
    "/jobs/estimate",
    response_model=EstimateResponse,
    status_code=status.HTTP_200_OK
)
async def estimate_job(req_body: CreateJobRequest, request: Request):
    """
    Estimate what a log collection job would do (dry-run).

    Returns a preview of commands, paths, and computed reltime without
    creating or executing a job. Helps users avoid wasted runs.

    Args:
        req_body: Job creation request (same as POST /jobs)
        request: FastAPI request object

    Returns:
        EstimateResponse with command preview and reltime computation

    Raises:
        HTTPException: If profile not found or validation error
    """
    request_id = get_request_id(request)
    logger.info(f"Estimating job for profile '{req_body.profile}' with {len(req_body.nodes)} nodes (request_id={request_id})")

    try:
        # Get profile
        catalog = get_profile_catalog()
        profile = catalog.get_profile(req_body.profile)
        if not profile:
            raise ValueError(f"Profile not found: {req_body.profile}")

        # Compute reltime (same logic as job execution)
        time_mode = req_body.options.time_mode if req_body.options and req_body.options.time_mode else "relative"
        computation_now = datetime.now(timezone.utc)

        if time_mode == "range" and req_body.options:
            # Absolute time range mode
            start_time = req_body.options.start_time
            end_time = req_body.options.end_time

            # Compute reltime from range
            reltime_unit, reltime_value = compute_reltime_from_range(start_time, end_time)

            requested_start_time = start_time
            requested_end_time = end_time
            requested_reltime_minutes = None
        else:
            # Relative time mode
            requested_reltime_minutes = (
                req_body.options.reltime_minutes if req_body.options and req_body.options.reltime_minutes
                else profile.reltime_minutes
            )
            reltime_unit = "minutes"
            reltime_value = requested_reltime_minutes
            requested_start_time = None
            requested_end_time = None

        # Determine other options
        compress = (
            req_body.options.compress if req_body.options and req_body.options.compress is not None
            else profile.compress
        )
        recurs = (
            req_body.options.recurs if req_body.options and req_body.options.recurs is not None
            else profile.recurs
        )
        match = req_body.options.match if req_body.options else profile.match

        # Build estimates for each node
        node_estimates = []
        total_commands = 0

        for node in req_body.nodes:
            commands = []

            # Build command estimate for each path
            for path in profile.paths:
                command = build_file_get_command(
                    path=path,
                    reltime_value=reltime_value,
                    reltime_unit=reltime_unit,
                    compress=compress,
                    recurs=recurs,
                    match=match
                )

                commands.append(CommandEstimate(
                    path=path,
                    command=command,
                    reltime_unit=reltime_unit,
                    reltime_value=reltime_value
                ))

            total_commands += len(commands)

            node_estimates.append(NodeEstimate(
                node=node,
                commands=commands,
                total_commands=len(commands)
            ))

        logger.info(
            f"Estimated {total_commands} commands across {len(req_body.nodes)} nodes "
            f"(reltime={reltime_unit} {reltime_value}, request_id={request_id})"
        )

        return EstimateResponse(
            profile=req_body.profile,
            nodes=node_estimates,
            total_nodes=len(req_body.nodes),
            total_commands=total_commands,
            time_mode=time_mode,
            requested_start_time=requested_start_time,
            requested_end_time=requested_end_time,
            requested_reltime_minutes=requested_reltime_minutes,
            computed_reltime_unit=reltime_unit,
            computed_reltime_value=reltime_value,
            computation_timestamp=computation_now
        )

    except ValueError as e:
        # Profile not found or validation error
        logger.error(f"Validation error estimating job: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_REQUEST",
                "message": str(e),
                "request_id": request_id
            }
        )
    except Exception as e:
        logger.exception(f"Error estimating job: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to estimate job",
                "request_id": request_id
            }
        )


@app.post(
    "/jobs",
    response_model=CreateJobResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def create_job(req_body: CreateJobRequest, background_tasks: BackgroundTasks, request: Request):
    """
    Create a new log collection job.

    The job will be executed asynchronously in the background.

    Args:
        req_body: Job creation request
        background_tasks: FastAPI background tasks
        request: FastAPI request object

    Returns:
        CreateJobResponse with job ID and initial status

    Raises:
        HTTPException: If profile not found or other validation error
    """
    request_id = get_request_id(request)
    logger.info(f"Creating job for profile '{req_body.profile}' with {len(req_body.nodes)} nodes (request_id={request_id})")

    try:
        job_manager = get_job_manager()

        # Create the job
        job = job_manager.create_job(req_body)

        # Schedule execution in background
        background_tasks.add_task(job_manager.execute_job, job.job_id)

        logger.info(f"Job {job.job_id} created and queued for execution (request_id={request_id})")

        return CreateJobResponse(
            job_id=job.job_id,
            status=job.status,
            created_at=job.created_at
        )

    except ValueError as e:
        # Profile not found or validation error
        logger.error(f"Validation error creating job: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_REQUEST",
                "message": str(e),
                "request_id": request_id
            }
        )
    except Exception as e:
        logger.exception(f"Error creating job: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to create job",
                "request_id": request_id
            }
        )


@app.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK
)
async def get_job_status(job_id: str, request: Request):
    """
    Get the status of a log collection job.

    Args:
        job_id: Job identifier
        request: FastAPI request object

    Returns:
        JobStatusResponse with job status and node details

    Raises:
        HTTPException: If job not found
    """
    request_id = get_request_id(request)
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        logger.warning(f"Job {job_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    # Get progress metrics
    progress = job.get_progress_metrics()

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        profile=job.profile.name,
        nodes=list(job.node_statuses.values()),
        # Include progress metrics
        total_nodes=progress["total_nodes"],
        completed_nodes=progress["completed_nodes"],
        succeeded_nodes=progress["succeeded_nodes"],
        failed_nodes=progress["failed_nodes"],
        running_nodes=progress["running_nodes"],
        percent_complete=progress["percent_complete"],
        last_updated_at=progress["last_updated_at"],
        # Include time window configuration
        requested_start_time=job.requested_start_time,
        requested_end_time=job.requested_end_time,
        requested_reltime_minutes=job.requested_reltime_minutes,
        computed_reltime_unit=job.computed_reltime_unit,
        computed_reltime_value=job.computed_reltime_value,
        computation_timestamp=job.computation_timestamp,
        # Include debug level
        debug_level=job.debug_level,
        # Download available if job finished and has artifacts
        download_available=(
            job.status in (JobStatusEnum.SUCCEEDED, JobStatusEnum.PARTIAL) and
            any(
                artifact for ns in job.node_statuses.values()
                for artifact in ns.artifacts
            )
        )
    )


@app.get(
    "/jobs/{job_id}/artifacts",
    response_model=ArtifactsResponse,
    status_code=status.HTTP_200_OK
)
async def get_job_artifacts(job_id: str, request: Request):
    """
    Get all artifacts collected by a job.

    Args:
        job_id: Job identifier
        request: FastAPI request object

    Returns:
        ArtifactsResponse with list of artifacts

    Raises:
        HTTPException: If job not found
    """
    request_id = get_request_id(request)
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        logger.warning(f"Job {job_id} not found for artifacts (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    # Collect all artifacts from all nodes
    all_artifacts = []
    for node_status in job.node_statuses.values():
        all_artifacts.extend(node_status.artifacts)

    return ArtifactsResponse(
        job_id=job.job_id,
        artifacts=all_artifacts
    )


@app.get(
    "/jobs",
    response_model=JobsListResponse,
    status_code=status.HTTP_200_OK
)
async def list_jobs(limit: int = 20):
    """
    List recent jobs.

    Args:
        limit: Maximum number of jobs to return (default 20)

    Returns:
        JobsListResponse with list of job summaries
    """
    job_manager = get_job_manager()
    jobs = job_manager.list_jobs(limit=limit)

    summaries = [
        JobSummary(
            job_id=job.job_id,
            status=job.status,
            profile=job.profile.name,
            created_at=job.created_at,
            node_count=len(job.nodes_list)
        )
        for job in jobs
    ]

    return JobsListResponse(jobs=summaries)


# ============================================================================
# Download and Cancellation Endpoints
# ============================================================================


@app.get(
    "/artifacts/{artifact_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Artifact file download"},
        404: {
            "description": "Artifact not found",
            "model": ErrorResponse
        }
    }
)
async def download_artifact(artifact_id: str, request: Request):
    """
    Download an artifact by its stable ID.

    Args:
        artifact_id: Stable artifact identifier
        request: FastAPI request object

    Returns:
        FileResponse with artifact file

    Raises:
        HTTPException: If artifact not found
    """
    request_id = get_request_id(request)
    logger.info(f"Artifact download request: {artifact_id} (request_id={request_id})")

    file_path = get_artifact_path(artifact_id)
    if not file_path:
        logger.warning(f"Artifact {artifact_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "ARTIFACT_NOT_FOUND",
                "message": f"Artifact {artifact_id} not found",
                "request_id": request_id
            }
        )

    return FileResponse(
        file_path,
        filename=file_path.name,
        media_type="application/octet-stream"
    )


@app.get(
    "/jobs/{job_id}/artifacts/{artifact_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Download single artifact from a job"},
        404: {
            "description": "Job or artifact not found",
            "model": ErrorResponse
        }
    }
)
async def download_job_artifact(job_id: str, artifact_id: str, request: Request):
    """
    Download a single artifact from a specific job.

    This is the hierarchical route that follows REST conventions:
    /jobs/{job_id}/artifacts/{artifact_id}/download

    Args:
        job_id: Job identifier
        artifact_id: Artifact identifier
        request: FastAPI request object

    Returns:
        FileResponse with artifact file

    Raises:
        HTTPException: If job or artifact not found
    """
    request_id = get_request_id(request)
    logger.info(f"Job artifact download: job={job_id}, artifact={artifact_id} (request_id={request_id})")

    # Get job to verify it exists and count artifacts for error messages
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        logger.warning(f"Job {job_id} not found for artifact download (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "artifact_id": artifact_id,
                "request_id": request_id
            }
        )

    # Count total artifacts for helpful error message
    total_artifacts = sum(len(ns.artifacts) for ns in job.node_statuses.values())

    # Look up artifact by ID
    file_path = get_artifact_path(artifact_id)
    if not file_path:
        logger.warning(
            f"Artifact {artifact_id} not found in job {job_id} "
            f"({total_artifacts} artifacts exist) (request_id={request_id})"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "ARTIFACT_NOT_FOUND",
                "message": f"Artifact {artifact_id} not found in job {job_id}",
                "job_id": job_id,
                "artifact_id": artifact_id,
                "total_artifacts_in_job": total_artifacts,
                "request_id": request_id
            }
        )

    # Verify the artifact actually belongs to this job (security check)
    # The artifact path should contain the job_id
    artifact_path_str = str(file_path)
    if job_id not in artifact_path_str:
        logger.error(
            f"Security: Artifact {artifact_id} does not belong to job {job_id} "
            f"(request_id={request_id})"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "ARTIFACT_NOT_FOUND",
                "message": f"Artifact {artifact_id} not found in job {job_id}",
                "job_id": job_id,
                "artifact_id": artifact_id,
                "request_id": request_id
            }
        )

    logger.info(f"Serving artifact: {file_path.name} from job {job_id} (request_id={request_id})")
    return FileResponse(
        file_path,
        filename=file_path.name,
        media_type="application/octet-stream"
    )


@app.get(
    "/jobs/{job_id}/nodes/{node_ip}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Zip file containing all artifacts for this node"},
        404: {
            "description": "Job or node not found",
            "model": ErrorResponse
        }
    }
)
async def download_node_artifacts(job_id: str, node_ip: str, request: Request):
    """
    Download all artifacts for a specific node as a zip file.

    Args:
        job_id: Job identifier
        node_ip: Node IP or hostname
        request: FastAPI request object

    Returns:
        FileResponse with zip file containing all node artifacts

    Raises:
        HTTPException: If job or node not found, or no artifacts available
    """
    request_id = get_request_id(request)
    logger.info(f"Node artifacts download request: job={job_id}, node={node_ip} (request_id={request_id})")

    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        logger.warning(f"Job {job_id} not found for node download (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    # Find node status
    node_status = job.node_statuses.get(node_ip)
    if not node_status:
        logger.warning(f"Node {node_ip} not found in job {job_id} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "NODE_NOT_FOUND",
                "message": f"Node {node_ip} not found in job {job_id}",
                "request_id": request_id
            }
        )

    # Get artifacts for this node
    artifacts = node_status.artifacts
    if not artifacts:
        logger.warning(f"No artifacts found for node {node_ip} in job {job_id} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "NO_ARTIFACTS",
                "message": f"No artifacts available for node {node_ip}",
                "request_id": request_id
            }
        )

    # Generate manifest and standardized filename
    try:
        # Generate manifest
        manifest = generate_manifest(
            job_id=job.job_id,
            profile=job.profile.name,
            nodes=[node_ip],
            artifacts=artifacts,
            time_mode="range" if job.requested_start_time else "relative",
            requested_start_time=job.requested_start_time,
            requested_end_time=job.requested_end_time,
            requested_reltime_minutes=job.requested_reltime_minutes,
            computed_reltime_unit=job.computed_reltime_unit,
            computed_reltime_value=job.computed_reltime_value,
            computation_timestamp=job.computation_timestamp
        )

        # Generate standardized filename
        zip_name = generate_zip_filename(
            job_id=job.job_id,
            profile=job.profile.name,
            time_mode="range" if job.requested_start_time else "relative",
            requested_start_time=job.requested_start_time,
            requested_end_time=job.requested_end_time,
            requested_reltime_minutes=job.requested_reltime_minutes,
            node=node_ip
        )

        # Create zip archive with manifest
        zip_path = create_zip_archive(artifacts, zip_name, manifest_data=manifest)

        # Return zip file and clean up after
        return FileResponse(
            zip_path,
            filename=f"{zip_name}.zip",
            media_type="application/zip",
            background=lambda: zip_path.unlink()  # Clean up temp file after serving
        )
    except Exception as e:
        logger.error(f"Failed to create zip for node {node_ip}: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ZIP_CREATION_FAILED",
                "message": "Failed to create zip archive",
                "request_id": request_id
            }
        )


@app.get(
    "/jobs/{job_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Zip file containing all artifacts for all nodes"},
        404: {
            "description": "Job not found",
            "model": ErrorResponse
        }
    }
)
async def download_job_artifacts(job_id: str, request: Request):
    """
    Download all artifacts for all nodes in a job as a zip file.

    Args:
        job_id: Job identifier
        request: FastAPI request object

    Returns:
        FileResponse with zip file containing all job artifacts

    Raises:
        HTTPException: If job not found or no artifacts available
    """
    request_id = get_request_id(request)
    logger.info(f"Job artifacts download request: job={job_id} (request_id={request_id})")

    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        logger.warning(f"Job {job_id} not found for download (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    # Collect all artifacts from all nodes
    all_artifacts = []
    for node_status in job.node_statuses.values():
        all_artifacts.extend(node_status.artifacts)

    if not all_artifacts:
        logger.warning(f"No artifacts found for job {job_id} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "NO_ARTIFACTS",
                "message": f"No artifacts available for job {job_id}",
                "request_id": request_id
            }
        )

    # Generate manifest and standardized filename
    try:
        # Get list of all nodes
        all_nodes = list(job.node_statuses.keys())

        # Generate manifest
        manifest = generate_manifest(
            job_id=job.job_id,
            profile=job.profile.name,
            nodes=all_nodes,
            artifacts=all_artifacts,
            time_mode="range" if job.requested_start_time else "relative",
            requested_start_time=job.requested_start_time,
            requested_end_time=job.requested_end_time,
            requested_reltime_minutes=job.requested_reltime_minutes,
            computed_reltime_unit=job.computed_reltime_unit,
            computed_reltime_value=job.computed_reltime_value,
            computation_timestamp=job.computation_timestamp
        )

        # Generate standardized filename
        zip_name = generate_zip_filename(
            job_id=job.job_id,
            profile=job.profile.name,
            time_mode="range" if job.requested_start_time else "relative",
            requested_start_time=job.requested_start_time,
            requested_end_time=job.requested_end_time,
            requested_reltime_minutes=job.requested_reltime_minutes
        )

        # Create zip archive with manifest
        zip_path = create_zip_archive(all_artifacts, zip_name, manifest_data=manifest)

        # Return zip file and clean up after
        return FileResponse(
            zip_path,
            filename=f"{zip_name}.zip",
            media_type="application/zip",
            background=lambda: zip_path.unlink()  # Clean up temp file after serving
        )
    except Exception as e:
        logger.error(f"Failed to create zip for job {job_id}: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ZIP_CREATION_FAILED",
                "message": "Failed to create zip archive",
                "request_id": request_id
            }
        )


@app.post(
    "/jobs/{job_id}/cancel",
    response_model=CancelJobResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Job cancellation initiated",
            "model": CancelJobResponse
        },
        404: {
            "description": "Job not found",
            "model": ErrorResponse
        }
    }
)
async def cancel_job(job_id: str, request: Request):
    """
    Cancel a running job (best-effort).

    This will stop scheduling new nodes and attempt to cancel the running task.
    Nodes that are already being processed may complete.

    Args:
        job_id: Job identifier
        request: FastAPI request object

    Returns:
        CancelJobResponse with cancellation status

    Raises:
        HTTPException: If job not found
    """
    request_id = get_request_id(request)
    logger.info(f"Job cancellation request: {job_id} (request_id={request_id})")

    job_manager = get_job_manager()
    success = job_manager.cancel_job(job_id)

    if not success:
        logger.warning(f"Job {job_id} not found for cancellation (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    job = job_manager.get_job(job_id)
    return CancelJobResponse(
        job_id=job.job_id,
        status=job.status,
        cancelled=job.cancelled,
        message="Job cancellation initiated"
    )


# ============================================================================
# Retry Failed Nodes
# ============================================================================


@app.post(
    "/jobs/{job_id}/retry-failed",
    response_model=RetryJobResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Retry of failed nodes initiated",
            "model": RetryJobResponse
        },
        404: {
            "description": "Job not found",
            "model": ErrorResponse
        }
    }
)
async def retry_failed_nodes(job_id: str, request: Request):
    """
    Retry only the failed nodes in a job.

    Reuses the same job configuration (profile, time window, credentials)
    but only re-executes nodes that have FAILED status.

    This is useful when some nodes fail due to transient issues (network
    glitches, temporary timeouts, etc.) and you want to retry just those
    nodes without re-running successful ones.

    Artifacts from retry attempts are stored in attempt-specific directories
    (e.g., attempt_1, attempt_2) to preserve the full history.

    Args:
        job_id: Job identifier
        request: FastAPI request object

    Returns:
        RetryJobResponse with retry status and list of nodes being retried

    Raises:
        HTTPException: If job not found or no failed nodes to retry
    """
    request_id = get_request_id(request)
    logger.info(f"Retry failed nodes request: {job_id} (request_id={request_id})")

    job_manager = get_job_manager()
    retried_nodes = job_manager.retry_failed_nodes(job_id)

    if retried_nodes is None:
        logger.warning(f"Job {job_id} not found for retry (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found",
                "request_id": request_id
            }
        )

    job = job_manager.get_job(job_id)

    if len(retried_nodes) == 0:
        message = "No failed nodes to retry"
    else:
        message = f"Retry initiated for {len(retried_nodes)} failed node(s)"

    logger.info(f"Job {job_id} retry: {len(retried_nodes)} nodes queued (request_id={request_id})")

    return RetryJobResponse(
        job_id=job.job_id,
        status=job.status,
        retried_nodes=retried_nodes,
        retry_count=len(retried_nodes),
        message=message
    )


# ============================================================================
# Packet Capture Endpoints
# ============================================================================


@app.post(
    "/captures",
    response_model=StartCaptureResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {
            "description": "Capture started successfully",
            "model": StartCaptureResponse
        },
        401: {
            "description": "Authentication failed",
            "model": ErrorResponse
        },
        502: {
            "description": "Network error (host unreachable)",
            "model": ErrorResponse
        },
        504: {
            "description": "Connection timeout",
            "model": ErrorResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def start_capture(
    req_body: StartCaptureRequest,
    background_tasks: BackgroundTasks,
    request: Request
):
    """
    Start a new packet capture on a CUCM node.

    The capture runs in the background for the specified duration.
    Use GET /captures/{capture_id} to check status.

    Args:
        req_body: Capture request parameters
        background_tasks: FastAPI background tasks
        request: FastAPI request object

    Returns:
        StartCaptureResponse with capture ID and initial status
    """
    request_id = get_request_id(request)
    logger.info(
        f"Starting packet capture on {req_body.host}:{req_body.port} "
        f"for {req_body.duration_sec}s (request_id={request_id})"
    )

    try:
        capture_manager = get_capture_manager()

        # Create capture session
        capture = capture_manager.create_capture(req_body)

        # Schedule execution in background
        background_tasks.add_task(capture_manager.execute_capture, capture.capture_id)

        logger.info(f"Capture {capture.capture_id} created and queued (request_id={request_id})")

        return StartCaptureResponse(
            capture_id=capture.capture_id,
            status=capture.status,
            host=req_body.host,
            filename=capture.filename,
            duration_sec=req_body.duration_sec,
            message="Capture started",
            created_at=capture.created_at
        )

    except Exception as e:
        logger.exception(f"Error starting capture: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to start capture",
                "request_id": request_id
            }
        )


@app.get(
    "/captures",
    response_model=CaptureListResponse,
    status_code=status.HTTP_200_OK
)
async def list_captures(limit: int = 50):
    """
    List recent packet captures.

    Args:
        limit: Maximum number of captures to return (default 50)

    Returns:
        CaptureListResponse with list of captures
    """
    capture_manager = get_capture_manager()
    captures = capture_manager.list_captures(limit=limit)

    return CaptureListResponse(
        captures=[c.to_info() for c in captures],
        total=len(captures)
    )


@app.get(
    "/captures/{capture_id}",
    response_model=CaptureStatusResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Capture status retrieved",
            "model": CaptureStatusResponse
        },
        404: {
            "description": "Capture not found",
            "model": ErrorResponse
        }
    }
)
async def get_capture_status(capture_id: str, request: Request):
    """
    Get the status of a packet capture.

    Args:
        capture_id: Capture identifier
        request: FastAPI request object

    Returns:
        CaptureStatusResponse with capture status and details

    Raises:
        HTTPException: If capture not found
    """
    request_id = get_request_id(request)
    capture_manager = get_capture_manager()
    capture = capture_manager.get_capture(capture_id)

    if not capture:
        logger.warning(f"Capture {capture_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "CAPTURE_NOT_FOUND",
                "message": f"Capture {capture_id} not found",
                "request_id": request_id
            }
        )

    download_available = (
        capture.status == "completed" and
        capture.local_file_path is not None and
        capture.local_file_path.exists()
    )

    return CaptureStatusResponse(
        capture=capture.to_info(),
        download_available=download_available
    )


@app.post(
    "/captures/{capture_id}/stop",
    response_model=StopCaptureResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Capture stop initiated",
            "model": StopCaptureResponse
        },
        404: {
            "description": "Capture not found",
            "model": ErrorResponse
        },
        400: {
            "description": "Capture not running",
            "model": ErrorResponse
        }
    }
)
async def stop_capture(capture_id: str, request: Request):
    """
    Stop a running packet capture.

    Args:
        capture_id: Capture identifier
        request: FastAPI request object

    Returns:
        StopCaptureResponse with stop status

    Raises:
        HTTPException: If capture not found or not running
    """
    request_id = get_request_id(request)
    logger.info(f"Stopping capture {capture_id} (request_id={request_id})")

    capture_manager = get_capture_manager()
    capture = capture_manager.get_capture(capture_id)

    if not capture:
        logger.warning(f"Capture {capture_id} not found for stop (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "CAPTURE_NOT_FOUND",
                "message": f"Capture {capture_id} not found",
                "request_id": request_id
            }
        )

    if capture.status != CaptureStatusEnum.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "CAPTURE_NOT_RUNNING",
                "message": f"Capture {capture_id} is not running (status: {capture.status.value})",
                "request_id": request_id
            }
        )

    success = await capture_manager.stop_capture(capture_id)

    return StopCaptureResponse(
        capture_id=capture_id,
        status=capture.status,
        message="Capture stop initiated" if success else "Failed to stop capture"
    )


@app.get(
    "/captures/{capture_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Capture file download"},
        404: {
            "description": "Capture or file not found",
            "model": ErrorResponse
        }
    }
)
async def download_capture(capture_id: str, request: Request):
    """
    Download a completed packet capture file.

    Args:
        capture_id: Capture identifier
        request: FastAPI request object

    Returns:
        FileResponse with capture file (.cap)

    Raises:
        HTTPException: If capture or file not found
    """
    request_id = get_request_id(request)
    logger.info(f"Download capture {capture_id} (request_id={request_id})")

    capture_manager = get_capture_manager()
    capture = capture_manager.get_capture(capture_id)

    if not capture:
        logger.warning(f"Capture {capture_id} not found for download (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "CAPTURE_NOT_FOUND",
                "message": f"Capture {capture_id} not found",
                "request_id": request_id
            }
        )

    if capture.status != CaptureStatusEnum.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "CAPTURE_NOT_READY",
                "message": f"Capture {capture_id} is not completed (status: {capture.status.value})",
                "request_id": request_id
            }
        )

    # Check if local_file_path is set and exists
    file_path = capture.local_file_path
    if not file_path or not file_path.exists():
        # Fallback: search for file recursively in SFTP received directories
        # CUCM preserves directory structure: <capture_id>/<host>/<timestamp>/platform/cli/<file>.cap
        settings = get_settings()
        capture_file = f"{capture.filename}.cap"
        found_file = None

        # Search in primary location: artifacts_dir/<capture_id>/
        primary_dir = settings.artifacts_dir / capture_id
        if primary_dir.exists():
            for cap_file in primary_dir.rglob(capture_file):
                found_file = cap_file
                break

        # If not found, try nested location: artifacts_dir/<sftp_base>/<capture_id>/
        if not found_file:
            sftp_base = settings.sftp_remote_base_dir or ""
            if sftp_base:
                nested_dir = settings.artifacts_dir / sftp_base / capture_id
                if nested_dir.exists():
                    for cap_file in nested_dir.rglob(capture_file):
                        found_file = cap_file
                        break

        if found_file:
            file_path = found_file
            # Update capture for future requests
            capture.local_file_path = file_path
            capture.file_size_bytes = file_path.stat().st_size
            logger.info(f"Found capture file: {file_path}")
        else:
            logger.warning(f"Capture file {capture_file} not found for {capture_id} (request_id={request_id})")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "CAPTURE_FILE_NOT_FOUND",
                    "message": f"Capture file for {capture_id} not found on server",
                    "request_id": request_id
                }
            )

    return FileResponse(
        file_path,
        filename=f"{capture.filename}.cap",
        media_type="application/vnd.tcpdump.pcap"
    )


@app.delete(
    "/captures/{capture_id}",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Capture deleted"},
        404: {
            "description": "Capture not found",
            "model": ErrorResponse
        }
    }
)
async def delete_capture(capture_id: str, request: Request):
    """
    Delete a packet capture and its files.

    Args:
        capture_id: Capture identifier
        request: FastAPI request object

    Returns:
        Success message

    Raises:
        HTTPException: If capture not found
    """
    request_id = get_request_id(request)
    logger.info(f"Deleting capture {capture_id} (request_id={request_id})")

    capture_manager = get_capture_manager()
    success = capture_manager.delete_capture(capture_id)

    if not success:
        logger.warning(f"Capture {capture_id} not found for deletion (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "CAPTURE_NOT_FOUND",
                "message": f"Capture {capture_id} not found",
                "request_id": request_id
            }
        )

    return {"message": f"Capture {capture_id} deleted"}


# ============================================================================
# Capture Session Endpoints (Multi-Device Orchestration)
# ============================================================================


@app.post(
    "/capture-sessions",
    response_model=StartCaptureSessionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Capture session created and starting"},
        400: {
            "description": "Invalid request",
            "model": ErrorResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def start_capture_session(
    request: StartCaptureSessionRequest,
    req: Request,
    background_tasks: BackgroundTasks
):
    """
    Start a multi-device capture session.

    Orchestrates packet captures across multiple devices (CUCM, CUBE, CSR, Expressway)
    simultaneously. All captures use the same duration and optional filter settings.

    Args:
        request: Capture session request with targets and settings
        req: FastAPI request object
        background_tasks: Background tasks for async execution

    Returns:
        StartCaptureSessionResponse with session ID and initial status

    Raises:
        HTTPException: If validation fails or session cannot be created
    """
    request_id = get_request_id(req)
    logger.info(
        f"Starting capture session with {len(request.targets)} targets "
        f"(request_id={request_id})"
    )

    try:
        session_manager = get_session_manager()

        # Create the session
        session = session_manager.create_session(request)

        # Start captures in background
        background_tasks.add_task(session_manager.start_session, session, request)

        return StartCaptureSessionResponse(
            session_id=session.session_id,
            status=session.status,
            message=f"Capture session created with {len(request.targets)} targets",
            created_at=session.created_at,
            targets=session.targets,
        )

    except ValueError as e:
        logger.error(f"Invalid capture session request: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_REQUEST",
                "message": str(e),
                "request_id": request_id
            }
        )
    except Exception as e:
        logger.error(f"Failed to create capture session: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SESSION_START_FAILED",
                "message": f"Failed to start capture session: {str(e)}",
                "request_id": request_id
            }
        )


@app.get(
    "/capture-sessions",
    response_model=CaptureSessionListResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "List of capture sessions"}
    }
)
async def list_capture_sessions(
    limit: int = 50,
    req: Request = None
):
    """
    List recent capture sessions.

    Args:
        limit: Maximum number of sessions to return (default: 50)
        req: FastAPI request object

    Returns:
        CaptureSessionListResponse with list of sessions
    """
    request_id = get_request_id(req)
    logger.info(f"Listing capture sessions (limit={limit}, request_id={request_id})")

    session_manager = get_session_manager()
    sessions = session_manager.list_sessions(limit=limit)

    return CaptureSessionListResponse(
        sessions=[s.to_info() for s in sessions],
        total=len(sessions)
    )


@app.get(
    "/capture-sessions/{session_id}",
    response_model=CaptureSessionStatusResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Session status"},
        404: {
            "description": "Session not found",
            "model": ErrorResponse
        }
    }
)
async def get_capture_session_status(session_id: str, request: Request):
    """
    Get status of a capture session.

    Updates the session status by checking underlying capture statuses,
    then returns the current state with timing information.

    Args:
        session_id: Session identifier
        request: FastAPI request object

    Returns:
        CaptureSessionStatusResponse with session information

    Raises:
        HTTPException: If session not found
    """
    request_id = get_request_id(request)
    logger.info(f"Getting capture session status {session_id} (request_id={request_id})")

    session_manager = get_session_manager()

    # Update session status from underlying captures
    await session_manager.update_session_status(session_id)

    session = session_manager.get_session(session_id)

    if not session:
        logger.warning(f"Capture session {session_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"Capture session {session_id} not found",
                "request_id": request_id
            }
        )

    # Calculate timing information
    download_available = session.status in [
        CaptureSessionStatusEnum.COMPLETED,
        CaptureSessionStatusEnum.PARTIAL
    ]

    elapsed_sec = None
    remaining_sec = None
    if session.status == CaptureSessionStatusEnum.CAPTURING and session.capture_started_at:
        now = datetime.now(timezone.utc)
        elapsed_td = now - session.capture_started_at
        elapsed_sec = int(elapsed_td.total_seconds())
        # Only calculate remaining time for standard mode (when duration_sec is set)
        if session.duration_sec is not None:
            remaining_sec = max(0, session.duration_sec - elapsed_sec)

    return CaptureSessionStatusResponse(
        session=session.to_info(),
        download_available=download_available,
        elapsed_sec=elapsed_sec,
        remaining_sec=remaining_sec
    )


@app.post(
    "/capture-sessions/{session_id}/stop",
    response_model=StopCaptureSessionResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Session stop initiated"},
        404: {
            "description": "Session not found",
            "model": ErrorResponse
        }
    }
)
async def stop_capture_session(session_id: str, request: Request):
    """
    Stop a running capture session.

    Stops all active captures in the session. Captures that have already
    completed are not affected.

    Args:
        session_id: Session identifier
        request: FastAPI request object

    Returns:
        StopCaptureSessionResponse with updated status

    Raises:
        HTTPException: If session not found
    """
    request_id = get_request_id(request)
    logger.info(f"Stopping capture session {session_id} (request_id={request_id})")

    session_manager = get_session_manager()
    session = await session_manager.stop_session(session_id)

    if not session:
        logger.warning(f"Capture session {session_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"Capture session {session_id} not found",
                "request_id": request_id
            }
        )

    return StopCaptureSessionResponse(
        session_id=session.session_id,
        status=session.status,
        message="Capture session stop initiated"
    )


@app.get(
    "/capture-sessions/{session_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Session bundle download"},
        404: {
            "description": "Session or bundle not found",
            "model": ErrorResponse
        },
        409: {
            "description": "Session not ready for download",
            "model": ErrorResponse
        }
    }
)
async def download_capture_session_bundle(session_id: str, request: Request):
    """
    Download capture session bundle as ZIP.

    Returns a ZIP file containing all completed captures from the session.
    Only available when session status is COMPLETED or PARTIAL.

    Args:
        session_id: Session identifier
        request: FastAPI request object

    Returns:
        FileResponse with ZIP bundle

    Raises:
        HTTPException: If session not found or not ready for download
    """
    request_id = get_request_id(request)
    logger.info(f"Downloading capture session bundle {session_id} (request_id={request_id})")

    session_manager = get_session_manager()
    session = session_manager.get_session(session_id)

    if not session:
        logger.warning(f"Capture session {session_id} not found (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"Capture session {session_id} not found",
                "request_id": request_id
            }
        )

    # Check if session is ready for download
    if session.status not in [CaptureSessionStatusEnum.COMPLETED, CaptureSessionStatusEnum.PARTIAL]:
        logger.warning(
            f"Capture session {session_id} not ready for download (status={session.status}, "
            f"request_id={request_id})"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "SESSION_NOT_READY",
                "message": f"Session is not ready for download (status: {session.status})",
                "request_id": request_id
            }
        )

    # Create ZIP bundle with all completed captures
    settings = get_settings()
    capture_manager = get_capture_manager()

    # Collect all completed capture files
    capture_files = []
    for target in session.targets:
        if target.capture_id and target.status == "completed":
            capture = capture_manager.get_capture(target.capture_id)
            if capture and capture.local_file_path and capture.local_file_path.exists():
                # Use the actual local_file_path from the capture object
                capture_files.append((capture.local_file_path, f"{target.host}_{capture.local_file_path.name}"))

    if not capture_files:
        logger.warning(f"No capture files found for session {session_id} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "NO_CAPTURES_FOUND",
                "message": "No completed capture files found in session",
                "request_id": request_id
            }
        )

    # Create ZIP bundle
    bundle_filename = f"capture_session_{session_id[:8]}.zip"
    bundle_path = Path(settings.artifacts_dir) / "sessions" / bundle_filename
    bundle_path.parent.mkdir(parents=True, exist_ok=True)

    import zipfile
    with zipfile.ZipFile(bundle_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path, archive_name in capture_files:
            zipf.write(file_path, archive_name)

    # Update session with bundle filename
    session.bundle_filename = bundle_filename

    return FileResponse(
        bundle_path,
        filename=bundle_filename,
        media_type="application/zip"
    )


@app.delete(
    "/capture-sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Session deleted"},
        404: {
            "description": "Session not found",
            "model": ErrorResponse
        }
    }
)
async def delete_capture_session(session_id: str, request: Request):
    """
    Delete a capture session.

    Deletes the session metadata. Note: This does not delete the underlying
    individual capture files. Use the individual capture delete endpoint if needed.

    Args:
        session_id: Session identifier
        request: FastAPI request object

    Returns:
        Success message

    Raises:
        HTTPException: If session not found
    """
    request_id = get_request_id(request)
    logger.info(f"Deleting capture session {session_id} (request_id={request_id})")

    session_manager = get_session_manager()
    success = session_manager.delete_session(session_id)

    if not success:
        logger.warning(f"Capture session {session_id} not found for deletion (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "SESSION_NOT_FOUND",
                "message": f"Capture session {session_id} not found",
                "request_id": request_id
            }
        )

    return {"message": f"Capture session {session_id} deleted"}


# ============================================================================
# Log Collection Endpoints
# ============================================================================


@app.post(
    "/logs",
    response_model=StartLogCollectionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Log collection started"},
        400: {
            "description": "Invalid request",
            "model": ErrorResponse
        },
        500: {
            "description": "Internal server error",
            "model": ErrorResponse
        }
    }
)
async def start_log_collection(
    req_body: StartLogCollectionRequest,
    background_tasks: BackgroundTasks,
    request: Request
):
    """
    Start log collection from a CUBE or Expressway device.

    For CUBE:
    - Uses VoIP Trace (IOS-XE 17.3.2+) by default - minimal CPU impact
    - Set include_debug=true for traditional debug collection (CPU intensive)

    For Expressway:
    - Uses diagnostic logging REST API
    - Collects event logs and system diagnostics

    The collection runs in the background. Use GET /logs/{collection_id} to check status.
    """
    request_id = get_request_id(request)
    logger.info(
        f"Starting log collection on {req_body.host} "
        f"(device_type={req_body.device_type}, request_id={request_id})"
    )

    try:
        manager = get_log_collection_manager()
        collection = manager.create_collection(req_body)

        # Start collection in background
        background_tasks.add_task(manager.execute_collection, collection.collection_id)

        logger.info(
            f"Log collection {collection.collection_id} created and queued "
            f"(request_id={request_id})"
        )

        return StartLogCollectionResponse(
            collection_id=collection.collection_id,
            status=collection.status,
            host=req_body.host,
            device_type=req_body.device_type,
            message="Log collection started",
            created_at=collection.created_at
        )

    except Exception as e:
        logger.exception(f"Failed to start log collection: {e} (request_id={request_id})")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "COLLECTION_START_FAILED",
                "message": str(e),
                "request_id": request_id
            }
        )


@app.get(
    "/logs",
    response_model=LogCollectionListResponse,
    responses={
        200: {"description": "List of log collections"}
    }
)
async def list_log_collections(
    limit: int = 50,
    request: Request = None
):
    """
    List recent log collection operations.

    Returns up to 'limit' most recent collections, ordered by creation time descending.
    """
    manager = get_log_collection_manager()
    collections = manager.list_collections(limit=limit)

    return LogCollectionListResponse(
        collections=[c.to_info() for c in collections],
        total=len(collections)
    )


@app.get(
    "/logs/profiles",
    response_model=LogProfilesResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "List of available profiles for CUBE and Expressway"}
    }
)
async def list_log_profiles():
    """
    List available log collection profiles for CUBE and Expressway devices.

    Returns all configured profiles with their settings.
    Use these profile names when starting log collection.
    """
    catalog = get_profile_catalog()

    # Get CUBE profiles
    cube_profiles = [
        CubeProfileResponse(
            name=p.name,
            description=p.description,
            device_type=p.device_type,
            method=p.method,
            commands=p.commands,
            include_debug=p.include_debug,
            duration_sec=p.duration_sec
        )
        for p in catalog.list_cube_profiles()
    ]

    # Get Expressway profiles
    expressway_profiles = [
        ExpresswayProfileResponse(
            name=p.name,
            description=p.description,
            device_type=p.device_type,
            method=p.method,
            tcpdump=p.tcpdump
        )
        for p in catalog.list_expressway_profiles()
    ]

    return LogProfilesResponse(
        cube_profiles=cube_profiles,
        expressway_profiles=expressway_profiles
    )


@app.get(
    "/logs/{collection_id}",
    response_model=LogCollectionStatusResponse,
    responses={
        200: {"description": "Collection status"},
        404: {
            "description": "Collection not found",
            "model": ErrorResponse
        }
    }
)
async def get_log_collection_status(collection_id: str, request: Request):
    """
    Get the status of a log collection operation.

    Returns current status, progress, and download availability.
    """
    request_id = get_request_id(request)
    manager = get_log_collection_manager()
    collection = manager.get_collection(collection_id)

    if not collection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "COLLECTION_NOT_FOUND",
                "message": f"Log collection {collection_id} not found",
                "request_id": request_id
            }
        )

    download_available = (
        collection.status == LogCollectionStatusEnum.COMPLETED and
        collection.local_file_path is not None and
        collection.local_file_path.exists()
    )

    return LogCollectionStatusResponse(
        collection=collection.to_info(),
        download_available=download_available
    )


@app.post(
    "/logs/{collection_id}/stop",
    status_code=status.HTTP_200_OK,
    responses={404: {"description": "Collection not found"}},
    tags=["Log Collection"],
    summary="Stop a running log collection",
)
async def stop_log_collection(collection_id: str):
    """
    Stop a running log collection gracefully.

    Sends a stop signal to interrupt the active collection.
    The collection will finish any in-progress operations and save results.
    """
    manager = get_log_collection_manager()
    result = await manager.stop_collection(collection_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Collection not found or not running"
        )
    return {"message": "Stop signal sent", "collection_id": collection_id}


# ============================================================================
# CUBE Debug Status Endpoints
# ============================================================================


@app.post(
    "/cube-debug/status",
    response_model=CubeDebugStatusResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Current debug status"},
        401: {"description": "Authentication failed", "model": ErrorResponse},
        502: {"description": "Network error", "model": ErrorResponse},
        504: {"description": "Connection timeout", "model": ErrorResponse},
    },
    tags=["CUBE Debug"],
    summary="Check current debug status on a CUBE",
)
async def get_cube_debug_status(req_body: CubeDebugStatusRequest, request: Request):
    """
    Check which debug categories are currently enabled on a CUBE.

    Connects via SSH and runs `show debug` to list active debugs.
    """
    request_id = get_request_id(request)
    logger = logging.getLogger("api.cube_debug")

    try:
        async with CSRSSHClient(
            host=req_body.host,
            port=req_body.port,
            username=req_body.username,
            password=req_body.password,
            connect_timeout=float(req_body.connect_timeout_sec),
        ) as client:
            output = await client.execute_command("show debug", timeout=30.0)

            categories: list[CubeDebugCategory] = []
            if output:
                # If output contains "no debugging", all debugs are off
                lower_output = output.lower()
                if "no debug" not in lower_output:
                    # Parse each non-empty line for active debug categories
                    for line in output.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        # Skip header/prompt lines
                        if line.startswith("#") or "show debug" in line.lower():
                            continue
                        # Lines like "CCSIP SPI messages debugging is on"
                        # or "VoIP ccAPI inout debugging is on"
                        if "debugging is on" in line.lower():
                            # Extract the category name (everything before "debugging is on")
                            idx = line.lower().index("debugging is on")
                            name = line[:idx].strip()
                            if name:
                                categories.append(CubeDebugCategory(name=name, enabled=True))
                        elif "debugging is off" in line.lower():
                            idx = line.lower().index("debugging is off")
                            name = line[:idx].strip()
                            if name:
                                categories.append(CubeDebugCategory(name=name, enabled=False))

            return CubeDebugStatusResponse(
                host=req_body.host,
                success=True,
                categories=categories,
                raw_output=output,
                checked_at=datetime.now(timezone.utc),
            )

    except CSRAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": f"Authentication failed for {req_body.host}: {e}",
                "request_id": request_id,
            },
        )
    except CSRConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "CONNECTION_TIMEOUT",
                "message": f"Connection to {req_body.host} failed: {e}",
                "request_id": request_id,
            },
        )
    except CSRCommandTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "COMMAND_TIMEOUT",
                "message": f"Command timed out on {req_body.host}: {e}",
                "request_id": request_id,
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error checking CUBE debug status on {req_body.host}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "NETWORK_ERROR",
                "message": f"Failed to check debug status on {req_body.host}: {e}",
                "request_id": request_id,
            },
        )


@app.post(
    "/cube-debug/enable",
    response_model=CubeDebugEnableResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Debug commands enabled"},
        401: {"description": "Authentication failed", "model": ErrorResponse},
        502: {"description": "Network error", "model": ErrorResponse},
        504: {"description": "Connection timeout", "model": ErrorResponse},
    },
    tags=["CUBE Debug"],
    summary="Enable debug commands on a CUBE",
)
async def enable_cube_debug(req_body: CubeDebugEnableRequest, request: Request):
    """
    Enable one or more debug commands on a CUBE.

    Connects via SSH and executes each debug command
    (e.g., `debug ccsip messages`, `debug voip ccapi inout`).
    """
    request_id = get_request_id(request)
    logger = logging.getLogger("api.cube_debug")

    try:
        async with CSRSSHClient(
            host=req_body.host,
            port=req_body.port,
            username=req_body.username,
            password=req_body.password,
            connect_timeout=float(req_body.connect_timeout_sec),
        ) as client:
            enabled: list[str] = []
            failed: list[str] = []
            all_output: list[str] = []

            for cmd in req_body.commands:
                try:
                    output = await client.execute_command(cmd, timeout=30.0)
                    all_output.append(f"=== {cmd} ===\n{output or ''}")
                    # Check for error indicators in output
                    if output and ("invalid" in output.lower() or "error" in output.lower() or "% " in output):
                        failed.append(cmd)
                    else:
                        enabled.append(cmd)
                except Exception as cmd_err:
                    logger.warning(f"Failed to execute debug command '{cmd}': {cmd_err}")
                    failed.append(cmd)
                    all_output.append(f"=== {cmd} ===\nERROR: {cmd_err}")

            return CubeDebugEnableResponse(
                host=req_body.host,
                success=len(enabled) > 0,
                enabled=enabled,
                failed=failed,
                raw_output="\n".join(all_output),
            )

    except CSRAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": f"Authentication failed for {req_body.host}: {e}",
                "request_id": request_id,
            },
        )
    except CSRConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "CONNECTION_TIMEOUT",
                "message": f"Connection to {req_body.host} failed: {e}",
                "request_id": request_id,
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error enabling CUBE debug on {req_body.host}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "NETWORK_ERROR",
                "message": f"Failed to enable debug on {req_body.host}: {e}",
                "request_id": request_id,
            },
        )


@app.post(
    "/cube-debug/clear",
    response_model=CubeDebugClearResponse,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "All debugs cleared"},
        401: {"description": "Authentication failed", "model": ErrorResponse},
        502: {"description": "Network error", "model": ErrorResponse},
        504: {"description": "Connection timeout", "model": ErrorResponse},
    },
    tags=["CUBE Debug"],
    summary="Clear all debugs on a CUBE",
)
async def clear_cube_debug(req_body: CubeDebugStatusRequest, request: Request):
    """
    Clear all active debugs on a CUBE.

    Connects via SSH and runs `undebug all`.
    """
    request_id = get_request_id(request)
    logger = logging.getLogger("api.cube_debug")

    try:
        async with CSRSSHClient(
            host=req_body.host,
            port=req_body.port,
            username=req_body.username,
            password=req_body.password,
            connect_timeout=float(req_body.connect_timeout_sec),
        ) as client:
            output = await client.execute_command("undebug all", timeout=30.0)

            return CubeDebugClearResponse(
                host=req_body.host,
                success=True,
                raw_output=output,
            )

    except CSRAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": f"Authentication failed for {req_body.host}: {e}",
                "request_id": request_id,
            },
        )
    except CSRConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "CONNECTION_TIMEOUT",
                "message": f"Connection to {req_body.host} failed: {e}",
                "request_id": request_id,
            },
        )
    except Exception as e:
        logger.exception(f"Unexpected error clearing CUBE debug on {req_body.host}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "NETWORK_ERROR",
                "message": f"Failed to clear debug on {req_body.host}: {e}",
                "request_id": request_id,
            },
        )


@app.get(
    "/logs/{collection_id}/download",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Log file download"},
        404: {
            "description": "Collection or file not found",
            "model": ErrorResponse
        }
    }
)
async def download_log_collection(collection_id: str, request: Request):
    """
    Download the collected log file.

    Returns the log file as a downloadable attachment.
    """
    request_id = get_request_id(request)
    manager = get_log_collection_manager()
    collection = manager.get_collection(collection_id)

    if not collection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "COLLECTION_NOT_FOUND",
                "message": f"Log collection {collection_id} not found",
                "request_id": request_id
            }
        )

    if collection.status != LogCollectionStatusEnum.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "COLLECTION_NOT_READY",
                "message": f"Log collection is {collection.status.value}, not ready for download",
                "request_id": request_id
            }
        )

    if not collection.local_file_path or not collection.local_file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "FILE_NOT_FOUND",
                "message": "Log file not found on server",
                "request_id": request_id
            }
        )

    file_path = collection.local_file_path
    filename = file_path.name

    # Determine media type based on file extension
    if filename.endswith('.tar.gz'):
        media_type = "application/gzip"
    elif filename.endswith('.txt'):
        media_type = "text/plain"
    else:
        media_type = "application/octet-stream"

    logger.info(f"Downloading log file {filename} (request_id={request_id})")

    return FileResponse(
        file_path,
        filename=filename,
        media_type=media_type
    )


@app.delete(
    "/logs/{collection_id}",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Collection deleted"},
        404: {
            "description": "Collection not found",
            "model": ErrorResponse
        }
    }
)
async def delete_log_collection(collection_id: str, request: Request):
    """
    Delete a log collection and its files.
    """
    request_id = get_request_id(request)
    logger.info(f"Deleting log collection {collection_id} (request_id={request_id})")

    manager = get_log_collection_manager()
    success = manager.delete_collection(collection_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "COLLECTION_NOT_FOUND",
                "message": f"Log collection {collection_id} not found",
                "request_id": request_id
            }
        )

    return {"message": f"Log collection {collection_id} deleted"}


# ============================================================================
# Utility Functions
# ============================================================================


def _truncate_output(output: str) -> tuple[str, bool]:
    """
    Truncate output to maximum size if needed.

    Args:
        output: Raw output string

    Returns:
        Tuple of (truncated_output, was_truncated)
    """
    if len(output) <= MAX_RAW_OUTPUT_SIZE:
        return output, False

    # Truncate and add marker
    truncated = output[:MAX_RAW_OUTPUT_SIZE]
    truncated += "\n\n... [OUTPUT TRUNCATED] ..."
    return truncated, True


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """Handle Pydantic validation errors"""
    logger.error(f"Validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Invalid request parameters",
            "details": exc.errors()
        }
    )


# ============================================================================
# Environment Endpoints
# ============================================================================


@app.get("/environments", response_model=EnvironmentListResponse)
async def list_environments():
    """List all environments"""
    mgr = get_environment_manager()
    envs = mgr.list_all()
    return EnvironmentListResponse(
        environments=[e.to_response() for e in envs],
        total=len(envs),
    )


@app.post("/environments", response_model=EnvironmentResponse, status_code=201)
async def create_environment(request: EnvironmentCreate):
    """Create a new environment"""
    mgr = get_environment_manager()
    env = mgr.create(
        name=request.name,
        description=request.description,
        devices=request.devices if request.devices else None,
    )
    return env.to_response()


@app.get("/environments/{env_id}", response_model=EnvironmentResponse)
async def get_environment(env_id: str):
    """Get an environment by ID"""
    mgr = get_environment_manager()
    env = mgr.get(env_id)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return env.to_response()


@app.put("/environments/{env_id}", response_model=EnvironmentResponse)
async def update_environment(env_id: str, request: EnvironmentUpdate):
    """Update an environment"""
    mgr = get_environment_manager()
    env = mgr.update(env_id, name=request.name, description=request.description)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return env.to_response()


@app.delete("/environments/{env_id}", status_code=204)
async def delete_environment(env_id: str):
    """Delete an environment"""
    mgr = get_environment_manager()
    if not mgr.delete(env_id):
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")


@app.post("/environments/{env_id}/devices", response_model=EnvironmentResponse)
async def add_device_to_environment(env_id: str, request: DeviceEntryCreate):
    """Add a device to an environment"""
    mgr = get_environment_manager()
    env = mgr.add_device(env_id, request)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return env.to_response()


@app.delete("/environments/{env_id}/devices/{device_id}", response_model=EnvironmentResponse)
async def remove_device_from_environment(env_id: str, device_id: str):
    """Remove a device from an environment"""
    mgr = get_environment_manager()
    env = mgr.remove_device(env_id, device_id)
    if not env:
        raise HTTPException(
            status_code=404,
            detail=f"Environment {env_id} or device {device_id} not found"
        )
    return env.to_response()


@app.post("/environments/{env_id}/discover", response_model=EnvironmentResponse)
async def discover_environment_nodes(env_id: str, request: DiscoverNodesRequest):
    """Discover CUCM subscriber nodes and add them to the environment"""
    mgr = get_environment_manager()
    env = mgr.get(env_id)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")

    # Discover nodes using existing discover logic
    try:
        raw_output = await run_show_network_cluster(
            host=request.publisher_host,
            port=request.port,
            username=request.username,
            password=request.password,
            connect_timeout=request.connect_timeout_sec,
            command_timeout=request.command_timeout_sec,
        )
        nodes = parse_show_network_cluster(raw_output)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Discovery failed: {str(e)}")

    # Add discovered nodes as devices (skip publisher if already exists)
    existing_hosts = {d.host for d in env.devices}
    from app.models import DeviceEntryCreate, EnvironmentDeviceType
    for node in nodes:
        node_host = node.get("ip", "")
        if not node_host or node_host in existing_hosts:
            continue
        role_str = node.get("role", "Subscriber")
        device_name = node.get("host", node_host)
        create = DeviceEntryCreate(
            name=device_name,
            device_type=EnvironmentDeviceType.CUCM,
            host=node_host,
            port=request.port,
            role="publisher" if "pub" in role_str.lower() else "subscriber",
        )
        env.add_device(create)

    env.save()
    return env.to_response()


# ============================================================================
# Scenario Endpoints
# ============================================================================


@app.get("/scenarios", response_model=ScenarioListResponse)
async def list_scenarios():
    """List available scenario templates"""
    from app.scenario_service import get_scenario_manager
    mgr = get_scenario_manager()
    return ScenarioListResponse(scenarios=mgr.list_all())


# ============================================================================
# Investigation Endpoints
# ============================================================================


@app.post("/investigations", response_model=CreateInvestigationResponse, status_code=202)
async def create_investigation(request: CreateInvestigationRequest, background_tasks: BackgroundTasks):
    """Create a new investigation"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    try:
        inv = mgr.create(request)
        return CreateInvestigationResponse(
            investigation_id=inv.investigation_id,
            status=inv.status,
            message=f"Investigation '{inv.name}' created",
            created_at=inv.created_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/investigations", response_model=InvestigationListResponse)
async def list_investigations():
    """List all investigations"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    investigations = mgr.list_all()
    from app.models import InvestigationSummary
    summaries = [
        InvestigationSummary(
            investigation_id=inv.investigation_id,
            name=inv.name,
            scenario=inv.scenario,
            status=inv.status,
            device_count=len(inv.devices),
            created_at=inv.created_at,
            completed_at=inv.completed_at,
            download_available=inv.bundle_path is not None,
        )
        for inv in investigations
    ]
    return InvestigationListResponse(investigations=summaries, total=len(summaries))


@app.get("/investigations/new", include_in_schema=False)
async def serve_investigation_wizard():
    """Serve SPA for /investigations/new (must be before {inv_id} param route)"""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="Frontend not found")


@app.get("/investigations/{inv_id}", response_model=InvestigationStatusResponse)
async def get_investigation(inv_id: str):
    """Get investigation status"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    return inv.to_status_response()


@app.post("/investigations/{inv_id}/prepare", response_model=InvestigationStatusResponse)
async def prepare_investigation(inv_id: str, background_tasks: BackgroundTasks):
    """Start the preparation phase (set traces, run health baseline)"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    try:
        background_tasks.add_task(mgr.start_preparation, inv_id)
        return inv.to_status_response()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/investigations/{inv_id}/ready", response_model=InvestigationStatusResponse)
async def signal_investigation_ready(inv_id: str):
    """Signal that the investigation is ready to start recording"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    try:
        mgr.signal_ready(inv_id)
        return inv.to_status_response()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/investigations/{inv_id}/record", response_model=InvestigationStatusResponse)
async def start_investigation_recording(inv_id: str, background_tasks: BackgroundTasks):
    """Start the recording phase (start captures)"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    try:
        background_tasks.add_task(mgr.start_recording, inv_id)
        return inv.to_status_response()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/investigations/{inv_id}/collect", response_model=InvestigationStatusResponse)
async def collect_investigation(inv_id: str, background_tasks: BackgroundTasks):
    """Stop recording and start collecting artifacts"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    try:
        background_tasks.add_task(mgr.stop_and_collect, inv_id)
        return inv.to_status_response()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/investigations/{inv_id}/cancel", response_model=InvestigationStatusResponse)
async def cancel_investigation(inv_id: str):
    """Cancel an investigation"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    mgr.cancel(inv_id)
    return inv.to_status_response()


@app.get("/investigations/{inv_id}/download")
async def download_investigation_bundle(inv_id: str):
    """Download the investigation artifact bundle"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    inv = mgr.get(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
    if not inv.bundle_path:
        raise HTTPException(status_code=404, detail="No bundle available for download")
    bundle = Path(inv.bundle_path)
    if not bundle.exists():
        raise HTTPException(status_code=404, detail="Bundle file not found on disk")
    return FileResponse(
        path=str(bundle),
        filename=bundle.name,
        media_type="application/zip",
    )


@app.delete("/investigations/{inv_id}", status_code=204)
async def delete_investigation(inv_id: str):
    """Delete an investigation"""
    from app.investigation_service import get_investigation_manager
    mgr = get_investigation_manager()
    if not mgr.delete(inv_id):
        raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")


# ============================================================================
# Frontend SPA Routing (Catch-all - must be LAST)
# ============================================================================
# These routes are defined last so API routes take precedence

if FRONTEND_DIR.exists() and FRONTEND_DIR.is_dir():
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        """
        Serve the React SPA for all non-API routes.

        This catch-all route serves index.html for client-side routing.
        All API routes defined above will take precedence.
        """
        index_file = FRONTEND_DIR / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="Frontend not found")

        return FileResponse(index_file)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
