"""FastAPI application for CUCM Log Collector"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
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
    CancelJobResponse,  # v0.3
    RetryJobResponse,  # BE-030
    EstimateResponse,  # BE-027
    NodeEstimate,  # BE-027
    CommandEstimate,  # BE-027
    ClusterHealthRequest,  # Health Status
    ClusterHealthResponse,  # Health Status
    StartCaptureRequest,  # Packet Capture
    StartCaptureResponse,  # Packet Capture
    CaptureStatusResponse,  # Packet Capture
    CaptureListResponse,  # Packet Capture
    StopCaptureResponse,  # Packet Capture
    CaptureStatus as CaptureStatusEnum,  # Packet Capture
    StartLogCollectionRequest,  # Log Collection
    StartLogCollectionResponse,  # Log Collection
    LogCollectionStatusResponse,  # Log Collection
    LogCollectionListResponse,  # Log Collection
    LogCollectionStatus as LogCollectionStatusEnum,  # Log Collection
)
from app.ssh_client import (
    run_show_network_cluster,
    CUCMAuthError,
    CUCMConnectionError,
    CUCMCommandTimeoutError,
    CUCMSSHClientError
)
from app.parsers import parse_show_network_cluster
from app.profiles import get_profile_catalog
from app.job_manager import get_job_manager
from app.middleware import RequestIDMiddleware, APIKeyAuthMiddleware, get_request_id  # v0.3
from app.artifact_manager import (
    get_artifact_path,
    get_transcript_path,
    create_zip_archive,
    generate_manifest,  # BE-029
    generate_zip_filename  # BE-029
)
from app.config import get_settings  # BE-012
from app.prompt_responder import compute_reltime_from_range, build_file_get_command  # BE-027
from app.health_service import check_cluster_health  # Health Status
from app.capture_service import get_capture_manager  # Packet Capture
from app.log_service import get_log_collection_manager  # Log Collection


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Reduce AsyncSSH library noise
logging.getLogger('asyncssh').setLevel(logging.WARNING)

# Create FastAPI app
app = FastAPI(
    title="CUCM Log Collector API",
    description="Backend service for discovering and collecting logs from CUCM clusters",
    version="0.5.0"  # v0.5.0: Packet capture support
)

# Wire up middleware (v0.3)
# CORS middleware must be first (BE-008: Flutter Web support)
# BE-015: Use environment variable directly to avoid loading full settings at import time
cors_allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"  # Default: localhost/127.0.0.1
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=cors_allowed_origins,  # BE-015: Configurable CORS origins
    allow_methods=["*"],  # Allow all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allow all headers (including Authorization, Content-Type)
    expose_headers=["X-Request-ID", "Content-Disposition"],  # BE-015: Expose headers for downloads
    allow_credentials=True  # Allow cookies/auth headers
)
app.add_middleware(RequestIDMiddleware)  # Adds request_id
app.add_middleware(APIKeyAuthMiddleware)  # Auth (if API_KEY env set)


# ============================================================================
# Exception Handlers (v0.3.1)
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


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "CUCM Log Collector",
        "version": "0.3.3",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


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

    # BE-012: Safe debug logging (only when DEBUG_HTTP=true)
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
# Job Management Endpoints (v0.2)
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
            match=p.match
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
    BE-027: Estimate what a log collection job would do (dry-run).

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

    # BE-019: Get progress metrics
    progress = job.get_progress_metrics()

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        profile=job.profile.name,
        nodes=list(job.node_statuses.values()),
        # BE-019: Include progress metrics
        total_nodes=progress["total_nodes"],
        completed_nodes=progress["completed_nodes"],
        succeeded_nodes=progress["succeeded_nodes"],
        failed_nodes=progress["failed_nodes"],
        running_nodes=progress["running_nodes"],
        percent_complete=progress["percent_complete"],
        last_updated_at=progress["last_updated_at"],
        # BE-026: Include time window configuration
        requested_start_time=job.requested_start_time,
        requested_end_time=job.requested_end_time,
        requested_reltime_minutes=job.requested_reltime_minutes,
        computed_reltime_unit=job.computed_reltime_unit,
        computed_reltime_value=job.computed_reltime_value,
        computation_timestamp=job.computation_timestamp
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
# v0.3 Endpoints - Downloads and Cancellation
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
    Download an artifact by its stable ID (v0.3).

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
    Download a single artifact from a specific job (BE-021.2).

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
    Download all artifacts for a specific node as a zip file (BE-017).

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

    # BE-029: Generate manifest and standardized filename
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
    Download all artifacts for all nodes in a job as a zip file (BE-017).

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

    # BE-029: Generate manifest and standardized filename
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
    Cancel a running job (best-effort) (v0.3).

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
# BE-030: Retry Failed Nodes
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
    BE-030: Retry only the failed nodes in a job.

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

    return CaptureStatusResponse(capture=capture.to_info())


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
