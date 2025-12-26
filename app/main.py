"""FastAPI application for CUCM Log Collector"""

import asyncio
import logging
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse
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
    JobStatus as JobStatusEnum
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
    version="0.2.0"
)

# Maximum size for raw output in responses (40KB)
MAX_RAW_OUTPUT_SIZE = 40 * 1024


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "CUCM Log Collector",
        "version": "0.2.0",
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
async def discover_nodes(request: DiscoverNodesRequest):
    """
    Discover nodes in a CUCM cluster.

    Connects to the CUCM Publisher via SSH, executes 'show network cluster',
    and parses the output to extract cluster node information.

    Args:
        request: DiscoverNodesRequest with connection parameters

    Returns:
        DiscoverNodesResponse with list of nodes

    Raises:
        HTTPException: With appropriate status code and error details
    """
    logger.info(
        f"Node discovery request for {request.publisher_host}:{request.port} "
        f"as user {request.username}"
    )
    # NEVER log the password

    raw_output: Optional[str] = None
    nodes: list[ClusterNode] = []

    try:
        # Run the SSH command
        raw_output = await run_show_network_cluster(
            host=request.publisher_host,
            port=request.port,
            username=request.username,
            password=request.password,
            connect_timeout=float(request.connect_timeout_sec),
            command_timeout=float(request.command_timeout_sec)
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
        logger.error(f"Authentication failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_FAILED",
                "message": "Authentication failed. Please check username and password."
            }
        )

    except CUCMCommandTimeoutError as e:
        logger.error(f"Command timeout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "COMMAND_TIMEOUT",
                "message": f"Command execution timed out after {request.command_timeout_sec}s"
            }
        )

    except CUCMConnectionError as e:
        error_msg = str(e).lower()

        # Check if it's a timeout
        if "timeout" in error_msg:
            logger.error(f"Connection timeout: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "CONNECT_TIMEOUT",
                    "message": f"Connection timeout to {request.publisher_host}:{request.port}"
                }
            )
        else:
            # Other network errors (unreachable, refused, etc)
            logger.error(f"Connection error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "NETWORK_ERROR",
                    "message": f"Cannot connect to {request.publisher_host}:{request.port}. "
                               f"Please check host is reachable and SSH is available."
                }
            )

    except CUCMSSHClientError as e:
        logger.error(f"SSH client error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SSH_ERROR",
                "message": "SSH client error occurred"
            }
        )

    except Exception as e:
        logger.exception(f"Unexpected error during node discovery: {str(e)}")
        # In production, don't expose internal error details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred during node discovery"
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
    "/jobs",
    response_model=CreateJobResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def create_job(request: CreateJobRequest, background_tasks: BackgroundTasks):
    """
    Create a new log collection job.

    The job will be executed asynchronously in the background.

    Args:
        request: Job creation request
        background_tasks: FastAPI background tasks

    Returns:
        CreateJobResponse with job ID and initial status

    Raises:
        HTTPException: If profile not found or other validation error
    """
    logger.info(f"Creating job for profile '{request.profile}' with {len(request.nodes)} nodes")

    try:
        job_manager = get_job_manager()

        # Create the job
        job = job_manager.create_job(request)

        # Schedule execution in background
        background_tasks.add_task(job_manager.execute_job, job.job_id)

        logger.info(f"Job {job.job_id} created and queued for execution")

        return CreateJobResponse(
            job_id=job.job_id,
            status=job.status,
            created_at=job.created_at
        )

    except ValueError as e:
        # Profile not found or validation error
        logger.error(f"Validation error creating job: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_REQUEST",
                "message": str(e)
            }
        )
    except Exception as e:
        logger.exception(f"Error creating job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to create job"
            }
        )


@app.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK
)
async def get_job_status(job_id: str):
    """
    Get the status of a log collection job.

    Args:
        job_id: Job identifier

    Returns:
        JobStatusResponse with job status and node details

    Raises:
        HTTPException: If job not found
    """
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found"
            }
        )

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        profile=job.profile.name,
        nodes=list(job.node_statuses.values())
    )


@app.get(
    "/jobs/{job_id}/artifacts",
    response_model=ArtifactsResponse,
    status_code=status.HTTP_200_OK
)
async def get_job_artifacts(job_id: str):
    """
    Get all artifacts collected by a job.

    Args:
        job_id: Job identifier

    Returns:
        ArtifactsResponse with list of artifacts

    Raises:
        HTTPException: If job not found
    """
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "JOB_NOT_FOUND",
                "message": f"Job {job_id} not found"
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
