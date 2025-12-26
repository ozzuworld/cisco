"""FastAPI application for CUCM Log Collector"""

import logging
from typing import Optional
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.models import (
    DiscoverNodesRequest,
    DiscoverNodesResponse,
    ErrorResponse,
    ClusterNode
)
from app.ssh_client import (
    run_show_network_cluster,
    CUCMAuthError,
    CUCMConnectionError,
    CUCMCommandTimeoutError,
    CUCMSSHClientError
)
from app.parsers import parse_show_network_cluster


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="CUCM Log Collector API",
    description="Backend service for discovering and collecting logs from CUCM clusters",
    version="0.1.0"
)

# Maximum size for raw output in responses (40KB)
MAX_RAW_OUTPUT_SIZE = 40 * 1024


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "CUCM Log Collector",
        "version": "0.1.0",
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
