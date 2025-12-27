"""Authentication and middleware for CUCM Log Collector API"""

import uuid
import logging
from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import get_settings


logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add a unique request ID to every request and response.

    The request ID is useful for tracing requests through logs and correlating
    errors with specific API calls.
    """

    async def dispatch(self, request: Request, call_next):
        """Add request ID to request state and response headers"""
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            # Even on error, include request_id
            logger.exception(f"Request {request_id} failed with exception: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "INTERNAL_ERROR",
                    "message": "An internal server error occurred",
                    "request_id": request_id
                },
                headers={"X-Request-ID": request_id}
            )


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Optional API key authentication middleware.

    If API_KEY is set in environment, requires all requests to include:
        Authorization: Bearer <API_KEY>

    If API_KEY is not set, authentication is disabled (dev mode).
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        settings = get_settings()
        self.api_key: Optional[str] = getattr(settings, 'api_key', None)
        self.auth_enabled = self.api_key is not None and len(self.api_key) > 0

        if self.auth_enabled:
            logger.info("API key authentication ENABLED")
        else:
            logger.warning("API key authentication DISABLED (dev mode)")

    async def dispatch(self, request: Request, call_next):
        """Check API key if authentication is enabled"""
        # Skip auth for health check and docs
        if request.url.path in ["/", "/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        # Skip auth for OPTIONS (CORS preflight) requests (BE-008)
        if request.method == "OPTIONS":
            return await call_next(request)

        if self.auth_enabled:
            # Get request_id from request state (set by RequestIDMiddleware)
            # If missing (race condition), generate one defensively (v0.3.1)
            request_id = getattr(request.state, 'request_id', None)
            if not request_id:
                request_id = str(uuid.uuid4())
                request.state.request_id = request_id
                logger.warning(
                    f"Request ID missing in auth middleware, generated {request_id}"
                )

            # Check Authorization header
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                logger.warning(f"Request {request_id} missing Authorization header")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": "AUTH_REQUIRED",
                        "message": "Authorization header required",
                        "request_id": request_id
                    },
                    headers={"X-Request-ID": request_id}
                )

            # Check Bearer token format
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                logger.warning(f"Request {request_id} has invalid Authorization format")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": "INVALID_AUTH_FORMAT",
                        "message": "Authorization must be 'Bearer <token>'",
                        "request_id": request_id
                    },
                    headers={"X-Request-ID": request_id}
                )

            token = parts[1]

            # Validate token
            if token != self.api_key:
                logger.warning(f"Request {request_id} has invalid API key")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": "INVALID_API_KEY",
                        "message": "Invalid API key",
                        "request_id": request_id
                    },
                    headers={"X-Request-ID": request_id}
                )

        # Authentication passed or disabled
        return await call_next(request)


def get_request_id(request: Request) -> str:
    """
    Get the request ID from the request state.

    If missing (edge case), generates a new UUID and attaches it (v0.3.1).

    Args:
        request: FastAPI request object

    Returns:
        Request ID string (always a valid UUID)
    """
    request_id = getattr(request.state, 'request_id', None)
    if not request_id:
        # Defensive: generate UUID if missing (should not happen with middleware)
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        logger.warning(f"Request ID missing, generated {request_id}")
    return request_id
