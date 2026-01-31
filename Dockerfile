# ==============================================================================
# CUCM Log Collector - Unified Application
# ==============================================================================
# This Dockerfile builds both frontend and backend into a single container
# The FastAPI backend serves the React frontend and handles all API requests
#
# Build: docker build -t cucm-log-collector:latest .
# Run:   docker run -p 8000:8000 -p 2222:2222 -v ./storage:/app/storage cucm-log-collector
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Frontend (React + Vite)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package.json frontend/package-lock.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source code
COPY frontend/ ./

# Set build-time environment variables
# API calls will use relative paths (same origin) - no CORS issues
ENV VITE_API_BASE_URL=""

# Build the frontend for production
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Final Application (Python + FastAPI + Frontend)
# ------------------------------------------------------------------------------
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
# - gcc: Required for Python packages with C extensions
# - libffi-dev: Required for cryptography package
# - curl: For healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY Backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY Backend/app/ ./app/
COPY Backend/profiles.yaml .

# Copy built frontend from stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create storage directories with correct permissions
RUN mkdir -p /app/storage/received \
             /app/storage/jobs \
             /app/storage/transcripts \
             /app/storage/captures \
             /app/storage/sessions \
    && chmod -R 775 /app/storage

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
# 8000 - HTTP (Frontend UI + API)
# 2222 - Embedded SFTP Server (for CUCM file uploads)
EXPOSE 8000 2222

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command - run FastAPI with uvicorn
# The application serves both frontend (/) and API (/api/*)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
