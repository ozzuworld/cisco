# ==============================================================================
# CUCM Log Collector - Unified Application
# ==============================================================================
# This Dockerfile builds both frontend and backend into a single container
# The FastAPI backend serves the React frontend and handles all API requests
# OpenSSH sshd handles SFTP for CUCM file uploads (replaces asyncssh)
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
# Stage 2: Final Application (Python + FastAPI + Frontend + OpenSSH SFTP)
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

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
# - openssh-server: SFTP server for CUCM file uploads (replaces asyncssh)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY Backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY Backend/app/ ./app/
COPY Backend/profiles.yaml .
COPY Backend/scenarios.yaml .

# Copy SFTP server configuration and entrypoint
COPY Backend/sshd_config_sftp ./sshd_config_sftp
COPY Backend/entrypoint.sh ./entrypoint.sh
# Fix Windows CRLF line endings and make executable
RUN sed -i 's/\r$//' ./entrypoint.sh ./sshd_config_sftp && chmod +x ./entrypoint.sh

# Copy built frontend from stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create storage directories
# /app/storage and /app/storage/received MUST be root:root 755
# (ChrootDirectory requires every path component to be root-owned, not group/other writable)
# Subdirectories for app data can be more permissive since they're not in the chroot path
RUN mkdir -p /app/storage/received \
             /app/storage/jobs \
             /app/storage/transcripts \
             /app/storage/captures \
             /app/storage/sessions \
             /app/storage/environments \
             /app/storage/investigations \
    && chmod 755 /app/storage \
    && chmod 755 /app/storage/received

# Create SFTP/SCP user for CUCM/CUBE file uploads
# Home directory is storage/received - uploads land here
# Shell is /bin/sh for SCP compatibility (IOS-XE 'monitor capture export scp://...')
# SFTP works via Subsystem; SCP needs a real shell. Chroot provides security.
RUN useradd --home-dir /app/storage/received \
            --no-create-home \
            --shell /bin/sh \
            cucm-collector \
    && chown root:root /app/storage/received \
    && chmod 755 /app/storage/received

# Create sshd privilege separation directory
RUN mkdir -p /run/sshd

# Expose ports
# 8000 - HTTP (Frontend UI + API)
# 2222 - OpenSSH SFTP Server (for CUCM file uploads)
EXPOSE 8000 2222

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Entrypoint handles sshd setup + uvicorn startup
# Container runs as root so sshd can manage user authentication
# Security: sshd restricts the SFTP user via ForceCommand internal-sftp
CMD ["./entrypoint.sh"]
