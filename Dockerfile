# CUCM Log Collector - Docker Image
# Single container with FastAPI + Embedded SFTP Server
#
# Build: docker build -t cucm-log-collector .
# Run:   docker run -p 8000:8000 -p 2222:2222 -v ./storage:/app/storage cucm-log-collector

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
# - gcc: Required for some Python packages with C extensions
# - libffi-dev: Required for cryptography package
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY profiles.yaml .

# Create storage directories with correct permissions
RUN mkdir -p /app/storage/received \
             /app/storage/jobs \
             /app/storage/transcripts \
    && chmod -R 775 /app/storage

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
# 8000 - FastAPI HTTP API
# 2222 - Embedded SFTP Server (for CUCM file uploads)
EXPOSE 8000 2222

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command - run with uvicorn
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
