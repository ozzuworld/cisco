# CUCM Log Collector - Docker Deployment Guide

## Overview

This application is packaged as a **single Docker container** that includes:
- ✅ **Frontend** - React UI built with Vite
- ✅ **Backend** - FastAPI REST API
- ✅ **SFTP Server** - Embedded SFTP for CUCM file uploads
- ✅ **No CORS Issues** - Frontend and backend served from same origin

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Build and start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

Access the application:
- **Web UI**: http://localhost:8000
- **API Docs**: http://localhost:8000/health
- **SFTP**: localhost:2222 (user: cucm, pass: cisco123)

### Option 2: Docker Build & Run

```bash
# Build the image
docker build -t cucm-log-collector:latest .

# Run the container
docker run -d \
  --name cucm-log-collector \
  -p 8000:8000 \
  -p 2222:2222 \
  -v $(pwd)/storage:/app/storage \
  -e SFTP_USERNAME=cucm \
  -e SFTP_PASSWORD=cisco123 \
  cucm-log-collector:latest

# View logs
docker logs -f cucm-log-collector

# Stop and remove
docker stop cucm-log-collector
docker rm cucm-log-collector
```

---

## Architecture

### Single Container Design

```
┌─────────────────────────────────────────┐
│   Docker Container (Port 8000)          │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  FastAPI Application                │ │
│  │  ┌──────────────┐  ┌──────────────┐│ │
│  │  │   Frontend   │  │   Backend    ││ │
│  │  │ React + Vite │  │   FastAPI    ││ │
│  │  │ (Static)     │  │   REST API   ││ │
│  │  └──────────────┘  └──────────────┘│ │
│  │                                     │ │
│  │  ┌──────────────────────────────┐  │ │
│  │  │   SFTP Server (Port 2222)    │  │ │
│  │  │   For CUCM file uploads      │  │ │
│  │  └──────────────────────────────┘  │ │
│  └────────────────────────────────────┘ │
│                                          │
│  Volume: /app/storage                    │
└─────────────────────────────────────────┘
```

### How It Works

1. **Frontend Build**: During Docker build, the React app is compiled to static files
2. **Static Serving**: FastAPI serves the built frontend from `/app/frontend/dist`
3. **API Routes**: All API calls go to the same server (no CORS!)
4. **SPA Routing**: Frontend routes (/, /dashboard, /jobs, etc.) serve `index.html`
5. **API Endpoints**: Backend routes (/jobs, /captures, etc.) return JSON

---

## Build Process

The `Dockerfile` uses a multi-stage build:

### Stage 1: Frontend Build (Node.js)

```dockerfile
FROM node:20-alpine AS frontend-builder
# Install npm dependencies
# Build React app with Vite
# Output: /app/frontend/dist/*
```

### Stage 2: Final Image (Python + FastAPI)

```dockerfile
FROM python:3.11-slim
# Install Python dependencies
# Copy backend code
# Copy built frontend from stage 1
# Configure and run
```

**Benefits**:
- ✅ Single image - no separate frontend container
- ✅ No nginx needed - FastAPI serves everything
- ✅ No CORS issues - same origin
- ✅ Smaller final image - Node.js not included
- ✅ Easy deployment - one docker-compose command

---

## Configuration

### Environment Variables

Configure via `docker-compose.yml` or `-e` flags:

#### Application Settings

```yaml
ARTIFACTS_DIR: /app/storage/received       # Where to store downloaded files
JOBS_DIR: /app/storage/jobs                # Job metadata storage
TRANSCRIPT_DIR: /app/storage/transcripts   # Command output logs
```

#### SFTP Server

```yaml
SFTP_SERVER_ENABLED: true                  # Enable embedded SFTP
SFTP_SERVER_HOST: 0.0.0.0                  # Listen on all interfaces
SFTP_SERVER_PORT: 2222                     # SFTP port
SFTP_ROOT_PATH: /app/storage/received      # SFTP root directory
SFTP_USERNAME: cucm                        # SFTP username
SFTP_PASSWORD: cisco123                    # SFTP password (CHANGE THIS!)
```

#### Security

```yaml
API_KEY: your-secret-key-here              # Optional API key auth
CORS_ALLOWED_ORIGINS: .*                   # CORS regex (default: allow all)
```

#### Logging

```yaml
LOG_LEVEL: INFO                            # DEBUG, INFO, WARNING, ERROR
```

---

## Volume Mounts

### Storage Directory Structure

```
storage/
├── received/          # SFTP uploads and downloaded artifacts
├── jobs/              # Job metadata and status
├── transcripts/       # Command execution logs
├── captures/          # Packet capture files (.cap)
└── sessions/          # Capture session bundles (.zip)
```

### Persistence

Mount `./storage` to persist data:

```bash
-v $(pwd)/storage:/app/storage
```

Or use a named Docker volume:

```yaml
volumes:
  - cucm-storage:/app/storage

volumes:
  cucm-storage:
```

---

## Networking

### Ports

| Port | Purpose | Protocol |
|---|---|---|
| 8000 | Web UI + API | HTTP |
| 2222 | SFTP Server | SSH/SFTP |

### Port Mapping Examples

**Default** (same ports):
```bash
-p 8000:8000 -p 2222:2222
```

**Custom ports**:
```bash
-p 80:8000 -p 2222:2222        # Web on port 80
-p 8080:8000 -p 2200:2222      # Custom ports
```

**With reverse proxy** (nginx, Traefik):
```bash
-p 127.0.0.1:8000:8000         # Only localhost
```

---

## Security Recommendations

### Production Deployment

1. **Change Default Credentials**

```yaml
environment:
  - SFTP_USERNAME=secure_user
  - SFTP_PASSWORD=very_secure_password_here  # Use secrets!
```

2. **Enable API Key Authentication**

```yaml
environment:
  - API_KEY=your-random-api-key-here
```

Then include in requests:
```bash
curl -H "Authorization: your-random-api-key-here" http://localhost:8000/jobs
```

3. **Restrict CORS**

```yaml
environment:
  - CORS_ALLOWED_ORIGINS=https://your-domain.com
```

4. **Use HTTPS**

Deploy behind nginx or Traefik with SSL:

```nginx
server {
    listen 443 ssl;
    server_name cucm-collector.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

5. **Firewall Rules**

Only expose necessary ports:
- Port 8000: From your network
- Port 2222: From CUCM servers only

---

## Monitoring

### Health Checks

```bash
# Container health
docker ps

# Application health
curl http://localhost:8000/health

# Response:
{
  "status": "healthy",
  "sftp_server": {
    "enabled": true,
    "running": true,
    "port": 2222
  }
}
```

### Logs

```bash
# View all logs
docker logs cucm-log-collector

# Follow logs
docker logs -f cucm-log-collector

# Last 100 lines
docker logs --tail 100 cucm-log-collector

# With timestamps
docker logs -t cucm-log-collector
```

### Metrics

Check container stats:
```bash
docker stats cucm-log-collector
```

---

## Upgrading

### Pull Latest Code

```bash
# Pull updates from Git
git pull origin main

# Rebuild image
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Preserve Data

Your data is safe in the `storage/` volume. Rebuilding the container doesn't delete it.

---

## Troubleshooting

### Issue: Frontend not loading

**Symptoms**: Blank page or 404 errors

**Solution**:
```bash
# Check if frontend was built
docker exec cucm-log-collector ls -la /app/frontend/dist

# Rebuild with no cache
docker-compose build --no-cache
docker-compose up -d
```

### Issue: API 404 errors

**Symptoms**: `/capture-sessions` returns 404

**Solution**:
```bash
# Check logs for startup errors
docker logs cucm-log-collector | grep ERROR

# Restart container
docker-compose restart
```

### Issue: SFTP connection refused

**Symptoms**: CUCM can't upload files

**Check**:
```bash
# Verify SFTP is running
curl http://localhost:8000/health

# Test SFTP connection
sftp -P 2222 cucm@localhost

# Check firewall
sudo ufw status
sudo ufw allow 2222/tcp
```

### Issue: Out of disk space

**Symptoms**: Container crashes, errors in logs

**Solution**:
```bash
# Check disk usage
df -h
du -sh storage/

# Clean old files
find storage/received -type f -mtime +30 -delete

# Increase volume size or move to larger disk
```

### Issue: High memory usage

**Solution**: Add memory limits to `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 2G
```

---

## Development

### Run Without Docker

```bash
# Backend
cd Backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frotend
npm install
npm run dev  # Runs on port 5173
```

### Build Frontend Manually

```bash
cd frotend
npm run build
# Output: dist/
```

### Test Production Build Locally

```bash
cd Backend
# Copy built frontend
cp -r ../frotend/dist ../frontend/dist
# Run FastAPI
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Performance Tuning

### Increase Workers (for high load)

Edit `Dockerfile` CMD:

```dockerfile
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Use Gunicorn (production)

```dockerfile
CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
```

Update requirements.txt:
```
gunicorn==21.2.0
```

---

## Summary

### ✅ Benefits of This Setup

- **Single Container** - Easy to deploy and manage
- **No CORS Issues** - Frontend and backend same origin
- **Production Ready** - Multi-stage build, health checks, security
- **Self-Contained** - No external dependencies (nginx, etc.)
- **Easy Updates** - Just rebuild and restart

### 📦 Deployment Checklist

- [ ] Clone repository
- [ ] Create `storage/` directory
- [ ] Customize `docker-compose.yml` (passwords, ports)
- [ ] Run `docker-compose up -d`
- [ ] Access http://localhost:8000
- [ ] Configure firewall rules
- [ ] Set up SSL (optional but recommended)
- [ ] Configure backups for `storage/` volume

### 🚀 Quick Commands

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Rebuild
docker-compose build --no-cache

# View logs
docker-compose logs -f

# Restart
docker-compose restart

# Update
git pull && docker-compose up -d --build
```

---

**You now have a fully unified CUCM Log Collector application running in a single Docker container!** 🎉
