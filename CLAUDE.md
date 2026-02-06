# CUCM Log Collector - Claude Session Memory

## What This Project Is

Web-based diagnostic platform for Cisco Unified Communications Manager (CUCM) clusters.
Single Docker container: React frontend + FastAPI backend + embedded OpenSSH SFTP server.

**Core capabilities:** Log collection, packet capture, trace level management, device health checks, investigation orchestration across CUCM/CUBE/CSR1000v/Expressway devices.

**Repo:** github.com/ozzuworld/cisco
**Owner:** hadmin

---

## Architecture

```
Single Docker Container (ports 8000 HTTP, 2222 SFTP)
├── React Frontend (Vite build, served as static by FastAPI)
├── FastAPI Backend (Python 3.11, asyncio/asyncssh)
├── OpenSSH SFTP Server (chroot'd, SCP support for IOS-XE)
└── /app/storage/ (persistent volume)
    ├── received/    SFTP uploads (root:root 755 for chroot)
    ├── jobs/        Job metadata JSON
    ├── transcripts/ SSH session logs
    ├── captures/    Packet capture .cap files
    ├── sessions/    Capture session ZIPs
    ├── environments/ Device inventory JSON
    └── investigations/ Investigation bundles
```

**Key design decisions:**
- CUCM pushes files TO the embedded SFTP server via `file get activelog` (push-only, no pull)
- IOS-XE/CUBE devices use SCP (requires chroot with binaries copied in)
- Expressway uses REST API (HTTPS)
- All storage is JSON file-based (no database)
- Atomic writes: write .tmp, fsync, rename
- Credentials never persisted to disk (in-memory only, 30min TTL)

---

## Tech Stack

**Backend:** Python 3.11, FastAPI, asyncssh, pydantic, uvicorn
**Frontend:** React 18, TypeScript, Vite, MUI (Material-UI), TanStack Query, React Router, Axios, React Hook Form, Zod
**Infra:** Docker (multi-stage build), OpenSSH sshd, docker-compose

---

## File Layout

```
Backend/
├── app/
│   ├── main.py                  # FastAPI app, 60+ REST endpoints
│   ├── config.py                # Pydantic settings (env vars)
│   ├── models.py                # 100+ Pydantic models
│   ├── job_manager.py           # CUCM log collection orchestration
│   ├── capture_service.py       # Packet captures (CUCM/CUBE/CSR/Expressway)
│   ├── capture_session_service.py # Multi-device capture sessions
│   ├── investigation_service.py # Multi-phase investigation orchestration
│   ├── device_health_service.py # Health checks (CUCM/CUBE/Expressway)
│   ├── ssh_client.py            # AsyncSSH interactive shell for CUCM
│   ├── ssh_session_manager.py   # Persistent SSH connection pooling (15min TTL)
│   ├── environment_service.py   # Device inventory CRUD (JSON files)
│   ├── scenario_service.py      # Investigation scenario templates
│   ├── log_service.py           # Log collection lifecycle
│   ├── expressway_client.py     # Expressway REST API client
│   ├── health_service.py        # CUCM cluster health checks
│   ├── profiles.py              # Log collection profile catalog
│   ├── artifact_manager.py      # File discovery, ZIP, downloads
│   ├── middleware.py            # Request ID tracking, API key auth
│   ├── parsers.py               # CLI output parsing
│   └── network_utils.py         # IP address detection
├── tests/
│   └── test_ssh_session_manager.py
├── profiles.yaml                # 11 log collection profiles
├── scenarios.yaml               # 5 investigation scenario templates
├── sshd_config_sftp             # OpenSSH config for embedded SFTP
└── entrypoint.sh                # Container startup (SFTP setup + uvicorn)

frontend/src/
├── App.tsx                      # Routes + providers
├── layouts/MainLayout.tsx       # Sidebar nav (3 groups)
├── context/
│   ├── ThemeContext.tsx          # Dark/light mode
│   └── CredentialContext.tsx     # In-memory credential store
├── pages/
│   ├── Landing.tsx              # Home page
│   ├── Dashboard.tsx            # System status
│   ├── Environments.tsx         # Device inventory management
│   ├── InvestigationWizard.tsx  # 5-step investigation setup wizard
│   ├── InvestigationDashboard.tsx # Live investigation monitor
│   ├── Investigations.tsx       # Investigation list
│   ├── CaptureSession.tsx       # Multi-device packet capture UI
│   ├── LogCollection.tsx        # Log collection + CUBE debug
│   ├── TraceLevel.tsx           # CUCM trace + CUBE debug management
│   ├── Health.tsx               # Cluster/device health
│   ├── Jobs.tsx / JobDetails.tsx / NewJob.tsx # CUCM log jobs
│   ├── Profiles.tsx             # Profile catalog
│   └── Settings.tsx             # App settings
├── services/                    # API client layer (one per feature)
├── hooks/                       # React Query hooks (one per feature)
└── types/                       # TypeScript types (one per feature)

Dockerfile                       # Multi-stage: node:20-alpine → python:3.11-slim
docker-compose.yml               # Single service, ports 8000+22(→2222)
```

---

## API Endpoints (60+ total)

**Cluster:** POST /discover-nodes, POST /cluster/health
**Device Health:** POST /device/health
**SSH Sessions:** POST/GET/DELETE /ssh-sessions, GET /ssh-sessions/{id}
**Trace Levels:** POST /trace-levels, POST /trace-levels/set
**Profiles:** GET /profiles
**Jobs:** POST/GET /jobs, GET/POST /jobs/{id} (status/cancel/retry/download/artifacts)
**Captures:** POST/GET /captures, GET/POST/DELETE /captures/{id} (status/stop/download)
**Capture Sessions:** POST/GET /capture-sessions, GET/POST/DELETE /capture-sessions/{id}
**Log Collections:** POST/GET /log-collections, GET/POST/DELETE /log-collections/{id}
**CUBE Debug:** POST /cube/debug-status, /cube/debug/enable, /cube/debug/clear
**Environments:** POST/GET /environments, GET/PUT/DELETE /environments/{id}, POST devices, POST discover
**Scenarios:** GET /scenarios
**Investigations:** POST/GET /investigations, GET/DELETE /investigations/{id}, POST prepare/ready/record/collect/cancel, GET download

---

## Investigation Phases

1. **PREPARE** - Set trace levels on CUCM nodes, run health checks
2. **RECORD** - Start packet captures on all devices, wait for duration
3. **COLLECT** - Stop captures, collect logs, reset traces, create ZIP bundle

Operations: trace, health, capture, logs (each optional per investigation)
5 scenario templates: call_quality, call_routing, registration, b2b_federation, custom

---

## Docker / Deployment

```bash
docker-compose up -d              # Start
docker-compose logs -f            # Logs
curl http://localhost:8000/health # Health check
sftp -P 22 cucm-collector@host   # Test SFTP (port 22 on host maps to 2222 in container)
```

**Env vars:** SFTP_SERVER_ENABLED, SFTP_USERNAME, SFTP_PASSWORD, API_KEY (optional), CORS_ALLOWED_ORIGINS, LOG_LEVEL
**Storage:** ./storage volume mounted to /app/storage (persistent)

---

## Branch: claude/fix-api-key-auth-FLgUJ

### Committed (14 commits on top of main):
- Fixed SFTP reliability in Docker (SSH key exchange, ChrootDirectory perms, DNS timeouts)
- Switched to CUCM push-only model (removed pull/SCP fallback)
- Fixed CORS/localhost — frontend uses same-origin/relative URLs
- Fixed download button always greyed out (added download_available field)
- Added then reduced SFTP diagnostic logging (DEBUG3 → INFO)

### Uncommitted (not yet committed):
All the major new features are staged/untracked:
- **Environments** - Device inventory CRUD (backend service + frontend page)
- **Investigations** - Multi-phase orchestration engine + wizard + dashboard
- **Device Health** - CUCM/CUBE/Expressway health checks (SSH + REST)
- **SSH Session Manager** - Connection pooling with 15min TTL
- **Scenario Templates** - 5 pre-built investigation configs
- **Trace Level Page** - Full CUCM trace + CUBE debug UI (1,504 lines)
- **Credential Context** - In-memory credential store (frontend)
- **CUBE Debug** - Enable/clear IOS-XE debugs via API
- **Many endpoint additions** in main.py and models.py

### Files deleted from main:
- Backend/Dockerfile (consolidated to root Dockerfile)
- Backend/docker-compose.yml (consolidated to root docker-compose.yml)

---

## Known Issues / Watch Out For

1. **ChrootDirectory ownership** - /app/storage MUST be root:root 755 or sshd refuses to start
2. **SCP chroot** - IOS-XE devices need scp binary + libs copied into chroot (entrypoint.sh handles this)
3. **SFTP port mapping** - docker-compose maps host:22 → container:2222 (host sshd was moved to port 22222)
4. **CORS** - Currently set to `.*` (allow all) — not production-ready
5. **API Key auth** - Implemented but disabled by default
6. **No database** - Everything is JSON files with atomic writes
7. **Credential TTL** - 30 minutes in-memory, then cleared
8. **SSH session TTL** - 15 minutes, background cleanup every 60s
9. **Max 20 nodes per job**, max 5 parallel SSH connections
10. **Expressway licensing endpoint** - Tries multiple API paths as fallback

---

## Development Commands

```bash
# Backend (without Docker)
cd Backend && pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (dev server on :5173)
cd frontend && npm install && npm run dev

# Frontend (production build)
cd frontend && npm run build

# Run tests
cd Backend && pytest -v

# Docker
docker-compose up -d --build
docker-compose logs -f
```

---

## Device Type Reference

| Device | Protocol | Default Port | Default Interface | Capture Method |
|--------|----------|-------------|-------------------|----------------|
| CUCM | SSH | 22 | eth0 | tcpdump via SSH |
| CUBE | SSH | 22 | GigabitEthernet1 | IOS-XE EPC |
| CSR1000v | SSH | 22 | GigabitEthernet1 | IOS-XE EPC |
| Expressway | HTTPS | 443 | eth0 | REST API |

---

## Log Collection Profiles (profiles.yaml)

basic_platform, callmanager_full, callmanager_sdl, tomcat_logs, database_logs, cups_logs, emergency_debug, security_audit, cti_logs, oamp_logs, oamp_platform

---

## What To Work On Next

The uncommitted features (investigations, environments, device health, SSH sessions, scenarios, trace level page, CUBE debug, credential context) need to be committed and tested. The branch has 14 SFTP/infra fix commits but none of the new feature work is committed yet.
