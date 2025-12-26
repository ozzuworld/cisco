# CUCM Log Collector Backend (v0.2.0)

A Python backend service for discovering Cisco Unified Communications Manager (CUCM) cluster nodes and collecting logs via automated SSH sessions.

## Features

### v0.1 - Node Discovery
- 🔍 **Node Discovery**: Connect to CUCM Publisher and discover all cluster nodes
- 🔐 **Secure SSH**: AsyncSSH-based interactive shell sessions with robust timeout handling
- 📊 **REST API**: FastAPI-powered endpoints for integration with frontend applications
- 🧪 **Well-tested**: Comprehensive unit tests with sample CUCM output

### v0.2 - Log Collection (Current)
- 📁 **Profiles**: Pre-defined log collection profiles for common scenarios
- 🔄 **Job Management**: Create and track asynchronous log collection jobs
- 📝 **Transcripts**: Complete session transcripts for troubleshooting
- 📦 **Artifact Tracking**: Automatic discovery and cataloging of collected files
- ⚡ **Concurrency Control**: Configurable parallel execution per job
- 🎯 **Interactive Prompts**: Automatic response to CUCM CLI prompts

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env with your SFTP and CUCM settings

# 3. Run
uvicorn app.main:app --reload

# 4. Test
curl http://localhost:8000/profiles
```

See full documentation below for detailed setup and usage.

## Architecture

```
app/
├── main.py              # FastAPI app (v0.2)
├── config.py            # Configuration management
├── models.py            # Pydantic models
├── ssh_client.py        # AsyncSSH client
├── parsers.py           # CLI parsers
├── profiles.py          # Profile catalog
├── prompt_responder.py  # Interactive prompts
└── job_manager.py       # Job execution

tests/
├── test_parser.py
├── test_profiles.py
└── test_prompt_responder.py

profiles.yaml            # Profile definitions
```

## Installation & Configuration

See full README.md for detailed installation steps.

**Key Requirements:**
- Python 3.11+
- SFTP server (CUCM pushes logs here)
- CUCM OS Admin credentials

**SFTP Server Setup (Critical):**

CUCM **pushes** logs to an SFTP server. Configure in `.env`:

```bash
SFTP_HOST=your-sftp-server.com
SFTP_PORT=22
SFTP_USERNAME=cucm-collector
SFTP_PASSWORD=your-password
SFTP_REMOTE_BASE_DIR=/cucm-logs
```

Quick SFTP server for testing (Docker):
```bash
docker run -p 2222:22 -d \
  -e SFTP_USERS='cucm:password:1001' \
  -v $(pwd)/storage/received:/home/cucm/upload \
  atmoz/sftp
```

## API Reference

### Node Discovery (v0.1)

**POST /discover-nodes** - Discover cluster nodes

Request:
```json
{
  "publisher_host": "10.10.10.10",
  "port": 22,
  "username": "admin",
  "password": "your-password"
}
```

### Profiles (v0.2)

**GET /profiles** - List available profiles

Response includes built-in profiles:
- `basic_platform` - Syslog, install logs
- `callmanager_full` - All CM logs
- `emergency_debug` - All logs, last 30 min
- And more...

### Jobs (v0.2)

**POST /jobs** - Create log collection job

Request:
```json
{
  "publisher_host": "10.10.10.10",
  "port": 22,
  "username": "admin",
  "password": "your-password",
  "nodes": ["10.10.10.10", "10.10.10.11"],
  "profile": "basic_platform",
  "options": {
    "reltime_minutes": 60
  }
}
```

Response (202):
```json
{
  "job_id": "550e8400-...",
  "status": "queued",
  "created_at": "2025-12-26T10:00:00Z"
}
```

**GET /jobs/{job_id}** - Get job status

**GET /jobs/{job_id}/artifacts** - List collected files

**GET /jobs** - List recent jobs

## Usage Examples

### Example 1: Basic Log Collection

```bash
# 1. Discover nodes
curl -X POST http://localhost:8000/discover-nodes \
  -H "Content-Type: application/json" \
  -d '{"publisher_host": "10.10.10.10", "port": 22, "username": "admin", "password": "pass"}'

# 2. List profiles
curl http://localhost:8000/profiles

# 3. Create job
JOB_ID=$(curl -X POST http://localhost:8000/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "publisher_host": "10.10.10.10",
    "port": 22,
    "username": "admin",
    "password": "pass",
    "nodes": ["10.10.10.10"],
    "profile": "basic_platform"
  }' | jq -r '.job_id')

# 4. Monitor status
watch -n 5 "curl -s http://localhost:8000/jobs/$JOB_ID | jq '.status'"

# 5. Get artifacts
curl http://localhost:8000/jobs/$JOB_ID/artifacts | jq
```

### Example 2: Custom Time Window

Collect last 4 hours of CallManager logs:

```bash
curl -X POST http://localhost:8000/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "publisher_host": "10.10.10.10",
    "port": 22,
    "username": "admin",
    "password": "pass",
    "nodes": ["10.10.10.10", "10.10.10.11"],
    "profile": "callmanager_full",
    "options": {
      "reltime_minutes": 240
    }
  }'
```

## Profiles

Profiles defined in `profiles.yaml`:

| Profile | Description | Use Case |
|---------|-------------|----------|
| `basic_platform` | Syslog, install logs | Basic troubleshooting |
| `callmanager_full` | All CM trace logs | Call processing issues |
| `callmanager_sdl` | SDL logs only | Signaling issues |
| `tomcat_logs` | Tomcat logs | Web interface issues |
| `database_logs` | DB diagnostics | Database problems |
| `cups_logs` | CUPS/Presence | Presence issues |
| `emergency_debug` | All logs (30 min) | Emergency troubleshooting |
| `security_audit` | Audit logs (24h) | Security review |

### Custom Profiles

Edit `profiles.yaml`:

```yaml
profiles:
  - name: my_profile
    description: "Custom collection"
    paths:
      - "cm/trace/ccm"
      - "platform/log/syslog"
    reltime_minutes: 120
    compress: true
    recurs: true
    match: null
```

## How It Works

### Log Collection Flow

1. User creates job via `POST /jobs`
2. Job queued and executed in background
3. For each node:
   - SSH connect
   - Run `file get activelog` for each path
   - Auto-respond to SFTP prompts
   - CUCM pushes files to SFTP server
   - Capture transcript
4. Discover artifacts in SFTP directory
5. Update job status

### Interactive Prompt Handling

```
admin:file get activelog platform/log/syslog reltime 60 compress
SFTP host: <auto: sftp.example.com>
SFTP port: <auto: 22>
User: <auto: cucm-collector>
Password: <auto: ***>
Directory: <auto: /cucm-logs/job-id/node>
Transfer complete.
admin:
```

The `PromptResponder` detects and responds to these prompts automatically.

## Storage Structure

```
storage/
├── jobs/{job-id}.json          # Job metadata
├── transcripts/{job-id}/
│   └── {node}.log              # Session transcript
└── received/{job-id}/{node}/   # Collected artifacts
    └── *.tgz
```

## Testing

```bash
# Unit tests
pytest -v

# With coverage
pytest --cov=app

# Specific modules
pytest tests/test_profiles.py -v
pytest tests/test_prompt_responder.py -v
```

## Troubleshooting

### No Artifacts Collected

1. Check SFTP server is running and reachable from CUCM
2. Verify SFTP credentials in `.env`
3. Review transcript: `cat storage/transcripts/{job-id}/{node}.log`
4. Check for SFTP errors in transcript

### Job Timeout

- Increase `JOB_COMMAND_TIMEOUT_SEC` in `.env`
- Reduce `reltime_minutes` (less data)
- Check CUCM system load

### Network Errors

- Verify node reachable: `ping {node}`
- Check SSH: `ssh admin@{node}`
- Review firewall rules

## Configuration

Key environment variables:

```bash
# SFTP (where CUCM pushes logs)
SFTP_HOST=sftp.example.com
SFTP_PORT=22
SFTP_USERNAME=cucm-collector
SFTP_PASSWORD=secret
SFTP_REMOTE_BASE_DIR=/cucm-logs

# Storage
STORAGE_ROOT=./storage

# Job Settings
MAX_CONCURRENCY_PER_JOB=2
JOB_COMMAND_TIMEOUT_SEC=600
```

See `.env.example` for all options.

## Security

- ✅ Passwords never logged or persisted
- ✅ AsyncSSH logging reduced to WARNING
- ✅ SFTP credentials from environment only
- ⚠️ Use HTTPS in production
- ⚠️ Secure SFTP server access
- ⚠️ Protect `storage/` directory

## What's Next

- Web UI for job management
- Scheduled jobs
- Log parsing and analysis
- API authentication
- Multi-cluster support

---

**Version**: 0.2.0
**Full Documentation**: See README.md
**API Docs**: http://localhost:8000/docs
