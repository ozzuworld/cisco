# CUCM Log Collector Backend (MVP v0.1)

A Python backend service for discovering and managing Cisco Unified Communications Manager (CUCM) cluster nodes via SSH.

## Features (MVP v0.1)

- 🔍 **Node Discovery**: Connect to CUCM Publisher and discover all cluster nodes
- 🔐 **Secure SSH**: AsyncSSH-based interactive shell sessions with robust timeout handling
- 📊 **REST API**: FastAPI-powered endpoints for integration with frontend applications
- 🧪 **Well-tested**: Comprehensive unit tests with sample CUCM output
- 🚀 **Production-ready**: Proper error handling, logging, and type safety

## Architecture

```
app/
├── main.py          # FastAPI application with /discover-nodes endpoint
├── ssh_client.py    # AsyncSSH interactive shell client for CUCM CLI
├── parsers.py       # Parser for 'show network cluster' command output
└── models.py        # Pydantic request/response models

tests/
└── test_parser.py   # Unit tests for parser logic
```

## Requirements

- Python 3.11 or higher
- CUCM Publisher accessible via SSH (TCP port 22)
- OS Admin credentials for CUCM

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd cisco
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Service

### Development Mode

```bash
# Run with auto-reload enabled
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or use the built-in runner:

```bash
python -m app.main
```

### Production Mode

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

## Running Tests

### Unit Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=app tests/
```

### Test Parser Only

```bash
pytest tests/test_parser.py -v
```

## API Endpoints

### Health Check

```bash
GET /health
```

Response:
```json
{
  "status": "healthy"
}
```

### Discover Nodes

```bash
POST /discover-nodes
```

**Request Body:**

```json
{
  "publisher_host": "10.10.10.10",
  "port": 22,
  "username": "admin",
  "password": "your-password",
  "connect_timeout_sec": 30,
  "command_timeout_sec": 120
}
```

**Success Response (200):**

```json
{
  "nodes": [
    {
      "ip": "104.156.46.16",
      "fqdn": "den01wx051ccm01.wx051.webexcce.com",
      "host": "den01wx051ccm01",
      "role": "Publisher",
      "product": "callmanager",
      "dbrole": "DBPub",
      "raw": "104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated"
    },
    {
      "ip": "104.156.46.17",
      "fqdn": "den02wx051ccm01.wx051.webexcce.com",
      "host": "den02wx051ccm01",
      "role": "Subscriber",
      "product": "callmanager",
      "dbrole": "DBSub",
      "raw": "104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Fri Mar 28 06:07:43 2025"
    }
  ],
  "raw_output": null,
  "raw_output_truncated": false
}
```

**No Nodes Found (200 with empty list):**

If parsing returns zero nodes, the response includes raw output for debugging:

```json
{
  "nodes": [],
  "raw_output": "admin:show network cluster\n[command output here]",
  "raw_output_truncated": false
}
```

**Error Responses:**

- **401 Unauthorized**: Authentication failed
  ```json
  {
    "error": "AUTH_FAILED",
    "message": "Authentication failed. Please check username and password."
  }
  ```

- **502 Bad Gateway**: Network error (host unreachable, connection refused)
  ```json
  {
    "error": "NETWORK_ERROR",
    "message": "Cannot connect to 10.10.10.10:22. Please check host is reachable and SSH is available."
  }
  ```

- **504 Gateway Timeout**: Connection or command timeout
  ```json
  {
    "error": "CONNECT_TIMEOUT",
    "message": "Connection timeout to 10.10.10.10:22"
  }
  ```

- **500 Internal Server Error**: Unexpected error
  ```json
  {
    "error": "INTERNAL_ERROR",
    "message": "An unexpected error occurred during node discovery"
  }
  ```

## Manual Testing with Real CUCM

### Prerequisites

1. CUCM Publisher reachable on TCP port 22
2. Valid OS Admin CLI credentials
3. Service running locally (see "Running the Service")

### Test Steps

#### 1. Test with curl

```bash
curl -X POST http://localhost:8000/discover-nodes \
  -H "Content-Type: application/json" \
  -d '{
    "publisher_host": "your-cucm-ip",
    "port": 22,
    "username": "admin",
    "password": "your-password",
    "connect_timeout_sec": 30,
    "command_timeout_sec": 120
  }'
```

#### 2. Test with Python requests

```python
import requests
import json

response = requests.post(
    "http://localhost:8000/discover-nodes",
    json={
        "publisher_host": "your-cucm-ip",
        "port": 22,
        "username": "admin",
        "password": "your-password",
        "connect_timeout_sec": 30,
        "command_timeout_sec": 120
    }
)

print(f"Status: {response.status_code}")
print(json.dumps(response.json(), indent=2))
```

#### 3. Test with httpie

```bash
http POST http://localhost:8000/discover-nodes \
  publisher_host="your-cucm-ip" \
  port:=22 \
  username="admin" \
  password="your-password" \
  connect_timeout_sec:=30 \
  command_timeout_sec:=120
```

### Expected Results

✅ **Successful Discovery:**
- HTTP 200 response
- `nodes` array contains all cluster nodes (Publisher + Subscribers)
- Each node has: ip, fqdn, host, role, product, dbrole

❌ **Common Issues:**

| Issue | Likely Cause | Status Code |
|-------|-------------|-------------|
| Authentication failure | Wrong credentials | 401 |
| Connection timeout | CUCM unreachable, firewall blocking | 504 |
| Connection refused | SSH not running, wrong port | 502 |
| Command timeout | CLI hung or very slow response | 504 |
| No nodes parsed | Unexpected output format | 200 (with raw_output) |

## Debug Mode

If nodes are not being parsed correctly, check the logs:

```bash
# The service logs command execution
# Look for lines like:
# INFO - Discovered X nodes
# WARNING - No nodes parsed from output. Including raw output in response.
```

When `nodes` is empty, the response automatically includes `raw_output` (truncated to 40KB) to help diagnose parsing issues.

## Security Notes

⚠️ **Important Security Considerations:**

1. **Credentials**: Never log passwords. The service is designed to NOT log the password parameter.
2. **Known Hosts**: Currently set to `known_hosts=None` for lab environments. In production, implement proper host key verification.
3. **HTTPS**: Use HTTPS/TLS when deploying to production.
4. **Secrets Management**: Use environment variables or secret management systems for credentials.

## What's NOT in MVP v0.1

This MVP focuses on node discovery only. Future versions will include:

- ❌ Log file collection (`file get` commands)
- ❌ Job scheduling and management
- ❌ Collection profiles/templates
- ❌ Persistent storage (database)
- ❌ Authentication/authorization for API
- ❌ Multi-cluster management

## CUCM CLI Details

### Interactive Shell Requirement

CUCM OS Admin CLI is **prompt-driven** and may hang with `exec_command()`. This service uses:
- ✅ Interactive shell sessions (`open_session()`)
- ✅ PTY (pseudo-terminal) allocation
- ✅ Explicit prompt detection (`admin:`)
- ✅ Robust timeout handling

### Command Output Format

The `show network cluster` command returns:

```
admin:show network cluster
[IP] [FQDN] [HOST] [ROLE] [PRODUCT] [DBROLE] [additional info...]
[IP] [FQDN] [HOST] [ROLE] [PRODUCT] [DBROLE] [additional info...]
...

Server Table (processnode) Entries
----------------------------------
[additional sections...]
```

The parser:
- Parses lines before "Server Table" section
- Extracts: IP, FQDN, hostname, role (Publisher/Subscriber), product, DB role
- Deduplicates by IP address
- Validates IP format and role values

## Troubleshooting

### "Connection timeout" errors

- Verify CUCM is reachable: `ping <cucm-ip>`
- Check SSH port: `telnet <cucm-ip> 22` or `nc -zv <cucm-ip> 22`
- Increase `connect_timeout_sec` in request

### "Authentication failed" errors

- Verify OS Admin username/password
- Try SSH manually: `ssh admin@<cucm-ip>`
- Check account is not locked

### "Command timeout" errors

- CUCM CLI may be slow on large clusters
- Increase `command_timeout_sec` in request
- Check CUCM system load

### No nodes parsed (empty array)

- Check `raw_output` in response
- Verify CUCM version compatibility
- Check if output format has changed
- Review parser logic in `app/parsers.py`

## Development

### Project Structure

```
cisco/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app & endpoints
│   ├── models.py        # Pydantic models
│   ├── parsers.py       # Output parsers
│   └── ssh_client.py    # AsyncSSH client
├── tests/
│   ├── __init__.py
│   └── test_parser.py   # Parser unit tests
├── requirements.txt
└── README.md
```

### Adding New Features

1. Create feature branch
2. Add tests first (TDD)
3. Implement feature
4. Update documentation
5. Submit PR

## License

[Your License Here]

## Support

For issues and questions:
- Open an issue on GitHub
- Check CUCM documentation
- Review application logs

---

**Version**: 0.1.0
**Last Updated**: 2025-12-26
