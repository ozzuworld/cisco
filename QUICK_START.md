# CUCM Log Collector - Quick Start Guide

## 🚀 Deploy in 30 Seconds

```bash
# Clone the repository
git clone https://github.com/ozzuworld/cisco.git
cd cisco

# Start the application
docker-compose up -d

# Done! Access the UI
open http://localhost:8000
```

That's it! The application is now running.

---

## 📦 What Just Happened?

Docker built and started a **single container** with:
- ✅ React Frontend (served from FastAPI)
- ✅ FastAPI Backend (REST API)
- ✅ SFTP Server (for CUCM uploads)
- ✅ All storage and configuration

---

## 🌐 Access Points

| Service | URL | Credentials |
|---|---|---|
| **Web UI** | http://localhost:8000 | None (open access) |
| **API Health** | http://localhost:8000/health | None |
| **SFTP Server** | sftp://localhost:2222 | cucm / cisco123 |

---

## 🛠️ Common Commands

### View Logs
```bash
docker-compose logs -f
```

### Stop Application
```bash
docker-compose down
```

### Restart Application
```bash
docker-compose restart
```

### Update to Latest
```bash
git pull
docker-compose up -d --build
```

### Check Status
```bash
docker-compose ps
```

---

## ⚙️ Quick Configuration

Edit `docker-compose.yml` to customize:

### Change SFTP Credentials
```yaml
environment:
  - SFTP_USERNAME=myuser
  - SFTP_PASSWORD=mypassword
```

### Change Web Port
```yaml
ports:
  - "80:8000"      # Access on port 80
  - "2222:2222"
```

### Enable API Key Protection
```yaml
environment:
  - API_KEY=your-secret-key-here
```

Then restart:
```bash
docker-compose down && docker-compose up -d
```

---

## 📁 Data Storage

All data is stored in `./storage/`:

```
storage/
├── received/     # Downloaded logs and SFTP uploads
├── jobs/         # Job metadata
├── transcripts/  # Command outputs
├── captures/     # Packet captures (.cap files)
└── sessions/     # Capture session bundles (.zip)
```

**Backup this directory** to preserve your data.

---

## 🔒 Production Checklist

Before deploying to production:

- [ ] Change SFTP password in `docker-compose.yml`
- [ ] Set `API_KEY` for API authentication
- [ ] Restrict `CORS_ALLOWED_ORIGINS` to your domain
- [ ] Use HTTPS (deploy behind nginx/Traefik)
- [ ] Configure firewall rules
- [ ] Set up backups for `./storage/`
- [ ] Review resource limits in `docker-compose.yml`

---

## 🐛 Troubleshooting

### UI doesn't load
```bash
docker-compose logs app | grep ERROR
docker-compose restart
```

### API returns 404
```bash
# Check if backend started correctly
curl http://localhost:8000/health
```

### SFTP connection refused
```bash
# Verify SFTP is running
docker exec cucm-log-collector netstat -tlnp | grep 2222

# Test connection
sftp -P 2222 cucm@localhost
```

### Out of memory
```bash
# Check usage
docker stats cucm-log-collector

# Increase limit in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 4G
```

---

## 📚 More Info

- **Full Deployment Guide**: See [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
- **API Implementation**: See [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
- **API Audit**: See [FRONTEND_BACKEND_AUDIT_REPORT.md](FRONTEND_BACKEND_AUDIT_REPORT.md)

---

## ✨ Features

### Voice Quality Capture Sessions ⭐ NEW!
- Multi-device packet captures
- Orchestrate captures across CUCM, CUBE, CSR, Expressway
- Download all captures as ZIP bundle
- Real-time progress tracking

### CUCM Log Collection
- Discover cluster nodes
- Collect logs from multiple nodes
- Support for time ranges and profiles
- Download logs as ZIP

### CUBE/Expressway Logs
- VoIP trace collection
- Debug log capture
- Diagnostic logging

### Health Monitoring
- Cluster health checks
- Node status monitoring
- Real-time dashboards

### Trace Level Management
- Set trace levels on CUCM
- Service-specific configuration
- Multi-node support

---

## 🎯 Quick Usage Example

### 1. Access the Web UI
```
http://localhost:8000
```

### 2. Create a Capture Session
1. Click hamburger menu → **Captures**
2. Click **New Capture Session**
3. Add devices (CUCM, CUBE, etc.)
4. Set duration (60 seconds)
5. Click **Start Session**
6. Monitor real-time progress
7. Download ZIP bundle when complete

### 3. Collect CUCM Logs
1. Click hamburger menu → **Jobs**
2. Click **New Job**
3. Enter CUCM publisher IP and credentials
4. Discover cluster nodes
5. Select nodes and profile
6. Create job
7. Monitor progress
8. Download artifacts

---

## 💡 Pro Tips

### 1. Use Environment File

Create `.env` file:
```env
SFTP_USERNAME=admin
SFTP_PASSWORD=SecurePassword123!
API_KEY=very-secret-api-key
```

Reference in `docker-compose.yml`:
```yaml
env_file:
  - .env
```

### 2. Deploy Behind Nginx

```nginx
server {
    listen 443 ssl;
    server_name cucm-collector.example.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Auto-Restart on Failure

In `docker-compose.yml`:
```yaml
restart: unless-stopped
```

### 4. Schedule Backups

```bash
# Add to crontab
0 2 * * * tar -czf /backup/cucm-storage-$(date +\%Y\%m\%d).tar.gz /path/to/storage/
```

---

## 🤝 Support

If you encounter issues:

1. Check logs: `docker-compose logs -f`
2. Verify health: `curl http://localhost:8000/health`
3. Review [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
4. Check GitHub issues

---

**That's all you need to get started!** The application is designed to be simple to deploy and use. 🎉
