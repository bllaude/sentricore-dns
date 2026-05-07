# Sentricore DNS Proxy

A DNS proxy server that blocks malicious domains and logs all queries.

## Features

- DNS proxy on port 5300
- Domain blocking using blocklists
- SQLite database logging
- Web dashboard for monitoring

## Installation

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

The runners automatically use the virtual environment's Python, so no need to activate it manually.

1. Run the DNS proxy:
   ```bash
   python run_proxy.py
   ```

2. In another terminal, run the web dashboard:
   ```bash
   python run_web.py
   ```

3. Open http://127.0.0.1:5000 in your browser to view the dashboard.

## Raspberry Pi Deployment

Deploy Sentricore DNS Proxy as a permanent systemd service on Raspberry Pi.

### Quick Installation

1. Clone or download the repository to your Raspberry Pi
2. Run the installation script with sudo:

```bash
sudo bash install.sh
```

The script will:
- Install system dependencies (python3, python3-venv, git)
- Create a `sentricore` system user
- Set up Python virtual environment
- Install Python dependencies
- Create systemd services for auto-start on boot
- Start the DNS proxy and web dashboard

### Service Management

After installation, manage services with systemctl:

```bash
# View service status
sudo systemctl status sentricore-dns-proxy.service
sudo systemctl status sentricore-dns-web.service

# Start/stop/restart
sudo systemctl start sentricore-dns-proxy.service
sudo systemctl stop sentricore-dns-proxy.service
sudo systemctl restart sentricore-dns-proxy.service

# View logs
sudo journalctl -u sentricore-dns-proxy.service -f
sudo journalctl -u sentricore-dns-web.service -f

# Disable auto-start
sudo systemctl disable sentricore-dns-proxy.service
sudo systemctl disable sentricore-dns-web.service
```

### Network Configuration

Once running on Raspberry Pi:
- **DNS Proxy**: Listens on port 5300 (UDP)
- **Web Dashboard**: Accessible at `http://<pi-ip>:5000`
- **Health Check**: `curl http://<pi-ip>:5000/healthz`

To use the DNS proxy from other devices, point their DNS server to the Raspberry Pi's IP address.

## Docker Deployment

Deploy Sentricore DNS Proxy using Docker for consistent, portable environments.

### Build and Run with Docker Compose

1. Build the image and start the services:

```bash
docker-compose up -d
```

2. The services will be available at:
   - **DNS Proxy**: `127.0.0.1:5300` (UDP)
   - **Web Dashboard**: `http://127.0.0.1:5000`
   - **Health Check**: `curl http://127.0.0.1:5000/healthz`

3. View logs:

```bash
docker-compose logs -f sentricore-dns
```

4. Stop the services:

```bash
docker-compose down
```

### Using Docker Run

1. Build the image:

```bash
docker build -t sentricore-dns:latest .
```

2. Run the container:

```bash
docker run -d \
  --name sentricore-dns \
  -p 5300:5300/udp \
  -p 5000:5000/tcp \
  -v ./data:/app/data \
  -v ./logs:/app/logs \
  -v ./blocklists:/app/blocklists \
  -v ./config.json:/app/config.json:ro \
  --restart unless-stopped \
  sentricore-dns:latest
```

### Docker Compose with External Network

To use the proxy from other containers or hosts:

```bash
docker-compose up -d
# Access from another container at: sentricore-dns:5300 (UDP)
# Access from host at: 127.0.0.1:5300 or 192.168.x.x:5300
```

## Testing

Run the test suite with coverage:

```bash
bash run_tests.sh
```

Or with pytest directly:

```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=app --cov-report=html
```

## CI/CD

This project uses GitHub Actions for automated testing and Docker image building:

- **Tests Workflow** (`.github/workflows/tests.yml`):
  - Runs on Python 3.11, 3.12, and 3.13
  - Executes pytest with coverage reporting
  - Uploads coverage to Codecov
  - Runs flake8 linting checks

- **Docker Build Workflow** (`.github/workflows/docker.yml`):
  - Builds Docker image on push to master/tags
  - Validates Dockerfile syntax
  - Available for manual Docker image publishing

- **Publish Workflow** (`.github/workflows/publish.yml`):
  - Builds and pushes Docker image to Docker Hub
  - Optionally pushes to GHCR if `GHCR_TOKEN` secret is set

### Publish secrets

Set these repository secrets in GitHub Settings:

- `DOCKERHUB_USERNAME` (required for publish)
- `DOCKERHUB_TOKEN` (Docker Hub personal access token)
- `GHCR_TOKEN` (optional, if you want push to GitHub Container Registry)

Or run tests directly:

```bash
pytest tests/ -v
```

Coverage report is generated in `htmlcov/index.html`

## Configuration

Settings are configured in `config.json`:

- `upstream_dns`: Upstream DNS server [IP, port]
- `listen_address`: Proxy listen address [IP, port]
- `blocklist_path`: Path to blocklist file
- `blocklist_sources`: Array of blocklist paths or URLs
- `blocklist_update_interval`: Seconds between automatic blocklist reloads
- `cache_ttl`: DNS cache TTL in seconds
- `cache_max_size`: Maximum cache entries
- `database_path`: Path to SQLite database

## Health check

- HTTP: `GET /healthz` returns `status: ok` and current timestamp

## Metrics

Sentricore DNS Proxy exposes operational metrics in Prometheus text format on the `/metrics` endpoint.

### Prometheus metrics endpoint

```bash
curl http://127.0.0.1:5000/metrics
```

**Available metrics:**

- `sentricore_total_queries` — Total DNS queries processed (counter)
- `sentricore_blocked_queries` — Total blocked queries (counter)
- `sentricore_cache_hits` — Total cache hits (counter)
- `sentricore_cache_misses` — Total cache misses (counter)
- `sentricore_blocklist_size` — Current blocklist domain count (gauge)

### Prometheus + Grafana setup

1. Add Sentricore DNS to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'sentricore-dns'
    static_configs:
      - targets: ['127.0.0.1:5000']
```

2. Reload Prometheus and create dashboards in Grafana.

Example query:

```promql
rate(sentricore_total_queries[5m])  # QPS over last 5 minutes
rate(sentricore_blocked_queries[5m])  # Blocked queries per second
sentricore_cache_hits / (sentricore_cache_hits + sentricore_cache_misses)  # Cache hit ratio
```

## Blocklist Management API

Manage blocked domains dynamically via REST API without restarting.

### API key authentication

If `DASHBOARD_API_KEY` or `SENTRICORE_API_KEY` is set in the environment, API endpoints require authentication using either header or query parameter:

- `X-API-Key: <secret>`
- `?api_key=<secret>`

Example:

```bash
curl -H "X-API-Key: ${DASHBOARD_API_KEY}" http://127.0.0.1:5000/api/blocklist
```

### GET /api/blocklist

Get all blocked domains.

```bash
curl http://127.0.0.1:5000/api/blocklist
```
```

Response:
```json
{
  "count": 3,
  "domains": [
    {"domain": "badsite.com", "source": "api", "added_at": "2026-03-29T..."},
    {"domain": "evil.com", "source": "api", "added_at": "2026-03-29T..."}
  ]
}
```

### POST /api/blocklist

Add a domain to the blocklist.

```bash
curl -X POST http://127.0.0.1:5000/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "newbadsite.com"}'
```

Response: `201 Created` or `409 Conflict` if already exists

### DELETE /api/blocklist/{domain}

Remove a domain from the blocklist.

```bash
curl -X DELETE http://127.0.0.1:5000/api/blocklist/newbadsite.com
```

Response: `200 OK` or `404 Not Found`

Add domains to block in `blocklists/malware.txt`, one per line.