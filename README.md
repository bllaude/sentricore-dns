# Sentricore DNS Proxy

A security-focused DNS proxy that blocks malicious domains, caches responses,
rate-limits clients, and logs every query to SQLite — with a Flask web
dashboard and Prometheus metrics for monitoring.

## Features

- **DNS proxy** listening on UDP port 5300, forwarding to a configurable upstream resolver
- **Domain blocking** via local or URL-based blocklists, with automatic periodic reload
- **LRU response cache** with configurable TTL and max size
- **Per-client rate limiting** (token bucket) to prevent abuse / amplification
- **Batched SQLite logging** of queries and operational metrics
- **Web dashboard** with query history and health endpoint
- **Prometheus `/metrics`** endpoint
- **Blocklist management REST API** with optional API-key authentication
- **Deployment options**: bare metal, systemd (Raspberry Pi), Docker / Docker Compose
- **CI/CD** with GitHub Actions (tests, linting, coverage, Docker builds/publishing)

## Project Structure

```
.
├── app/
│   ├── dns/            # DNS proxy server (proxy.py, logger.py)
│   ├── models/         # SQLite database layer (database.py)
│   └── web/            # Flask dashboard + REST API (app.py, templates/)
├── blocklists/         # Blocklist files (one domain per line)
├── data/               # SQLite database (created at runtime)
├── logs/               # Proxy log files (created at runtime)
├── tests/              # Pytest test suite
├── config.json         # Main configuration file
├── run_proxy.py        # Runner: DNS proxy
├── run_web.py          # Runner: web dashboard (local dev)
├── Dockerfile          # Container image
├── docker-compose.yml  # Proxy + web services
└── install.sh          # Raspberry Pi / systemd installer
```

## Requirements

- Python 3.11+
- Dependencies: `dnslib`, `Flask`, `gunicorn` (see `requirements.txt`)

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

1. Run the DNS proxy:
   ```bash
   python run_proxy.py
   ```
   (equivalent to `python -m app.dns.proxy`)

2. In another terminal, run the web dashboard:
   ```bash
   python run_web.py
   ```
   (equivalent to `python -m app.web.app`; use gunicorn for production)

3. Open http://127.0.0.1:5000 in your browser to view the dashboard.

4. Point a client's DNS server at `<host>:5300` (UDP), e.g.:
   ```bash
   dig @127.0.0.1 -p 5300 example.com
   ```

## Configuration

Settings live in `config.json`:

| Key | Description |
|-----|-------------|
| `upstream_dns` | Upstream DNS server `[IP, port]` (default `1.1.1.1:53`) |
| `listen_address` | Proxy listen address `[IP, port]` (default `0.0.0.0:5300`) |
| `blocklist_path` | Primary blocklist file path |
| `blocklist_sources` | Array of blocklist paths or URLs, merged on load/reload |
| `blocklist_update_interval` | Seconds between automatic blocklist reloads |
| `cache_ttl` | DNS response cache TTL in seconds |
| `cache_max_size` | Maximum number of cached responses (LRU eviction) |
| `database_path` | Path to the SQLite database |
| `log_file` / `log_level` | Proxy log file location and level |
| `rate_limit_per_client_qps` | Sustained queries-per-second allowed per client IP |
| `rate_limit_burst` | Token-bucket burst allowance per client IP |
| `db_flush_interval` | Seconds between batched writes of query logs/metrics to SQLite |

### Environment variables (web app)

| Variable | Description |
|----------|-------------|
| `SENTRICORE_CONFIG` | Alternate path to `config.json` |
| `SENTRICORE_DB` | Override database path |
| `SENTRICORE_API_KEY` / `DASHBOARD_API_KEY` | Shared secret required for write API endpoints |
| `SENTRICORE_DENY_WRITES_WITHOUT_KEY` | Set to `0` to allow writes when no API key is configured (default: deny) |
| `SENTRICORE_WEB_HOST` / `SENTRICORE_WEB_PORT` | Dashboard bind host/port (default `127.0.0.1:5000`) |
| `FLASK_DEBUG` | Set to `1` to enable Flask debug mode |

## Web Endpoints

- `GET /` — Dashboard overview
- `GET /queries` — Query history
- `GET /healthz` — Health check (`status: ok` + timestamp)
- `GET /metrics` — Prometheus metrics
- `GET/POST/DELETE /api/blocklist` — Blocklist management (see below)

## Metrics

Operational metrics are exposed in Prometheus text format:

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

Example queries:

```promql
rate(sentricore_total_queries[5m])  # QPS over last 5 minutes
rate(sentricore_blocked_queries[5m])  # Blocked queries per second
sentricore_cache_hits / (sentricore_cache_hits + sentricore_cache_misses)  # Cache hit ratio
```

## Blocklist Management

Static lists: add domains to files under `blocklists/` (one per line; ad-block
style hosts entries like `0.0.0.0 domain` are normalized automatically). The
proxy merges all `blocklist_sources` (files or URLs) and reloads them every
`blocklist_update_interval` seconds — no restart needed.

Dynamic management via REST API (changes persist to the database):

### API key authentication

If `SENTRICORE_API_KEY` or `DASHBOARD_API_KEY` is set, protected endpoints
require authentication via header or query parameter:

- `X-API-Key: <secret>`
- `?api_key=<secret>`

By default, write endpoints are rejected when no API key is configured
(set `SENTRICORE_DENY_WRITES_WITHOUT_KEY=0` to change this).

### GET /api/blocklist

Get all blocked domains.

```bash
curl -H "X-API-Key: ${SENTRICORE_API_KEY}" http://127.0.0.1:5000/api/blocklist
```

Response:
```json
{
  "count": 2,
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
  -H "X-API-Key: ${SENTRICORE_API_KEY}" \
  -d '{"domain": "newbadsite.com"}'
```

Response: `201 Created` or `409 Conflict` if already exists.

### DELETE /api/blocklist/{domain}

Remove a dynamically added domain from the blocklist.

```bash
curl -X DELETE http://127.0.0.1:5000/api/blocklist/newbadsite.com \
  -H "X-API-Key: ${SENTRICORE_API_KEY}"
```

Response: `200 OK` or `404 Not Found`.

## Raspberry Pi Deployment

Deploy as permanent systemd services on Raspberry Pi.

### Quick Installation

```bash
sudo bash install.sh
```

The script will:
- Install system dependencies (python3, python3-venv, git)
- Create a `sentricore` system user
- Set up a Python virtual environment and install dependencies
- Install two systemd units (`sentricore-dns-proxy.service`, `sentricore-dns-web.service`) for auto-start on boot
- Start the DNS proxy and web dashboard

### Service Management

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

To use the proxy from other devices, point their DNS server to the Raspberry
Pi's IP address.

## Docker Deployment

### Build and Run with Docker Compose

```bash
docker compose up -d
```

Two services are started:
- **sentricore-dns-proxy** — the DNS proxy on `5300/udp` (with healthcheck)
- **sentricore-dns-web** — the dashboard served by gunicorn on `5000/tcp`

Volumes mount `./data`, `./logs`, `./blocklists`, and a read-only
`./config.json` into the containers.

Useful commands:

```bash
docker compose logs -f          # follow logs
docker compose down             # stop services
```

### Using Docker Run

```bash
docker build -t sentricore-dns:latest .

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

The container runs as a non-root `sentricore` user.

## Testing

Run the test suite with coverage:

```bash
bash run_tests.sh
```

Or with pytest directly:

```bash
pytest tests/ -v
pytest tests/ --cov=app --cov-report=html   # HTML report in htmlcov/index.html
```

## CI/CD

This project uses GitHub Actions:

- **Tests Workflow** (`.github/workflows/tests.yml`):
  - Runs on Python 3.11, 3.12, and 3.13
  - Executes pytest with coverage reporting
  - Uploads coverage to Codecov
  - Runs flake8 linting checks

- **Docker Build Workflow** (`.github/workflows/docker.yml`):
  - Builds the Docker image on push to master/tags
  - Validates Dockerfile syntax

- **Publish Workflow** (`.github/workflows/publish.yml`):
  - Builds and pushes the Docker image to Docker Hub
  - Optionally pushes to GHCR if `GHCR_TOKEN` secret is set

### Publish secrets

Set these repository secrets in GitHub Settings:

- `DOCKERHUB_USERNAME` (required for publish)
- `DOCKERHUB_TOKEN` (Docker Hub personal access token)
- `GHCR_TOKEN` (optional, to also push to GitHub Container Registry)

## License

All rights reserved unless otherwise stated.
