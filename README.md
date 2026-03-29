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

## Testing

Run the test suite with coverage:

```bash
bash run_tests.sh
```

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

## Blocklist Management API

Manage blocked domains dynamically via REST API without restarting.

### GET /api/blocklist

Get all blocked domains.

```bash
curl http://127.0.0.1:5000/api/blocklist
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