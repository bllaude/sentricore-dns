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