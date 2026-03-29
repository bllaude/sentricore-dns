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

## Configuration

- Blocklists are in the `blocklists/` folder
- Database is stored in `data/sentricore.db`
- Proxy listens on 0.0.0.0:5300
- Upstream DNS: 1.1.1.1

## Blocklists

Add domains to block in `blocklists/malware.txt`, one per line.