import socket
import time
import json
import logging
import signal
import urllib.request
from app.models.database import init_db, log_query, inc_metric
from dnslib import DNSRecord, RCODE
from datetime import datetime, timezone

CONFIG = json.load(open('config.json'))
UPSTREAM_DNS = tuple(CONFIG['upstream_dns'])
LISTEN_ADDRESS = tuple(CONFIG['listen_address'])
BLOCKLIST_PATH = CONFIG['blocklist_path']
BLOCKLIST_SOURCES = CONFIG.get('blocklist_sources', [BLOCKLIST_PATH])
BLOCKLIST_UPDATE_INTERVAL = CONFIG.get('blocklist_update_interval', 300)

# Setup logging
logging.basicConfig(filename='logs/proxy.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_blocklist():
    domains = set()
    for entry in BLOCKLIST_SOURCES:
        try:
            if entry.startswith('http://') or entry.startswith('https://'):
                with urllib.request.urlopen(entry, timeout=10) as resp:
                    text = resp.read().decode('utf-8', errors='ignore')
                source_domains = {line.strip().lower() for line in text.splitlines() if line.strip()}
                domains.update(source_domains)
            else:
                with open(entry, 'r') as f:
                    source_domains = {line.strip().lower() for line in f if line.strip()}
                domains.update(source_domains)
        except Exception as e:
            logging.warning(f"Could not load blocklist source {entry}: {e}")
    return domains


def reload_blocklist():
    global BLOCKLIST
    BLOCKLIST = load_blocklist()
    logging.info(f"Loaded {len(BLOCKLIST)} blocked domains from sources")


BLOCKLIST = load_blocklist()
init_db(CONFIG['database_path'])
CACHE = {}  # domain -> (response_bytes, timestamp)
CACHE_TTL = CONFIG['cache_ttl']
CACHE_MAX_SIZE = CONFIG['cache_max_size']
LAST_BLOCKLIST_RELOAD = time.time()


def is_blocked(domain):
    for blocked in BLOCKLIST:
        if domain == blocked or domain.endswith("." + blocked):
            return True
    return False


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(LISTEN_ADDRESS)

print("Sentricore DNS Proxy running on port 5300...")


def cleanup_and_exit(signum, frame):
    print("Shutting down Sentricore DNS Proxy...")
    logging.info("Shutting down Sentricore DNS Proxy...")
    try:
        sock.close()
    except Exception:
        pass
    exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)


def maybe_reload_blocklist():
    global LAST_BLOCKLIST_RELOAD
    if time.time() - LAST_BLOCKLIST_RELOAD > BLOCKLIST_UPDATE_INTERVAL:
        reload_blocklist()
        LAST_BLOCKLIST_RELOAD = time.time()

while True:
    try:
        data, addr = sock.recvfrom(512)

        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip(".").lower()

        # Periodically reload blocklist from sources
        maybe_reload_blocklist()

        print(f"[{datetime.now(timezone.utc)}] {addr[0]} → {domain}")

        if is_blocked(domain):
            print(f"[BLOCKED] {addr[0]} → {domain}")
            logging.info(f"BLOCKED: {addr[0]} -> {domain}")

            log_query(addr[0], domain, True, CONFIG['database_path'])
            inc_metric('total_queries', 1, CONFIG['database_path'])

            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN

            sock.sendto(reply.pack(), addr)
            continue

        inc_metric('total_queries', 1, CONFIG['database_path'])
        log_query(addr[0], domain, False, CONFIG['database_path'])

        # Check cache
        if domain in CACHE and time.time() - CACHE[domain][1] < CACHE_TTL:
            print(f"[CACHE HIT] {addr[0]} → {domain}")
            logging.info(f"CACHE HIT: {addr[0]} -> {domain}")
            inc_metric('cache_hits', 1, CONFIG['database_path'])
            response = CACHE[domain][0]
            sock.sendto(response, addr)
            continue

        inc_metric('cache_misses', 1, CONFIG['database_path'])

        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(3)
        upstream_sock.sendto(data, UPSTREAM_DNS)

        try:
            response, _ = upstream_sock.recvfrom(512)
            sock.sendto(response, addr)
            
            # Cache the response
            CACHE[domain] = (response, time.time())
            # Limit cache size
            if len(CACHE) > CACHE_MAX_SIZE:
                # Remove oldest entries (simple FIFO)
                oldest = min(CACHE, key=lambda k: CACHE[k][1])
                del CACHE[oldest]
                
        except socket.timeout:
            print(f"[TIMEOUT] {addr[0]} → {domain}")
            logging.warning(f"TIMEOUT: {addr[0]} -> {domain}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            sock.sendto(reply.pack(), addr)

    except Exception as e:
        print("Error:", e)
