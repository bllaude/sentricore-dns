"""Sentricore DNS proxy.

This module is import-safe: nothing happens at import time (no config
loading, socket binding, or signal-handler installation).  Call ``main()``
(or run ``python -m app.dns.proxy``) to start the server.
"""

import json
import logging
import re
import signal
import socket
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dnslib import DNSRecord, RCODE

from app.models.database import init_db, log_queries_batch, inc_metrics_batch

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Valid domain names (RFC-1035-ish, allows underscores that appear in practice)
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?)+$')

logger = logging.getLogger('sentricore.proxy')


def load_config(config_path=None):
    path = Path(config_path) if config_path else BASE_DIR / 'config.json'
    with open(path, 'r') as f:
        return json.load(f)


def normalize_blocklist(raw_lines):
    """filter/normalize raw blocklist lines into a set of lowercase domains.

    skips comments and hosts-file junk; strips leading wildcards and
    trailing dots.
    """
    domains = set()
    for line in raw_lines:
        line = line.strip().lower()
        if not line or line.startswith(('#', '!')):
            continue
        parts = line.split()
        if len(parts) > 1:
            # hosts format: "0.0.0.0 evil.com" / "127.0.0.1 bad.test"
            candidates = [p for p in parts if not p.startswith(('0.0.0.0', '127.0.0.1', '::'))]
            if not candidates:
                continue
            line = candidates[-1]
        line = line.lstrip('.').rstrip('.')
        if '*' in line:
            line = line.lstrip('*.')
        if DOMAIN_RE.match(line):
            domains.add(line)
    return domains


def load_blocklist(sources):
    """load blocked domains from local files and/or http(s) URLs."""
    domains = set()
    loaded_any = False
    for entry in sources:
        try:
            if entry.startswith('http://') or entry.startswith('https://'):
                parsed = urlparse(entry)
                # only allow remote HTTPS feeds (mitigates SSRF / cleartext).
                if parsed.scheme != 'https' or not parsed.hostname:
                    logging.warning("Skipping unsafe blocklist source: %s", entry)
                    continue
                import urllib.request
                req = urllib.request.Request(entry, headers={'User-Agent': 'sentricore-dns'})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    text = resp.read().decode('utf-8', errors='ignore')
                source_domains = normalize_blocklist(text.splitlines())
            else:
                path = Path(entry)
                if not path.is_absolute():
                    path = BASE_DIR / path
                with open(path, 'r') as f:
                    source_domains = normalize_blocklist(f)
            domains.update(source_domains)
            loaded_any = True
            logging.info("Loaded %d domains from %s", len(source_domains), entry)
        except Exception as e:
            logging.warning("Could not load blocklist source %s: %s", entry, e)
    if not loaded_any and sources:
        logging.error("All blocklist sources failed to load; keeping previous list")
    return domains, loaded_any


class Blocklist:
    """blocked-domain set with O(labels) suffix lookups and atomic reload."""

    def __init__(self, initial=None):
        self._lock = threading.Lock()
        self._domains = set(initial or ())

    def update(self, domains):
        with self._lock:
            self._domains = set(domains)

    def __len__(self):
        return len(self._domains)

    def contains(self, domain):
        """return True if domain (or any parent) is blocked.

        instead of scanning every blocked entry, walk the query's own
        suffixes (at most ~12 labels) and do O(1) set lookups.
        """
        if domain in self._domains:
            return True
        labels = domain.split('.')
        for i in range(1, len(labels)):
            if '.'.join(labels[i:]) in self._domains:
                return True
        return False

    __contains__ = contains


class LRUCache:
    """TTL + max-size cache with O(1) FIFO/LRU eviction."""

    def __init__(self, ttl, max_size):
        self.ttl = ttl
        self.max_size = max_size
        self._entries = OrderedDict()  # key -> (response_bytes, expires_at)

    def get(self, key):
        """return (response_bytes, age_seconds) or none."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        response, expires_at = entry
        now = time.monotonic()
        if now >= expires_at:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return response, self.ttl - (expires_at - now)

    def set(self, key, response, ttl=None):
        self._entries[key] = (response, time.monotonic() + (ttl if ttl is not None else self.ttl))
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_size:
            self._entries.popitem(last=False)  # evict oldest: O(1)

    def __len__(self):
        return len(self._entries)


class RateLimiter:
    """token bucket per client to blunt DNS amplification/flooding."""

    def __init__(self, rate, burst):
        self.rate = rate      # sustained queries per second per client
        self.burst = burst    # allowed burst size
        self._buckets = {}    # ip -> [tokens, last_time]
        self._last_gc = time.monotonic()

    def allow(self, ip):
        now = time.monotonic()
        if now - self._last_gc > 300:
            # drop stale buckets
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 300}
            self._last_gc = now
        tokens, last = self._buckets.get(ip, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[ip] = (tokens, now)
            return False
        self._buckets[ip] = (tokens - 1, now)
        return True


class DNSServer:
    def __init__(self, config, db_path=None):
        self.config = config
        self.db_path = str(db_path or (BASE_DIR / config.get('database_path', 'data/sentricore.db')))
        addr = tuple(config['listen_address'])
        self.upstream_dns = tuple(config['upstream_dns'])
        self.blocklist = Blocklist()
        self.cache = LRUCache(config.get('cache_ttl', 300), config.get('cache_max_size', 10000))
        self.rate_limiter = RateLimiter(
            config.get('rate_limit_per_client_qps', 50),
            config.get('rate_limit_burst', 100),
        )
        self.update_interval = config.get('blocklist_update_interval', 300)
        self.last_reload = 0.0
        self.running = False
        self._flush_interval = config.get('db_flush_interval', 1.0)
        self._pending_queries = []
        self._pending_metrics = {}
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(addr)
        self.listen_address = self._sock.getsockname()

    # ------------------------------------------------------------------
    def reload_blocklist(self):
        sources = self.config.get('blocklist_sources') or [self.config.get('blocklist_path')]
        sources = [s for s in sources if s]
        domains, ok = load_blocklist(sources)
        if ok:
            # merge manually-added domains from the database blocklist table
            try:
                from app.models.database import get_blocklist_domains
                domains.update(row['domain'] for row in get_blocklist_domains(self.db_path))
            except Exception as e:
                logging.warning("Could not merge DB blocklist: %s", e)
            self.blocklist.update(domains)
            logging.info("Blocklist reloaded: %d domains", len(domains))
        self.last_reload = time.time()

    # ------------------------------------------------------------------
    def maybe_reload_blocklist(self):
        if time.time() - self.last_reload > self.update_interval:
            try:
                self.reload_blocklist()
            except Exception:
                logging.exception("Blocklist reload failed")

    # ------------------------------------------------------------------
    def record(self, client_ip, domain, blocked, metric=None):
        """queue a query row / metric increment for batched DB writes."""
        self._pending_queries.append((
            datetime.now(timezone.utc).isoformat(), client_ip, domain, int(blocked)
        ))
        self._pending_metrics['total_queries'] = self._pending_metrics.get('total_queries', 0) + 1
        if metric:
            self._pending_metrics[metric] = self._pending_metrics.get(metric, 0) + 1

    def flush(self):
        if self._pending_queries:
            rows, self._pending_queries = self._pending_queries, []
            try:
                log_queries_batch(rows, self.db_path)
            except Exception:
                logging.exception("Failed to flush query log")
        if self._pending_metrics:
            deltas, self._pending_metrics = self._pending_metrics, {}
            try:
                inc_metrics_batch(deltas, self.db_path)
            except Exception:
                logging.exception("Failed to flush metrics")

    # ------------------------------------------------------------------
    def handle_query(self, data, addr):
        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip('.').lower()

        self.maybe_reload_blocklist()

        if self.blocklist.contains(domain):
            logging.info("BLOCKED: %s -> %s", addr[0], domain)
            self.record(addr[0], domain, True)
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            self._sock.sendto(reply.pack(), addr)
            return

        # cache hit: fix up the transaction ID and decrement TTLs before replying
        cached = self.cache.get(domain)
        if cached is not None:
            logging.info("CACHE HIT: %s -> %s", addr[0], domain)
            self.record(addr[0], domain, False, 'cache_hits')
            response_bytes, age = cached
            reply_bytes = self._refresh_cached_reply(response_bytes, request.header.id, age)
            self._sock.sendto(reply_bytes, addr)
            return

        self.record(addr[0], domain, False, 'cache_misses')

        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(3)
        try:
            try:
                upstream_sock.sendto(data, self.upstream_dns)
                response, _ = upstream_sock.recvfrom(1024)
            except (socket.timeout, OSError):
                logging.warning("TIMEOUT: %s -> %s", addr[0], domain)
                reply = request.reply()
                reply.header.rcode = RCODE.SERVFAIL
                self._sock.sendto(reply.pack(), addr)
                return
        finally:
            upstream_sock.close()

        self._sock.sendto(response, addr)

        # cache with the minimum TTL of the answer (bounded by cache_ttl)
        ttl = self._response_ttl(response)
        if ttl > 0:
            self.cache.set(domain, response, ttl=min(ttl, self.cache.ttl))

    @staticmethod
    def _response_ttl(response):
        try:
            parsed = DNSRecord.parse(response)
            ttls = [rr.ttl for rr in parsed.rr]
            return min(ttls) if ttls else 0
        except Exception:
            return 0

    @staticmethod
    def _refresh_cached_reply(cached_bytes, query_id, age=0):
        """rewrite a cached reply so its ID matches the live request and
        remaining TTLs reflect how long it has been sitting in the cache."""
        try:
            reply = DNSRecord.parse(cached_bytes)
            reply.header.id = query_id
            for rr in reply.rr:
                rr.ttl = max(1, int(rr.ttl - age))
            return reply.pack()
        except Exception:
            return cached_bytes

    # ------------------------------------------------------------------
    def serve_forever(self, max_queries=None):
        self.running = True
        processed = 0
        last_flush = time.monotonic()
        while self.running:
            try:
                data, addr = self._sock.recvfrom(512)
            except OSError:
                break
            if not self.rate_limiter.allow(addr[0]):
                logging.warning("RATE LIMITED: %s", addr[0])
                try:
                    request = DNSRecord.parse(data)
                    reply = request.reply()
                    reply.header.rcode = RCODE.SERVFAIL
                    self._sock.sendto(reply.pack(), addr)
                except Exception:
                    pass
                continue
            try:
                self.handle_query(data, addr)
            except Exception:
                logging.exception("Error handling query from %s", addr[0])
            processed += 1
            if time.monotonic() - last_flush >= self._flush_interval:
                self.flush()
                last_flush = time.monotonic()
            if max_queries is not None and processed >= max_queries:
                break
        self.flush()

    def stop(self):
        self.running = False
        try:
            self._sock.close()
        except Exception:
            pass

    def close(self):
        self.stop()


def setup_logging(config):
    log_path = BASE_DIR / config.get('log_file', 'logs/proxy.log')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(log_path),
        level=getattr(logging, config.get('log_level', 'INFO'), logging.INFO),
        format='%(asctime)s - %(levelname)s - %(message)s',
    )


def main(config_path=None):
    config = load_config(config_path)
    setup_logging(config)
    server = DNSServer(config)
    init_db(server.db_path)
    server.reload_blocklist()

    def shutdown(signum, frame):
        logging.info("Shutting down Sentricore DNS Proxy...")
        server.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    host, port = server.listen_address
    print(f"Sentricore DNS Proxy running on {host}:{port}...")
    try:
        server.serve_forever()
    finally:
        server.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())