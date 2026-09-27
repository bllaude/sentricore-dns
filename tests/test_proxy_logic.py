import pytest

from app.dns.proxy import (
    Blocklist,
    LRUCache,
    RateLimiter,
    normalize_blocklist,
)


def test_is_blocked_exact_match():
    bl = Blocklist({'bad.com', 'evil.com', 'malware.test'})
    assert bl.contains('bad.com')
    assert not bl.contains('example.com')


def test_is_blocked_subdomain():
    bl = Blocklist({'bad.com', 'evil.com'})
    assert bl.contains('sub.bad.com')
    assert bl.contains('deep.sub.bad.com')
    # suffix lookups must not match partial labels
    assert not bl.contains('notbad.com')
    assert not bl.contains('bad.com.evil.org')


def test_is_blocked_empty_blocklist():
    bl = Blocklist()
    assert not bl.contains('any.com')


def test_is_blocked_single_label_domain():
    """a bare hostname with no dots can only match exactly."""
    bl = Blocklist({'localhost'})
    assert bl.contains('localhost')
    assert not bl.contains('myhost')


def test_blocklist_reload_atomic_and_len():
    bl = Blocklist({'a.com'})
    assert len(bl) == 1
    bl.update({'b.com', 'c.com'})
    assert len(bl) == 2
    assert bl.contains('b.com')
    assert not bl.contains('a.com')


def test_cache_hit_and_age():
    cache = LRUCache(ttl=300, max_size=10)
    cache.set('example.com', b'resp')
    hit = cache.get('example.com')
    assert hit is not None
    response, age = hit
    assert response == b'resp'
    assert age < 5


def test_cache_expiry(monkeypatch):
    import time as time_module
    cache = LRUCache(ttl=100, max_size=10)
    base = time_module.monotonic()
    monkeypatch.setattr(time_module, 'monotonic', lambda: base)
    cache.set('example.com', b'resp')
    monkeypatch.setattr(time_module, 'monotonic', lambda: base + 200)
    assert cache.get('example.com') is None


def test_cache_fifo_eviction_keeps_newest():
    cache = LRUCache(ttl=300, max_size=3)
    for i in range(5):
        cache.set(f'domain{i}.com', f'r{i}'.encode())
    assert len(cache) == 3
    # oldest entries evicted, newest kept
    assert cache.get('domain4.com') is not None
    assert cache.get('domain2.com') is not None
    assert cache.get('domain0.com') is None


def test_rate_limiter_burst_then_deny():
    rl = RateLimiter(rate=1, burst=3)
    assert all(rl.allow('1.2.3.4') for _ in range(3))
    assert not rl.allow('1.2.3.4')
    # different client unaffected
    assert rl.allow('5.6.7.8')


def test_normalize_blocklist_skips_comments_and_hosts_format():
    lines = [
        '# comment',
        '!exclamation comment',
        '',
        '   ',
        'Bad.COM.',
        '0.0.0.0 evil.test',
        '127.0.0.1 malware.test',
        '*.wildcard.test',
        'not a domain !!',
    ]
    result = normalize_blocklist(lines)
    assert 'bad.com' in result
    assert 'evil.test' in result
    assert 'malware.test' in result
    assert 'wildcard.test' in result
    assert all(not any(c in d for c in (' ', '!', '@')) for d in result)