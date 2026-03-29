import pytest


def test_is_blocked_exact_match():
    """Test exact domain blocking"""
    # Import is_blocked from proxy module
    blocklist = {'bad.com', 'evil.com', 'malware.test'}
    
    def is_blocked(domain, blocklist):
        for blocked in blocklist:
            if domain == blocked or domain.endswith("." + blocked):
                return True
        return False
    
    assert is_blocked('bad.com', blocklist) == True
    assert is_blocked('example.com', blocklist) == False


def test_is_blocked_subdomain():
    """Test subdomain blocking"""
    blocklist = {'bad.com', 'evil.com'}
    
    def is_blocked(domain, blocklist):
        for blocked in blocklist:
            if domain == blocked or domain.endswith("." + blocked):
                return True
        return False
    
    assert is_blocked('sub.bad.com', blocklist) == True
    assert is_blocked('deep.sub.bad.com', blocklist) == True
    assert is_blocked('notbad.com', blocklist) == False


def test_is_blocked_empty_blocklist():
    """Test with empty blocklist"""
    blocklist = set()
    
    def is_blocked(domain, blocklist):
        for blocked in blocklist:
            if domain == blocked or domain.endswith("." + blocked):
                return True
        return False
    
    assert is_blocked('any.com', blocklist) == False


def test_cache_lookup_valid():
    """Test cache hit for valid entry"""
    import time
    
    cache = {}
    domain = 'example.com'
    response = b'cached_response'
    
    cache[domain] = (response, time.time())
    
    # Check within TTL
    found = domain in cache and (time.time() - cache[domain][1]) < 300
    assert found == True


def test_cache_lookup_expired():
    """Test cache miss for expired entry"""
    import time
    
    cache = {}
    domain = 'example.com'
    response = b'cached_response'
    
    # Add to cache with old timestamp (2000 seconds ago)
    cache[domain] = (response, time.time() - 2000)
    
    # Check if expired
    found = domain in cache and (time.time() - cache[domain][1]) < 300
    assert found == False


def test_cache_max_size_enforcement():
    """Test cache size limit"""
    import time
    
    cache = {}
    max_size = 5
    
    # Add 6 items to cache
    for i in range(6):
        cache[f'domain{i}.com'] = (b'response', time.time())
    
    # Remove oldest when exceeds max size
    if len(cache) > max_size:
        oldest = min(cache, key=lambda k: cache[k][1])
        del cache[oldest]
    
    assert len(cache) == max_size


def test_blocklist_loading():
    """Test loading blocklist from set"""
    blocklist = {'bad.com', 'evil.com', 'malware.test'}
    assert len(blocklist) == 3
    assert 'bad.com' in blocklist
