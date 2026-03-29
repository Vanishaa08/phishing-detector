import redis
import json
import hashlib

# Redis connection — falls back gracefully if Redis not running
try:
    r = redis.Redis(host='localhost', port=6379, db=0,
                    socket_connect_timeout=2)
    r.ping()
    REDIS_AVAILABLE = True
    print("Redis cache: connected")
except:
    REDIS_AVAILABLE = False
    print("Redis cache: not available — running without cache")

CACHE_TTL = 3600  # 1 hour

def get_cache_key(url):
    return f"phishguard:{hashlib.md5(url.encode()).hexdigest()}"

def get_cached(url):
    if not REDIS_AVAILABLE:
        return None
    try:
        key = get_cache_key(url)
        val = r.get(key)
        if val:
            return json.loads(val)
    except:
        pass
    return None

def set_cached(url, result):
    if not REDIS_AVAILABLE:
        return
    try:
        key = get_cache_key(url)
        r.setex(key, CACHE_TTL, json.dumps(result))
    except:
        pass

def get_cache_stats():
    if not REDIS_AVAILABLE:
        return {"status": "unavailable"}
    try:
        info = r.info()
        return {
            "status": "connected",
            "used_memory": info['used_memory_human'],
            "total_keys": r.dbsize(),
            "hits": info.get('keyspace_hits', 0),
            "misses": info.get('keyspace_misses', 0)
        }
    except:
        return {"status": "error"}