import time
from backend.db.database import get_active_indicators

_CACHE = {}
_CACHE_EXPIRES_AT = 0
_CACHE_TTL = 300  # 5 minutes

def get_merged_indicators(indicator_type: str) -> list[dict]:
    """
    Returns active indicators of the given type, using a 5-minute in-memory cache.
    Returns a list of dicts: {"value": str, "category": str, "severity": str}
    """
    global _CACHE, _CACHE_EXPIRES_AT
    
    now = time.time()
    if now > _CACHE_EXPIRES_AT:
        # Refresh cache
        try:
            active_inds = get_active_indicators()
            
            # Group by type for fast lookup
            new_cache = {}
            for ind in active_inds:
                t = ind["indicator_type"]
                if t not in new_cache:
                    new_cache[t] = []
                new_cache[t].append({
                    "value": ind["value"],
                    "category": ind["category"],
                    "severity": ind["severity"]
                })
            
            _CACHE = new_cache
            _CACHE_EXPIRES_AT = now + _CACHE_TTL
        except Exception:
            # If DB fails, use stale cache or empty if none
            pass

    return _CACHE.get(indicator_type, [])
