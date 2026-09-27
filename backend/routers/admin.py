import os
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from backend.models.schemas import IndicatorCreate, IndicatorUpdate, IndicatorResponse
from backend.db.database import add_indicator, get_all_indicators, update_indicator, delete_indicator
from backend.limiter import limiter

router = APIRouter()

def verify_admin_key(x_admin_key: str = Header(...)):
    expected_key = os.getenv("ADMIN_API_KEY")
    if not expected_key:
        raise HTTPException(status_code=500, detail="Server configuration error: ADMIN_API_KEY not set")
    if not secrets.compare_digest(x_admin_key, expected_key):
        raise HTTPException(status_code=401, detail="Invalid admin key")

@router.post("/indicators", response_model=IndicatorResponse, dependencies=[Depends(verify_admin_key)])
@limiter.limit("10/minute")
async def create_indicator(request: Request, indicator: IndicatorCreate):
    data = indicator.model_dump()
    result = add_indicator(data)
    # Force cache refresh logic could be added here or rely on TTL
    from backend.engines.indicator_cache import _CACHE_EXPIRES_AT
    import backend.engines.indicator_cache as cache
    cache._CACHE_EXPIRES_AT = 0  # Invalidate cache
    return result

@router.get("/indicators", response_model=list[IndicatorResponse], dependencies=[Depends(verify_admin_key)])
@limiter.limit("10/minute")
async def list_indicators(request: Request, indicator_type: Optional[str] = None, category: Optional[str] = None):
    return get_all_indicators(indicator_type=indicator_type, category=category)

@router.patch("/indicators/{indicator_id}", response_model=IndicatorResponse, dependencies=[Depends(verify_admin_key)])
@limiter.limit("10/minute")
async def modify_indicator(request: Request, indicator_id: int, updates: IndicatorUpdate):
    update_data = updates.model_dump(exclude_unset=True)
    result = update_indicator(indicator_id, update_data)
    if not result:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    import backend.engines.indicator_cache as cache
    cache._CACHE_EXPIRES_AT = 0  # Invalidate cache
    return result

@router.delete("/indicators/{indicator_id}", dependencies=[Depends(verify_admin_key)])
@limiter.limit("10/minute")
async def remove_indicator(request: Request, indicator_id: int):
    success = delete_indicator(indicator_id)
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    import backend.engines.indicator_cache as cache
    cache._CACHE_EXPIRES_AT = 0  # Invalidate cache
    return {"status": "deleted"}
