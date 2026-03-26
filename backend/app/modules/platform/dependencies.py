from functools import lru_cache

from app.modules.platform.service import PlatformService
from app.modules.platform.store import PlatformStore


@lru_cache
def get_platform_service() -> PlatformService:
    store = PlatformStore()
    return PlatformService(store=store)
