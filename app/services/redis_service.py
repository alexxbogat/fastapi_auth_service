import logging
import redis.asyncio as redis

from settings import REDIS_URL

logger = logging.getLogger()


async def get_redis():
    r = redis.from_url(REDIS_URL)
    try:
        await r.ping()
        logger.info(f'Connected to Redis at {REDIS_URL}')
        yield r
    except Exception as e:
        logger.critical(f'Cannot connect to Redis at {REDIS_URL}: {e}', exc_info=True)
        raise
    finally:
        await r.close()
        logger.info('Redis connection closed')
