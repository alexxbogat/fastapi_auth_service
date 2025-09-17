import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from settings import DATABASE_URL, LOGGING_MODE

logger = logging.getLogger()
engine = create_async_engine(DATABASE_URL, echo=(LOGGING_MODE == 'local'))
async_session = async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session():
    async with async_session() as session:
        try:
            logger.info('DB session opened')
            yield session
        except SQLAlchemyError as e:
            logger.critical(f'Database session error: {e}', exc_info=True)
            raise
        except Exception as e:
            logger.critical(f'Unexpected error in DB session: {e}', exc_info=True)
            raise
        finally:
            await session.close()
            logger.info('DB session closed')
