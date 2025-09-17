import logging
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.schemas import BlockUser

logger = logging.getLogger()


async def change_block_status(data: BlockUser, current_admin: User, db: AsyncSession) -> User:
    """
    Change the block status of a specific user.

    Args:
        data (BlockUser): Pydantic schema with `user_id` and `is_blocked`.
        current_admin (User): The admin performing the action.
        db (AsyncSession): Active database session.

    Returns:
        User: Updated user instance with new block status.
    """
    result = await db.execute(select(User).where(User.id == data.user_id))
    user = result.scalar_one_or_none()
    if not user:
        logger.warning(
            f'Admin {current_admin.email} tried to change block status for non-existent user ID {data.user_id}')
        raise HTTPException(status_code=404, detail='User not found')
    if user.id == current_admin.id:
        logger.warning(f'Admin {current_admin.email} attempted to block themselves')
        raise HTTPException(status_code=400, detail='You cannot block yourself')
    if user.is_blocked == data.is_blocked:
        logger.info(f'Admin {current_admin.email} attempted to set same block status for user {user.email}')
        raise HTTPException(status_code=400, detail='User already has this block status')
    user.is_blocked = data.is_blocked
    user.block_at = datetime.now()
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'Admin {current_admin.email} changed block status for user {user.email} to {user.is_blocked}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'Database error while changing block status for user ID {data.user_id}: {e}')
        raise
