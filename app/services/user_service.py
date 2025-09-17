import asyncio
import logging
from datetime import datetime

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.security import hash_secret, verify_token
from app.services.redis_service import get_redis
from app.session import get_db_session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/user/login')

logger = logging.getLogger()


class UserAlreadyExistsError(Exception):
    """Raised when trying to create a user with an existing email."""


async def get_current_user(token: str = Depends(oauth2_scheme),
                           redis=Depends(get_redis),
                           db: AsyncSession = Depends(get_db_session)) -> tuple:
    """
    Dependency: Extract and validate the current authenticated user from JWT.

    Args:
        token (str): Bearer token from the Authorization header.
        redis: Redis connection for token revocation checks.
        db (AsyncSession): Database session.

    Returns:
        tuple[User, dict]: The user instance and the decoded JWT payload.
    """
    try:
        payload = await verify_token(token, redis)
        user_email = payload.get('sub')
        if not user_email:
            logger.warning('Invalid token payload: "sub" is missing')
            raise HTTPException(status_code=401, detail='Invalid token payload')
        user = await get_user_by_email(user_email, db)
        if not user:
            logger.warning(f'User not found for email: {user_email}')
            raise HTTPException(status_code=401, detail='User not found')
        logger.info(f'Authenticated user: {user_email}')
        return user, payload
    except JWTError as e:
        logger.error(f'JWT validation error: {e}')
        raise HTTPException(status_code=401, detail='Invalid token')


def require_admin(user: tuple = Depends(get_current_user)):
    """
    Dependency: Ensure the current user has the admin role.

    Returns:
        User: The authenticated admin user.
    """
    user, _ = user
    if user.role.value != 'admin':
        logger.warning(f'Access denied for non-admin role {user.email}')
        raise HTTPException(status_code=404, detail='Not Found')
    return user


def require_user(user: tuple = Depends(get_current_user)):
    """
    Dependency: Ensure the current user has the user role.

    Returns:
        User: The authenticated user with role 'user'.
    """
    user, _ = user
    if user.role.value != 'user':
        logger.warning(f'Access denied for non-user role {user.email}')
        raise HTTPException(status_code=404, detail='Not Found')
    return user


async def create_user(email: str, password: str, db: AsyncSession) -> User:
    """
    Create a new user with a hashed password.

    Args:
        email (str): The user's email address.
        password (str): The user's plain text password.
        db (AsyncSession): Database session (injected).

    Returns:
        User: The created user instance.
    """
    logger.info(f'Creating user with email: {email}')
    user = await get_user_by_email(email, db)
    hashed_str = await hash_secret(password)

    if user and not user.is_deleted:
        logger.warning(f'User creation failed — already exists: {email}')
        raise UserAlreadyExistsError('User with this email already exists')
    if user and user.is_deleted:
        user.password = hashed_str
        user.updated_at = datetime.now()
    else:
        user = User(email=email, password=hashed_str)
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'User created: {email}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while creating user {email}: {e}')
        raise


async def get_user_by_email(email: str, db: AsyncSession) -> User | None:
    """
    Retrieve a user by email.

    Args:
        email (str): The email address to search for.
        db (AsyncSession): Database session (injected).

    Returns:
        User | None: The user instance if found, otherwise None.
    """
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def change_password(user_email: str, new_password: str, db: AsyncSession) -> User | None:
    """
    Update a user's password.

    Args:
        user_email (str): The email address of the user.
        new_password (str): The new hashed password to set.
        db (AsyncSession): Database session (injected).

    Returns:
        User | None: The updated user instance if found, otherwise None.
    """
    logger.info(f'Changing password for: {user_email}')
    res = await db.execute(select(User).where(User.email == user_email))
    user = res.scalar_one_or_none()
    if not user:
        logger.warning(f'User not found for password change: {user_email}')
        return None
    user.password = new_password
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'Password changed for: {user_email}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while changing password for {user_email}: {e}')
        raise


async def update_user(user: User, data, db: AsyncSession) -> User:
    """
    Update user attributes with provided data.

    Args:
        user (User): The user instance to update.
        data: Pydantic model or object with `.dict(exclude_unset=True)` method.
        db (AsyncSession): Database session (injected).

    Returns:
        User: The updated user instance.
    """
    logger.info(f'Updating user {user.email}')
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'User updated: {user.email}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while updating user {user.email}: {e}')
        raise


async def set_user_activity(user: User, db: AsyncSession, is_online: bool) -> User:
    """
    Update their last activity timestamp.

    Args:
        user (User): The user instance to update.
        db (AsyncSession): Database session (injected).
        is_online (bool): True to mark user as online, False to mark as offline.

    Returns:
        User: The updated user instance.
    """
    user.last_activity_at = datetime.now()
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while setting activity for {user.email}: {e}')
        raise


async def set_user_online(user: User, db: AsyncSession):
    """Mark a user as online and update their last activity timestamp."""
    return await set_user_activity(user, db, is_online=True)


async def set_user_offline(user: User, db: AsyncSession):
    """Mark a user as offline and update their last activity timestamp."""
    return await set_user_activity(user, db, is_online=False)
