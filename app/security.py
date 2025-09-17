import asyncio
import bcrypt
import logging
import uuid
import hashlib
from datetime import datetime, timedelta
from fastapi import HTTPException
from jose import jwt, JWTError
from secrets import token_urlsafe

from app.models import User
from settings import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    EMAIL_TOKEN_EXPIRE_MINUTES
)

logger = logging.getLogger()


async def create_refresh_token(user: User,
                               redis,
                               expires_delta: str = REFRESH_TOKEN_EXPIRE_MINUTES) -> str:
    """
    Generate a new refresh token for a user and store its hashed value in Redis.

    Args:
        user (User): The user for whom the refresh token is created.
        redis: Async Redis client for storing the token.
        expires_delta (str, optional): Token expiration time in minutes.

    Returns:
        str: The plain refresh token to be sent to the client.
    """
    try:
        await redis.delete(f'refresh:{user.id}')
        token = f'{user.id}-{uuid.uuid4().hex}'
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        await redis.set(f'refresh:{user.id}', hashed_token, ex=int(expires_delta) * 60)
        logger.info(f'Created refresh token for user {user.email}')
        return token
    except Exception as e:
        logger.critical(f'Failed to create refresh token for user {user.email}: {e}')
        raise HTTPException(status_code=500, detail=f'Token creation failed: {str(e)}')


async def validate_refresh_token(user: User, token: str, redis) -> str:
    """
    Validate a given refresh token against the hashed value stored in Redis.

    Args:
        user (User): The user associated with the token.
        token (str): The refresh token to validate.
        redis: Async Redis client to retrieve the stored token.

    Returns:
        str: The original token if valid.
    """
    try:
        hashed_token = await redis.get(f'refresh:{user.id}')
        if hashed_token is None:
            logger.warning(f'Refresh token missing for user {user.email}')
            raise HTTPException(status_code=401, detail='Refresh token is invalid or expired')
        if hashlib.sha256(token.encode()).hexdigest() != hashed_token.decode():
            logger.warning(f'Invalid refresh token attempt for user {user.email}')
            raise HTTPException(status_code=401, detail='Refresh token is invalid')
        logger.info(f'Refresh token validated for user {user.email}')
        return token
    except Exception as e:
        logger.warning(f'Error while validating refresh token for user {user.email}: {e}')
        raise HTTPException(status_code=401, detail='Invalid refresh token')


def create_access_token(data: dict, expires_delta: str = ACCESS_TOKEN_EXPIRE_MINUTES) -> tuple:
    """
    Create a JWT access token with expiration and a unique ID (jti).

    Args:
        data (dict): Payload data to include in the token.
        expires_delta (str): Token expiration time in minutes. Defaults to settings value.

    Returns:
        tuple: (encoded_jwt (str), jti (str))
            encoded_jwt - The generated JWT token.
            jti - A unique identifier for the token.
    """
    try:
        to_encode = data.copy()
        expire = datetime.now() + timedelta(minutes=int(expires_delta))
        jti = str(uuid.uuid4())
        to_encode.update({'exp': int(expire.timestamp()), 'jti': jti})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f'Access token created with jti {jti}')
        return encoded_jwt, jti
    except Exception as e:
        logger.critical(f'Failed to create access token: {e}')
        raise HTTPException(status_code=500, detail=f'Token creation failed: {str(e)}')


async def verify_token(token: str, redis) -> dict:
    """
    Verify and decode a JWT token, ensuring it has not been revoked.

    Args:
        token (str): The JWT access token to verify.
        redis: Redis connection to check token blacklist.

    Returns:
        dict: The decoded token payload.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get('jti')
        if await redis.get(f'blacklist:{jti}'):
            logger.warning(f'Revoked token used: jti {jti}')
            raise HTTPException(status_code=401, detail='Token revoked')
        logger.info(f'Token verified: jti {jti}')
        return payload
    except JWTError:
        logger.warning(f'Invalid token detected')
        raise HTTPException(status_code=401, detail='Invalid token')


async def verify_secret(secret: str, hashed: str) -> bool:
    """
    Verify that a secret matches its hashed value.

    Args:
        secret (str): The plain secret.
        hashed (str): The hashed secret stored in the database.

    Returns:
        bool: True if secret match, False otherwise.
    """
    result = await asyncio.to_thread(bcrypt.checkpw, secret.encode('utf-8'), hashed.encode('utf-8'))
    logger.info(f'Password verification result: {result}')
    return result


async def hash_secret(secret: str) -> str:
    """
    Hash any secret (password, refresh token, etc.) using bcrypt.

    Args:
        secret (str): Any secret (password, refresh token, etc.).

    Returns:
        str: The bcrypt-hashed secret.
    """
    try:
        salt = await asyncio.to_thread(bcrypt.gensalt)
        hashed = await asyncio.to_thread(bcrypt.hashpw, secret.encode('utf-8'), salt)
        logger.info('Secret hashed successfully')
        return hashed.decode('utf-8')
    except Exception as e:
        logger.critical(f'Failed to hash secret: {e}')
        raise HTTPException(status_code=500, detail=f'Secret hashing failed: {str(e)}')


async def create_email_token(user_id: int, redis, expire_minutes: str = EMAIL_TOKEN_EXPIRE_MINUTES) -> str:
    """
    Create a temporary email verification token.

    Args:
        user_id (int): The user ID associated with the token.
        redis: Redis connection for temporary storage.
        expire_minutes (str, optional): Token expiration in minutes. Defaults to settings value.

    Returns:
        str: The generated verification token.
    """
    try:
        token = token_urlsafe(32)
        ttl = timedelta(minutes=int(expire_minutes))
        await redis.setex(f'verification:{token}', ttl, user_id)
        logger.info(f'Email verification token created for user ID {user_id}')
        return token
    except Exception as e:
        logger.critical(f'Failed to create email token for user ID {user_id}: {e}')
        raise
