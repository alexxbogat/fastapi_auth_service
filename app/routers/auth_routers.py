import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.schemas import CreateUser, ResponseModel, ShowUser, LoginUser
from app.security import (
    create_email_token,
    verify_secret,
    create_access_token,
    create_refresh_token
)
from app.send_email import send_verification_email
from app.services.balance_service import add_balance
from app.services.redis_service import get_redis
from app.services.user_service import (
    create_user,
    UserAlreadyExistsError,
    get_user_by_email,
    set_user_online,
    get_current_user,
    set_user_offline
)
from app.session import get_db_session

logger = logging.getLogger()

auth_router = APIRouter(prefix='', tags=['Auth'])


@auth_router.post('/register')
async def register(user: CreateUser, redis=Depends(get_redis), db: AsyncSession = Depends(get_db_session)):
    """
    Register a new user.

    Args:
        user (CreateUser): User registration data containing email and password.
        redis (Redis): Redis instance.
        db (AsyncSession): Database session (injected)

    Returns:
        ResponseModel: Success message with created user details.

    """
    logger.info(f'Attempting to register user with email: {user.email}')
    try:
        user = await create_user(user.email, user.password.get_secret_value(), db)
        token = await create_email_token(user.id, redis)
        await send_verification_email(user.email, token)
        logger.info(f'User {user.email} registered successfully. Verification email sent.')
        return ResponseModel(
            success=True,
            message='Please check your email and confirm your email',
            data=ShowUser.model_validate(user).model_dump()
        )
    except UserAlreadyExistsError:
        logger.warning(f'Registration failed: user {user.email} already exists')
        raise HTTPException(status_code=409, detail='User already exists')


@auth_router.get('/verify', response_model=ResponseModel, summary='Verify user account')
async def verify_account(token: str, redis=Depends(get_redis), db: AsyncSession = Depends(get_db_session)):
    """
    Verify a newly registered user account using a one-time token.

    Args:
        token (str): Verification token provided in the URL.
        redis: Redis connection (used to store temporary verification tokens).
        db (AsyncSession): SQLAlchemy async database session.

    Returns:
        ResponseModel: Success message and the verified user data.
    """
    logger.info(f'Attempting to verify account with token: {token}')
    key = f'verification:{token}'
    user_id = await redis.get(key)

    if not user_id:
        logger.warning('Verification failed: Invalid or expired token')
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = await db.get(User, int(user_id))
    user.is_deleted = False
    db.add(user)
    await db.commit()
    await redis.delete(key)
    logger.info(f'User {user.email} verified successfully')
    return ResponseModel(
        success=True,
        message='Account verified successfully!',
        data=ShowUser.model_validate(user).model_dump()
    )


@auth_router.post('/login')
async def login(unauth_user: LoginUser,
                redis=Depends(get_redis),
                db: AsyncSession = Depends(get_db_session)):
    """
    Authenticate a user and issue a JWT token.

    Args:
        unauth_user (LoginUser): User login credentials (email, password).
        redis (Redis): Redis instance to store tokens.
        db (AsyncSession): Database session (injected)

    Returns:
        ResponseModel: Success message with user data and access token.
    """
    logger.info(f'Login attempt for email: {unauth_user.email}')
    user = await get_user_by_email(unauth_user.email, db)
    if user.is_blocked:
        logger.warning(f'Blocked user {user.email} attempted to log in')
        raise HTTPException(status_code=403, detail='Your account is blocked.')
    if not user or user.is_deleted != False:
        logger.warning(f'Login failed: User {unauth_user.email} is not registered')
        raise HTTPException(status_code=401, detail='User is not registered')
    password_correct = await verify_secret(unauth_user.password.get_secret_value(), user.password)
    if not password_correct:
        logger.warning(f'Login failed: Incorrect password for {unauth_user.email}')
        raise HTTPException(status_code=401, detail='Incorrect password')
    access_token, jti = create_access_token({'sub': str(user.email)})
    refresh_token = await create_refresh_token(user, redis)
    await set_user_online(user, db)
    if not user.role.value == 'admin':
        user = await add_balance(user, db)
    logger.info(f'User {user.email} logged in successfully')
    return ResponseModel(
        success=True,
        message='User is authorized',
        access_token=access_token,
        refresh_token=refresh_token,
        data=ShowUser.model_validate(user).model_dump()
    )


@auth_router.post('/logout')
async def logout(current_user=Depends(get_current_user),
                 redis=Depends(get_redis),
                 db: AsyncSession = Depends(get_db_session)):
    """
    Logout the currently authenticated user by blacklisting the JWT token.

    Args:
        current_user (User, dict): Current authenticated user and JWT payload.
        redis (Redis): Redis instance to store blacklisted tokens.
        db (AsyncSession): Database session (injected).

    Returns:
        ResponseModel: Success message confirming logout.
    """
    user, payload = current_user
    logger.info(f'Logout attempt by user: {user.email}')
    jti = payload.get('jti')
    exp = payload.get('exp')
    ttl = max(0, exp - int(datetime.now().timestamp()))
    await redis.setex(f'blacklist:{jti}', ttl, 'true')
    try:
        await set_user_offline(user, db)
        await redis.delete(f'refresh:{user.id}')
        logger.info(f'User {user.email} logged out successfully')
        return ResponseModel(
            success=True,
            message='Logged out successfully'
        )
    except Exception as e:
        await db.rollback()
        logger.error(f'Logout failed for user {user.email}: {str(e)}')
        raise HTTPException(status_code=500, detail=f'Logout failed: {str(e)}')
