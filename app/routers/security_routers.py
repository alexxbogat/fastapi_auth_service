import logging
from fastapi import Depends, APIRouter, HTTPException

from app.routers.user_routers import get_current_user
from app.schemas import ResponseModel, ShowUser, RefreshTokenRequest
from app.security import create_access_token, create_refresh_token, validate_refresh_token
from app.services.redis_service import get_redis

logger = logging.getLogger()
token_router = APIRouter(prefix='/token', tags=['Token'])


@token_router.post('/refresh-token',
                   summary='Refresh access and refresh tokens',
                   response_model=ResponseModel)
async def refresh_token(payload: RefreshTokenRequest,
                        redis=Depends(get_redis),
                        current_user=Depends(get_current_user)):
    """
    Refresh the access and refresh tokens for the currently authenticated user.

    Args:
        payload (RefreshTokenRequest): Contains the current refresh token.
        redis: Async Redis client dependency for storing and validating refresh tokens.
        current_user: Current authenticated user extracted via dependency.
    """
    user, _ = current_user
    logger.info(f'User {user.id} requested token refresh')
    try:
        await validate_refresh_token(user, payload.refresh_token, redis)
        new_access, _ = create_access_token({'sub': str(user.email)})
        new_refresh = await create_refresh_token(user, redis)
        logger.info(f'User {user.id} successfully refreshed tokens')
        return ResponseModel(
            success=True,
            message='Tokens updated',
            access_token=new_access,
            refresh_token=new_refresh,
            data=ShowUser.model_validate(user).model_dump()
        )
    except Exception as e:
        logger.warning(f'Unexpected error during token refresh for user {user.id}: {e}', exc_info=True)
        raise HTTPException(status_code=500, detail='Internal server error')
