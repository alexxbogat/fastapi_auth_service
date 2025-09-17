import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.services.balance_service import has_names
from app.schemas import ShowUser, ResponseModel, UserChangePassword, UpdateUser, ShowUpdateUser
from app.services.redis_service import get_redis
from app.services.user_service import change_password, update_user, get_current_user
from app.security import verify_secret, hash_secret
from app.session import get_db_session

logger = logging.getLogger()
router = APIRouter(prefix='/user', tags=['User'])


@router.post('/change-password')
async def change_pass(payload: UserChangePassword,
                      current_user=Depends(get_current_user),
                      db: AsyncSession = Depends(get_db_session)):
    """
    Change the password for the currently authenticated user.

    Args:
        payload (UserChangePassword): Old and new password.
        current_user (User): User extracted from the JWT token.
        db (AsyncSession): Database session (injected).

    Returns:
        ResponseModel: Success message with updated user data.
    """
    user, _ = current_user
    logger.info(f'User {user.email} attempts to change password')
    password_ok = await verify_secret(payload.old_password.get_secret_value(), user.password)
    if not password_ok:
        logger.warning(f'User {user.email} provided incorrect old password')
        raise HTTPException(status_code=401, detail='Incorrect old password')
    new_hashed_password = await hash_secret(payload.new_password.get_secret_value())
    await change_password(user.email, new_hashed_password, db)
    logger.info(f'User {user.email} successfully changed password')
    return ResponseModel(
        success=True,
        message='The user has changed the password',
        data=ShowUser.model_validate(user).model_dump()
    )


@router.put('/update', response_model=ShowUpdateUser, summary='Update current user profile')
async def update_current_user(request: UpdateUser,
                              current_user=Depends(get_current_user),
                              db: AsyncSession = Depends(get_db_session)):
    """
    Update the profile details of the currently authenticated user.

    Args:
        request (UpdateUser): New user data (first_name, last_name, email, balance).
        current_user (User): Current authenticated user.
        db (AsyncSession): Database session (injected).

    Returns:
        ShowUpdateUser: Updated user profile.
    """
    user, _ = current_user
    logger.info(f'User {user.email} attempts to update profile')
    if user.balance > 0 and request.role == 'admin':
        logger.warning(f'User {user.email} cannot change role to admin with positive balance ({user.balance})')
        raise HTTPException(status_code=422,
                            detail=f'Cannot change role to admin with positive balance ({user.balance}). '
                                   f'Please set balance to 0.00 or withdraw funds first.'
                            )
    user = await update_user(user, request, db)
    logger.info(f'User {user.id} successfully updated profile')
    return user


@router.put('/delete', response_model=ResponseModel, summary='Delete current user profile')
async def delete_current_user(current_user=Depends(get_current_user),
                              redis=Depends(get_redis),
                              db: AsyncSession = Depends(get_db_session)):
    """
    Soft-delete the currently authenticated user.

    Args:
        current_user: The authenticated user (extracted via dependency).
        db (AsyncSession): Active database session.

    Returns:
        ResponseModel: Success message after soft-delete.
    """
    user, _ = current_user
    logger.info(f'User {user.id} attempts to delete profile')
    if user.role.value != 'user':
        logger.warning(f'User {user.id} tried to delete profile without permission')
        raise HTTPException(status_code=403, detail='You do not have permission to delete the profile')
    try:
        user.is_deleted = True
        await redis.delete(f'refresh:{user.id}')
        logger.info(f'Refresh token for user {user.id} deleted from Redis')
        await db.commit()
        logger.info(f'User {user.id} profile deleted successfully')
        return ResponseModel(
            success=True,
            message='Profile deleted successfully'
        )
    except SQLAlchemyError as e:
        await db.rollback()
        logger.warning(f'Database error while deleting profile for user {user.id}: {str(e)}', exc_info=True)
        raise HTTPException(status_code=500, detail=f'Delete failed: {str(e)}')


@router.get('', response_model=ShowUpdateUser, summary='Get current user profile')
async def get_current_user_profile(current_user=Depends(get_current_user)):
    """
    Retrieve the profile information of the currently authenticated user.

    Args:
        current_user (User): Current authenticated user.

    Raises:
        HTTPException: If the user does not have both first_name and last_name.

    Returns:
        ShowUpdateUser: User profile details.
    """
    user, _ = current_user
    logger.info(f'User {user.id} requests profile info')
    if not has_names(user):
        logger.warning(f'User {user.id} does not have full name set')
        raise HTTPException(status_code=400, detail='User must provide first name and last name.')
    return user
