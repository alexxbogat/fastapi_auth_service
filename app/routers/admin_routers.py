import logging
from fastapi import Depends, HTTPException, APIRouter
from sqlalchemy import select, asc, desc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.schemas import UserSort, UserSortResponse, ShowUserSort, BlockUser, ResponseModel, ShowUser
from app.services.admin_service import change_block_status
from app.services.user_service import require_admin
from app.session import get_db_session

logger = logging.getLogger()
admin_router = APIRouter(prefix='/admin', tags=['Admin'])


@admin_router.get('/all-users',
                  response_model=UserSortResponse,
                  summary='Get all users',
                  description='Get all users with filters and sorting.')
async def get_all_users(current_admin: User = Depends(require_admin),
                        params: UserSort = Depends(),
                        db: AsyncSession = Depends(get_db_session)) -> UserSortResponse:
    """
    Retrieve a list of users with optional filtering and sorting.

    Query Parameters:
        id (int, optional): Filter by user ID.
        first_name (str, optional): Filter users by first name.
        last_name (str, optional): Filter users by last name.
        is_blocked (bool, optional): Filter users by blocked status.
        sort_by (str, optional): Field to sort by. Allowed values: 'id', 'balance', 'last_activity_at'.
        sort_type (str, optional): Sorting order. Allowed values: 'asc', 'desc'.
    """
    logger.info(f'Admin {current_admin.id} requested all users with params {params}')
    try:
        search = select(User)

        if params.id is not None:
            search = search.where(User.id == params.id)
        if params.first_name:
            search = search.where(User.first_name.ilike(f'%{params.first_name}%'))
        if params.last_name:
            search = search.where(User.last_name.ilike(f'%{params.last_name}%'))
        if params.is_blocked is not None:
            search = search.where(User.is_blocked == params.is_blocked)
        try:
            sort_col = getattr(User, params.sort_by)
        except AttributeError:
            logger.error(f'Invalid sort_by: {params.sort_by}')
            raise HTTPException(status_code=400, detail=f'Cannot sort by {params.sort_by}')

        search = search.order_by(asc(sort_col) if params.sort_type == 'asc' else desc(sort_col))

        result = await db.execute(search)
        users = result.scalars().all()
        logger.info(f'Admin {current_admin.id} retrieved {len(users)} users')
        return UserSortResponse(users=[
            ShowUserSort.model_validate(u).model_dump() for u in users
        ])
    except HTTPException as e:
        logger.warning(f'Error retrieving users: {e}', exc_info=True)
        raise


@admin_router.put('/user/block-status',
                  response_model=ResponseModel,
                  summary='Block or unblock a user',
                  description='Allows admin to block or unblock a user. Cannot block yourself.')
async def update_block_status(request: BlockUser,
                              current_admin: User = Depends(require_admin),
                              db: AsyncSession = Depends(get_db_session)) -> ResponseModel:
    """
    Block or unblock a user by ID.

    Args:
        request (BlockUser): User ID and new block status.
        current_admin (User): Current admin user (validated).
        db (AsyncSession): Database session.

    Returns:
        ResponseModel: Success message with updated status.
    """
    logger.info(f'Admin {current_admin.id} is changing block status: {request}')
    try:
        user = await change_block_status(request, current_admin, db)
        action = 'blocked' if user.is_blocked else 'unblocked'
        logger.info(f'User {user.id} was {action} by admin {current_admin.id}')
        return ResponseModel(
            success=True,
            message=f'User with id #{user.id} was {action} successfully',
            data=ShowUser.model_validate(user).model_dump()
        )
    except HTTPException as e:
        logger.warning(f'Unexpected error in block status update: {e}', exc_info=True)
        raise


@admin_router.get('/user/delete-status',
                  response_model=UserSortResponse,
                  summary='Get all soft-deleted users',
                  description='Returns a list of users where is_deleted = True.')
async def get_users_del_status(current_admin: User = Depends(require_admin),
                               db: AsyncSession = Depends(get_db_session)) -> UserSortResponse:
    """
    Retrieve all soft-deleted users is_deleted=True.

    Args:
        current_admin (User): Current admin user (validated).
        db (AsyncSession): Database session.

    Returns:
        UserSortResponse: List of soft-deleted users.
    """
    logger.info(f'Admin {current_admin.id} requested soft-deleted users')
    query = select(User).where(User.is_deleted == True)
    try:
        result = await db.execute(query)
        users = result.scalars().all()
    except SQLAlchemyError as e:
        logger.error(f'Database error while fetching soft-deleted users: {e}', exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    logger.info(f'Found {len(users)} soft-deleted users')
    return UserSortResponse(users=[
        ShowUserSort.model_validate(u).model_dump() for u in users
    ])
