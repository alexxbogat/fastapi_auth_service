import logging
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.routers.user_routers import get_current_user
from app.schemas import ResponseModel, ShowUser, BalanceWithdrawRequest
from app.services.balance_service import get_balance, withdraw_balance
from app.session import get_db_session
from app.routers.user_routers import router

logger = logging.getLogger()


@router.get('/balance',
            response_model=ResponseModel,
            summary='Get user balance')
async def get_user_balance(current_user=Depends(get_current_user)):
    """
    Retrieve the balance of the currently logged-in user.

    Returns:
        ResponseModel: Contains success status, message, and user data including balance.
    """
    user, _ = current_user
    logger.info(f'User {user.id} requested their balance')
    try:
        balance = get_balance(user)
    except ValueError as e:
        logger.warning(f'User {user.id} balance retrieval failed: {e}')
        raise HTTPException(status_code=400, detail=str(e))
    logger.info(f'User {user.id} balance retrieved: {balance}')
    return ResponseModel(
        success=True,
        message=f'Your profile balance {balance}',
        data=ShowUser.model_validate(user).model_dump()
    )


@router.put('/balance',
            response_model=ResponseModel,
            summary='Withdraw money from the user balance')
async def put_user_balance(request: BalanceWithdrawRequest,
                           current_user=Depends(get_current_user),
                           db: AsyncSession = Depends(get_db_session)):
    """
    Withdraw money from the current user's balance.

    Args:
        request (BalanceWithdrawRequest): Amount of money to withdraw.
        current_user (User): Current authenticated user.
        db (AsyncSession): Database session (injected).

    Raises:
        HTTPException: If user does not have names or balance goes negative.

    Returns:
        ResponseModel: Success message with updated user balance.
    """
    user, _ = current_user
    logger.info(f'User {user.id} requested to withdraw {request.money} dollars')
    try:
        user = await withdraw_balance(user, request.money, db)
    except ValueError as e:
        logger.warning(f'User {user.id} withdrawal failed: {e}')
        raise HTTPException(status_code=400, detail=str(e))
    logger.info(f'User {user.id} successfully withdrew {request.money} dollars. New balance: {user.balance}')
    return ResponseModel(
        success=True,
        message=f'{request.money} dollars have been withdrawn from your profile',
        data=ShowUser.model_validate(user).model_dump()
    )
