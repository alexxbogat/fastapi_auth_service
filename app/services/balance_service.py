import logging
from decimal import Decimal

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from settings import ADD_MONEY

logger = logging.getLogger()


def has_names(user: User) -> bool:
    """Check if the user has both first name and last name."""
    return bool(user.first_name and user.last_name)


def get_balance(user: User) -> Decimal:
    """Retrieve the current balance of a user."""
    if not has_names(user):
        logger.warning(f'Cannot get balance: missing names for user {user.email}')
        raise ValueError("User must provide first name and last name.")
    logger.info(f'Retrieved balance for user {user.email}: {user.balance}')
    return user.balance


async def add_balance(user: User, db: AsyncSession, money: Decimal = ADD_MONEY) -> User:
    """
    Add a specified amount to the user's balance if the user has first and last name.

    Args:
        user (User): The user instance to update.
        db (AsyncSession): Database session for committing changes.
        money (Decimal, optional): Amount to add. Defaults to ADD_MONEY.

    Returns:
        User: Updated user instance with new balance.
    """
    if not has_names(user):
        logger.warning(f'Cannot add balance: missing names for user {user.email}')
        return user
    user.balance += Decimal(money)
    db.add(user)
    logger.info(f'Adding {money} to balance of user {user.email}. New balance: {user.balance}')
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'Balance successfully updated for user {user.email}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while adding balance for user {user.email}: {e}')
        raise


async def withdraw_balance(user: User, money: Decimal, db: AsyncSession) -> User:
    """
    Withdraw a specified amount from the user's balance.

    Args:
        user (User): The user instance to update.
        money (Decimal): Amount to withdraw.
        db (AsyncSession): Database session for committing changes.

    Returns:
        User: Updated user instance with new balance.
    """
    if not has_names(user):
        logger.warning(f'Cannot withdraw balance: missing names for user {user.email}')
        raise ValueError('User must provide first name and last name.')
    if user.balance - money < 0:
        logger.warning(f'Attempt to withdraw {money} exceeds balance for user {user.email}')
        raise ValueError('Balance cannot be negative')
    user.balance -= Decimal(money)
    db.add(user)
    logger.info(f'Withdrawing {money} from user {user.email}. New balance: {user.balance}')
    try:
        await db.commit()
        await db.refresh(user)
        logger.info(f'Balance successfully updated for user {user.email}')
        return user
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f'DB error while withdrawing balance for user {user.email}: {e}')
        raise
