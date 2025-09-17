import enum
from datetime import datetime
from decimal import Decimal

from sqlalchemy import String, DateTime, func, Numeric, Boolean, CheckConstraint
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates


class Role(enum.Enum):
    USER = 'user'
    ADMIN = 'admin'


class Base(AsyncAttrs, DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str | None] = mapped_column(String(30), default=None)
    last_name: Mapped[str | None] = mapped_column(String(30), default=None)
    email: Mapped[str] = mapped_column(String, nullable=False, index=True, unique=True)
    password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[Role] = mapped_column(ENUM(Role, name='role', values_callable=lambda x: [e.value for e in x]),
                                       nullable=False,
                                       default=Role.USER.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                        default=None,
                                                        onupdate=func.now())
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                       server_default=func.now(),
                                                       onupdate=func.now())
    balance: Mapped[Decimal] = mapped_column(Numeric(precision=10, scale=2), default=0.00)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    block_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    is_deleted: Mapped[bool | None] = mapped_column(Boolean, default=None)

    __table_args__ = (
        CheckConstraint('balance >= 0.00'),
    )

    @validates('balance')
    def validate_balance(self, key, value):
        if value < 0:
            raise ValueError('Balance cannot be negative')
        return value
