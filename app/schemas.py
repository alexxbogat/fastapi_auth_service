from pydantic import BaseModel, EmailStr, SecretStr, Field, field_validator, ConfigDict
from decimal import Decimal
from datetime import datetime
from enum import Enum


def _check_password(password: str) -> None:
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(not c.isalnum() for c in password):
        raise ValueError("Password must contain at least one special character")
    if any(c in '@\"\'<>' for c in password):
        raise ValueError('Password contains forbidden characters: @ " \' < >')


class CreateUser(BaseModel):
    email: EmailStr
    password: SecretStr = Field(max_length=24, min_length=8, examples=['A4578Text325_!'])

    @field_validator("password", mode='after')
    @classmethod
    def check_passwords_match(cls, value: SecretStr) -> SecretStr:
        _check_password(value.get_secret_value())
        return value


class ShowUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None
    balance: Decimal


class LoginUser(BaseModel):
    email: EmailStr
    password: SecretStr = Field(max_length=24, min_length=8)


class UserChangePassword(BaseModel):
    old_password: SecretStr
    new_password: SecretStr = Field(max_length=24, min_length=8, examples=['A4578Text325_!'])

    @field_validator("new_password", mode='after')
    @classmethod
    def check_passwords_match(cls, value: SecretStr) -> SecretStr:
        _check_password(value.get_secret_value())
        return value


class ResponseModel(BaseModel):
    success: bool
    message: str
    data: dict | None = None
    access_token: str | None = None
    refresh_token: str | None = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class BalanceWithdrawRequest(BaseModel):
    money: Decimal


class RoleEnum(str, Enum):
    user = 'user'
    admin = 'admin'


class UpdateUser(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr | None = None
    role: RoleEnum | None = None
    balance: Decimal | None = None

    @field_validator('balance')
    @classmethod
    def check_admin_balance(cls, v, info):
        if v is not None and info.data.get('role') == RoleEnum.admin and v > 0:
            raise ValueError('Admin cannot have positive balance')
        return v


class ShowUpdateUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    first_name: str
    last_name: str
    created_at: datetime
    updated_at: datetime
    last_activity_at: datetime
    balance: Decimal


class UserSort(BaseModel):
    id: int | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_blocked: bool | None = None
    sort_by: str = 'id'
    sort_type: str = 'asc'

    @field_validator('sort_by', mode='after')
    @classmethod
    def check_sort_by_match(cls, value: str) -> str:
        if value not in ('id', 'balance', 'last_activity_at'):
            raise ValueError(f"Cannot sort by {value}")
        return value.lower()

    @field_validator('sort_type', mode='after')
    @classmethod
    def check_sort_type_match(cls, value: str) -> str:
        if value not in ('asc', 'desc'):
            raise ValueError(f"Invalid sort type {value}")
        return value.lower()


class ShowUserSort(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    first_name: str | None = None
    last_name: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    last_activity_at: datetime
    is_blocked: bool
    block_at: datetime | None = None
    role: RoleEnum
    balance: Decimal


class UserSortResponse(BaseModel):
    users: list[ShowUserSort]


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class BlockUser(BaseModel):
    user_id: int = Field(gt=0)
    is_blocked: bool
