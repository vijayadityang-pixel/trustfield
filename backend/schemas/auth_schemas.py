"""
TrustField - Auth Schemas
Pydantic models for login requests and token responses.
"""

from pydantic import BaseModel, ConfigDict, EmailStr

from db.models import UserRole


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: str | None = None
    role: UserRole
    is_active: bool

    class Config:
        from_attributes = True