"""CAS-SE Authentication Schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128)
    email: EmailStr | None = None
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(pattern="^(admin|uploader|trainer|researcher|auditor)$")


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str | None = None
    username: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    user_id: uuid.UUID
    username: str
    role: str
    email: str | None
    is_active: bool
