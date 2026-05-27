
from fastapi import FastAPI, HTTPException, status, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer # NEW: Extracts token from headers
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from contextlib import asynccontextmanager

from database import engine, Base, get_db
from models import User
from schemas import UserRegisterIn, UserLoginIn, TokenResponse, RefreshTokenIn
from security import hash_secret, verify_secret, create_access_token, create_refresh_token, verify_token
from middleware import get_current_user


users = APIRouter(
    prefix="/api/v1",
    tags=["Authentication API v1"] # Groups them together visually in /docs
)

@users.get("/users/me")
async def get_my_profile(current_user: User = Depends(get_current_user)):
    """
    Example of a protected route. Notice how we just add:
    `current_user: User = Depends(get_current_user)` 
    and FastAPI handles all the security automatically!
    """
    return {
        "id": current_user.id,
        "full_name": current_user.full_name,
        "user_id": current_user.user_id,
        "email": current_user.email,
        "account_type": current_user.account_type,
        "phone_number": current_user.phone_number,
        "country": current_user.country
    }