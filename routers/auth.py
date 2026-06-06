from fastapi import FastAPI, HTTPException, status, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import engine, Base, get_db
from models import User
from schemas import UserRegisterIn, UserLoginIn, TokenResponse, RefreshTokenIn, PinLoginIn
from security import hash_secret, verify_secret, create_access_token, create_refresh_token, verify_token
from middleware import get_current_user

auth_router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication API v1"]
)

@auth_router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegisterIn, db: AsyncSession = Depends(get_db)):
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    secure_pin = hash_secret(payload.pin)
    secure_password = hash_secret(payload.password)

    # UPDATED: Removed account_type and country, added currency!
    new_user = User(
        full_name=payload.full_name,
        email=payload.email,
        currency=payload.currency, 
        document_type=payload.document_type,
        phone_number=payload.phone_number,
        dob=payload.dob,
        hashed_pin=secure_pin,
        hashed_password=secure_password,
        id_image_path=payload.id_image_path,
        selfie_image_path=payload.selfie_image_path
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # UPDATED: Removed account_type from claims
    token_claims = {
        "sub": new_user.email,
        "user_id": str(new_user.id), 
        "type": "access"
    }
    
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": new_user.email, "type": "refresh"})
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer",
        "full_name": new_user.full_name,
        "avatar_url": new_user.selfie_image_path 
    }


@auth_router.post("/login", response_model=TokenResponse)
async def login_user(payload: UserLoginIn, db: AsyncSession = Depends(get_db)):
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user:
        is_valid = verify_secret(plain_secret=payload.password, hashed_secret=user.hashed_password)
        if is_valid:
            # UPDATED: Removed account_type
            token_claims = {
                "sub": user.email,
                "user_id": str(user.id),
                "type": "access"
            }
            
            access_token = create_access_token(data=token_claims)
            refresh_token = create_refresh_token(data={"sub": user.email, "type": "refresh"})
            
            return {
                "access_token": access_token, 
                "refresh_token": refresh_token, 
                "token_type": "bearer",
                "full_name": user.full_name,
                "avatar_url": user.selfie_image_path 
            }
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password combination."
    )


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(payload: RefreshTokenIn, db: AsyncSession = Depends(get_db)):
    token_data = verify_token(payload.refresh_token)
    
    if not token_data or token_data.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token."
        )
        
    email = token_data.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload invalid."
        )

    query = select(User).where(User.email == email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer active or does not exist."
        )
        
    # UPDATED: Removed account_type
    new_claims = {
        "sub": user.email,
        "user_id": str(user.id),
        "type": "access"
    }
    
    new_access_token = create_access_token(data=new_claims)
    new_refresh_token = create_refresh_token(data={"sub": user.email, "type": "refresh"})
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "full_name": user.full_name,
        "avatar_url": user.selfie_image_path 
    }
    

@auth_router.post("/logout", status_code=status.HTTP_200_OK)
async def logout_user(current_user: User = Depends(get_current_user)):
    print(f"🔒 User {current_user.email} initiated logout sequence.")
    return {
        "message": "Successfully logged out. Please drop the tokens from device storage.",
        "user": current_user.email
    }


@auth_router.post("/login/pin", response_model=TokenResponse)
async def login_with_pin(payload: PinLoginIn, db: AsyncSession = Depends(get_db)):
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found or inactive."
        )

    is_valid_pin = verify_secret(plain_secret=payload.pin, hashed_secret=user.hashed_pin)
    
    if not is_valid_pin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect PIN."
        )

    # UPDATED: Removed account_type
    token_claims = {
        "sub": user.email,
        "user_id": str(user.id), 
        "type": "access"
    }
    
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": user.email, "type": "refresh"})
    
    print(f"🔓 User {user.email} successfully logged in via PIN.")
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer",
        "full_name": user.full_name,
        "avatar_url": user.selfie_image_path 
    }