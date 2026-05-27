from fastapi import FastAPI, HTTPException, status, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer # NEW: Extracts token from headers
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import engine, Base, get_db
from models import User
from schemas import UserRegisterIn, UserLoginIn, TokenResponse, RefreshTokenIn, PinLoginIn
from security import hash_secret, verify_secret, create_access_token, create_refresh_token, verify_token
from middleware import get_current_user

auth_router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication API v1"] # Groups them together visually in /docs
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

    new_user = User(
        account_type=payload.account_type,
        full_name=payload.full_name,
        email=payload.email,
        country=payload.country,
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

    token_claims = {
        "sub": new_user.email,
        "user_id": new_user.id,
        "type": "access",
        "account_type": new_user.account_type
    }
    
    # Generate BOTH tokens
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": new_user.email, "type": "refresh"})
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }


@auth_router.post("/login", response_model=TokenResponse)
async def login_user(payload: UserLoginIn, db: AsyncSession = Depends(get_db)):
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user:
        is_valid = verify_secret(plain_secret=payload.password, hashed_secret=user.hashed_password)
        if is_valid:
            token_claims = {
                "sub": user.email,
                "user_id": user.id,
                "account_type": user.account_type,
                "type": "access"
            }
            
            # Generate BOTH tokens
            access_token = create_access_token(data=token_claims)
            refresh_token = create_refresh_token(data={"sub": user.email, "type": "refresh"})
            
            return {
                "access_token": access_token, 
                "refresh_token": refresh_token, 
                "token_type": "bearer"
            }
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password combination."
    )


# =======================================================================
# NEW: REFRESH TOKEN ENDPOINT
# =======================================================================
@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(payload: RefreshTokenIn, db: AsyncSession = Depends(get_db)):
    """
    Takes a valid refresh token and returns a fresh pair of access/refresh tokens.
    """
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

    # 2. Verify the user still exists in the database
    query = select(User).where(User.email == email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer active or does not exist."
        )
        
    # 3. Generate a new token pair
    new_claims = {
        "sub": user.email,
        "user_id": user.id,
        "account_type": user.account_type,
        "type": "access"
    }
    
    new_access_token = create_access_token(data=new_claims)
    new_refresh_token = create_refresh_token(data={"sub": user.email, "type": "refresh"})
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }
    
# =======================================================================
# NEW: LOGOUT ENDPOINT
# =======================================================================
@auth_router.post("/logout", status_code=status.HTTP_200_OK)
async def logout_user(current_user: User = Depends(get_current_user)):
    """
    Stateless logout endpoint. 
    Requires the client to pass a valid Bearer token to access it.
    """
    # NOTE: Because JWTs are stateless, actual logout happens on the Flutter app
    # by deleting the tokens from FlutterSecureStorage.
    # If you implement Redis later, you would add the token to a blacklist here.
    
    print(f"🔒 User {current_user.email} initiated logout sequence.")
    
    return {
        "message": "Successfully logged out. Please drop the tokens from device storage.",
        "user": current_user.email
    }

# =======================================================================
# NEW: QUICK PIN LOGIN ENDPOINT
# =======================================================================
@auth_router.post("/login/pin", response_model=TokenResponse)
async def login_with_pin(payload: PinLoginIn, db: AsyncSession = Depends(get_db)):
    """
    Authenticates a returning user via their 4-digit security PIN.
    """
    # 1. Look up the user by email
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    # 2. Verify existence and active status
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found or inactive."
        )

    # 3. Verify the PIN cryptographically
    is_valid_pin = verify_secret(plain_secret=payload.pin, hashed_secret=user.hashed_pin)
    
    if not is_valid_pin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect PIN."
        )

    # 4. Generate fresh token pair upon successful PIN entry
    token_claims = {
        "sub": user.email,
        "user_id": user.user_id, # Safely exposing the UUID instead of internal ID
        "account_type": user.account_type
    }
    
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": user.email})
    
    print(f"🔓 User {user.email} successfully logged in via PIN.")
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }