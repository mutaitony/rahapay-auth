import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional

# Configuration - In production, these should be loaded from environment variables
SECRET_KEY = "YOUR_SUPER_SECRET_KEY_RAHAPAY_FINTECH_KEEP_IT_SAFE" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15 # Short lifespan for security
REFRESH_TOKEN_EXPIRE_DAYS = 7 # Longer lifespan for refresh tokens

def hash_secret(secret: str) -> str:
    """Hashes a raw password or pin string using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(secret.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_secret(plain_secret: str, hashed_secret: str) -> bool:
    """Verifies a plain text secret against its stored hash."""
    return bcrypt.checkpw(plain_secret.encode('utf-8'), hashed_secret.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generates a securely signed JWT access token for the client architecture."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# NEW: Generates the refresh token
def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# NEW: Safely decodes and validates a token
def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None # Token has expired
    except jwt.InvalidTokenError:
        return None # Token is malformed or invalid