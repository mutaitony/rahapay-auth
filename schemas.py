from pydantic import BaseModel, EmailStr, Field
from typing import Optional

# Matches the payload from your MasterFlowScreen
class UserRegisterIn(BaseModel):
    account_type: str
    full_name: str
    email: EmailStr
    country: str
    document_type: str
    phone_number: str
    dob: str
    pin: str = Field(..., min_length=4, max_length=4)  # e.g., "Personal", "Business"   
    password: str
    id_image_path: Optional[str] = None
    selfie_image_path: Optional[str] = None

# Matches the payload from your SignInScreen
class UserLoginIn(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = True

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str # NEW: Added refresh token to the response
    token_type: str = "bearer"

class RefreshTokenIn(BaseModel):
    refresh_token: str # NEW: Schema for the refresh endpoint
    
class PinLoginIn(BaseModel):
    email: EmailStr
    pin: str = Field(..., min_length=4, max_length=4, description="User's 4-digit quick access PIN")