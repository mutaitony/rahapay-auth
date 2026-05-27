import uuid
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    
    user_id = Column(
        String(36), 
        default=lambda: str(uuid.uuid4()), 
        unique=True, 
        index=True, 
        nullable=False
    )
    
    # FIXED: Added explicit VARCHAR lengths required by the MySQL storage engine
    account_type = Column(String(50), nullable=False)  # e.g., "Personal", "Business"
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    country = Column(String(100), nullable=False)
    document_type = Column(String(100), nullable=False) # e.g., "National ID", "Passport"
    phone_number = Column(String(30), nullable=False)   # Protects formatting/long international codes
    dob = Column(String(20), nullable=False)            # e.g., "DD/MM/YYYY"
    
    # Bcrypt produces a 60-character string, but 255 gives your security layer buffer room
    hashed_pin = Column(String(255), nullable=False) 
    hashed_password = Column(String(255), nullable=True) 
    
    # Image storage locations can occasionally have exceptionally long system cache paths
    id_image_path = Column(String(512), nullable=True)
    selfie_image_path = Column(String(512), nullable=True)
    
    is_active = Column(Boolean, default=True)
    
    # FIXED: Removed timezone=True because MySQL DATETIME columns do not support timezones natively
    created_at = Column(DateTime, server_default=func.now())