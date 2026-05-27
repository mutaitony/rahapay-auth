from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

# Format: mysql+aiomysql://user:password@localhost:3306/database_name
# Adjust 'root' and 'admin' to match your local MySQL credentials
DATABASE_URL = "mysql+aiomysql://root:@localhost:3306/rahapay_auth"

engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

# Base class for database tables
class Base(DeclarativeBase):
    pass

# FastAPI Dependency to fetch DB sessions dynamically
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()