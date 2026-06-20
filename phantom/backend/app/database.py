import os
import ssl as _ssl
import logging
import asyncpg  # noqa: F401 — ensures the asyncpg dialect is registered with SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

logger = logging.getLogger("phantom.database")

DATABASE_URL = os.getenv("DATABASE_URL", "")

_engine_kwargs = {"echo": False, "pool_pre_ping": True}
if DATABASE_URL and "supabase.co" in DATABASE_URL:
    _ssl_ctx = _ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = _ssl.CERT_NONE
    _engine_kwargs["connect_args"] = {"ssl": _ssl_ctx}

engine = create_async_engine(DATABASE_URL, **_engine_kwargs) if DATABASE_URL else None
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession) if engine else None

Base = declarative_base()

_db_ready = False


async def get_db():
    if not async_session:
        raise Exception("DATABASE_URL not configured")
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    global _db_ready
    if not engine:
        logger.warning("DATABASE_URL not set — skipping database init")
        return
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _db_ready = True
        logger.info("Database connected and tables created")
    except Exception as e:
        logger.warning(f"Database unavailable (will retry on first request): {e}")
