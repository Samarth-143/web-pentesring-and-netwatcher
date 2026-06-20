import os
import ssl as _ssl
import logging
import asyncpg  # noqa: F401 — ensures the asyncpg dialect is registered with SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

logger = logging.getLogger("phantom.database")

DATABASE_URL = os.getenv("DATABASE_URL", "")

engine = None
async_session = None
_using_fallback = False

if DATABASE_URL:
    _engine_kwargs = {"echo": False, "pool_pre_ping": True}
    if "supabase.co" in DATABASE_URL:
        _ssl_ctx = _ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = _ssl.CERT_NONE
        _engine_kwargs["connect_args"] = {"ssl": _ssl_ctx}
    engine = create_async_engine(DATABASE_URL, **_engine_kwargs)
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

Base = declarative_base()


async def get_db():
    if not async_session:
        raise Exception("DATABASE_URL not configured")
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    global engine, async_session, _using_fallback

    if engine:
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Connected to PostgreSQL")
            return
        except Exception as e:
            logger.warning(f"PostgreSQL unreachable: {e}")
            logger.info("Falling back to SQLite (data will not persist across restarts)")

    # SQLite fallback for HF free tier
    _using_fallback = True
    engine = create_async_engine("sqlite+aiosqlite:///./phantom_hf.db", echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Using SQLite fallback")
