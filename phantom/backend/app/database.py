import os
import ssl as _ssl
import logging
import asyncpg  # noqa: F401 — ensures the asyncpg dialect is registered with SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

logger = logging.getLogger("phantom.database")

DATABASE_URL = os.getenv("DATABASE_URL", "")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

engine = None
async_session = None
_using_fallback = False
_using_supabase_rest = False

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
    global _using_supabase_rest
    
    # If using Supabase REST, return the REST adapter session
    if _using_supabase_rest:
        from app.supabase_db import get_supabase_session
        session = await get_supabase_session()
        yield session
        return
    
    if not async_session:
        raise Exception("DATABASE_URL not configured")
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    global engine, async_session, _using_fallback, _using_supabase_rest

    if engine:
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Connected to PostgreSQL")
            return
        except Exception as e:
            logger.warning(f"PostgreSQL unreachable: {e}")

    # Try Supabase REST API (works on HF free tier — HTTPS port 443)
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            from app.supabase_db import SupabaseSession, SUPABASE_URL as _url, SUPABASE_KEY as _key
            if _url and _key:
                logger.info("PostgreSQL unreachable — using Supabase REST API (HTTPS)")
                _using_supabase_rest = True
                _using_fallback = True
                
                # Verify connection by making a simple request
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{_url}/rest/v1/users?select=id&limit=1",
                        headers={"apikey": _key, "Authorization": f"Bearer {_key}"},
                        timeout=10.0,
                    )
                    resp.raise_for_status()
                    logger.info("Supabase REST API connection verified")
                return
        except Exception as e:
            logger.warning(f"Supabase REST API unavailable: {e}")

    # SQLite fallback for HF free tier (last resort)
    logger.info("Falling back to SQLite (data will not persist across restarts)")
    _using_fallback = True
    engine = create_async_engine("sqlite+aiosqlite:///./phantom_hf.db", echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
