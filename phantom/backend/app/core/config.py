from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = "postgresql+asyncpg://localhost:5432/phantom"
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    jwt_secret: str = "" # Uses fallback securely if not provided
    
    # Supabase Storage
    supabase_url: str = ""
    supabase_key: str = ""
    supabase_bucket: str = "scans"
    
    # OAuth configuration
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    frontend_url: str = "http://localhost:5173"

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
