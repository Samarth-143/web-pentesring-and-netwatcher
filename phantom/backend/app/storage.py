import httpx
import time
from app.core.config import settings

SUPABASE_URL = settings.supabase_url
SUPABASE_KEY = settings.supabase_key
BUCKET = settings.supabase_bucket


def _headers():
    return {
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "apikey": SUPABASE_KEY,
    }


async def upload_pdf(username: str, filename: str, pdf_bytes: bytes) -> str:
    """Upload a PDF to Supabase Storage under {username}/{filename}. Returns the storage path."""
    path = f"{username}/{filename}"
    url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{path}"

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            headers=_headers(),
            content=pdf_bytes,
            params={"upsert": "true"},
            timeout=30,
        )
        if resp.status_code not in (200, 201):
            raise Exception(f"Supabase upload failed ({resp.status_code}): {resp.text}")

    return path


async def get_signed_url(storage_path: str, expires: int = 3600) -> str:
    """Get a signed URL for a stored file. Default expiry: 1 hour."""
    url = f"{SUPABASE_URL}/storage/v1/object/sign/{BUCKET}/{storage_path}"

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            headers=_headers(),
            json={"expiresIn": expires},
            timeout=15,
        )
        if resp.status_code != 200:
            raise Exception(f"Supabase sign URL failed ({resp.status_code}): {resp.text}")
        data = resp.json()
        signed_url = data.get("signedURL") or data.get("signed_url", "")
        if not signed_url:
            raise Exception(f"No signedURL in response: {data}")
        return f"{SUPABASE_URL}/storage/v1/{signed_url}"


async def delete_file(storage_path: str) -> bool:
    """Delete a file from Supabase Storage."""
    url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET}/{storage_path}"

    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            url,
            headers=_headers(),
            timeout=15,
        )
        return resp.status_code in (200, 204)


async def list_user_files(username: str) -> list[dict]:
    """List all files in a user's folder. Returns list of {name, id, metadata}."""
    url = f"{SUPABASE_URL}/storage/v1/object/list/{BUCKET}"

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            headers=_headers(),
            json={"prefix": f"{username}/", "limit": 100, "offset": 0, "sortBy": {"column": "created_at", "order": "desc"}},
            timeout=15,
        )
        if resp.status_code != 200:
            raise Exception(f"Supabase list failed ({resp.status_code}): {resp.text}")
        return resp.json()
