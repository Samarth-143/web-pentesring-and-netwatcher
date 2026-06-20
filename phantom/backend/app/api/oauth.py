import os
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError

from app.database import get_db
from app import models
from app.auth import create_access_token
from app.core.config import settings
import secrets

router = APIRouter(prefix="/auth", tags=["OAuth"])

oauth = OAuth()
configured_providers = set()

# Setup Google
if settings.google_client_id and settings.google_client_secret:
    oauth.register(
        name='google',
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    configured_providers.add('google')

# Setup GitHub
if settings.github_client_id and settings.github_client_secret:
    oauth.register(
        name='github',
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )
    configured_providers.add('github')


@router.get("/oauth/config")
async def oauth_config():
    return {
        "google": "google" in configured_providers,
        "github": "github" in configured_providers,
    }

@router.get("/{provider}/login")
async def login_via_oauth(provider: str, request: Request):
    if provider not in ['google', 'github']:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    
    client = oauth.create_client(provider)
    if not client:
        raise HTTPException(status_code=400, detail=f"{provider.capitalize()} OAuth is not configured")
        
    # Standardize the redirect URI to point exactly to our backend callback
    redirect_uri = request.url_for('oauth_callback', provider=provider)
    return await client.authorize_redirect(request, redirect_uri)

@router.get("/{provider}/callback", include_in_schema=False)
async def oauth_callback(provider: str, request: Request, db: AsyncSession = Depends(get_db)):
    client = oauth.create_client(provider)
    if not client:
        raise HTTPException(status_code=400, detail="OAuth client not configured")
        
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as error:
        raise HTTPException(status_code=400, detail=f"OAuth Error: {error.error}")
        
    user_info = None
    email = None
    provider_id = None
    username = None
    
    if provider == 'google':
        user_info = token.get('userinfo')
        if not user_info:
            raise HTTPException(status_code=400, detail="Could not fetch Google user info")
        email = user_info.get('email')
        provider_id = user_info.get('sub')
        username = user_info.get('name') or email.split('@')[0]
        
    elif provider == 'github':
        resp = await client.get('user', token=token)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Could not fetch GitHub user info")
        user_info = resp.json()
        
        provider_id = str(user_info.get('id'))
        username = user_info.get('login')
        email = user_info.get('email')
        
        # GitHub emails might be private, so we need a separate call
        if not email:
            emails_resp = await client.get('user/emails', token=token)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                primary = next((e for e in emails if e.get('primary')), None)
                if primary:
                    email = primary.get('email')

    if not provider_id:
        raise HTTPException(status_code=400, detail="Failed to retrieve provider ID")
        
    if not username:
        username = f"{provider}_{provider_id}"

    # Check if user exists
    if provider == 'google':
        query = select(models.User).where(models.User.google_id == provider_id)
    else:
        query = select(models.User).where(models.User.github_id == provider_id)
        
    result = await db.execute(query)
    user = result.scalars().first()
    
    if not user and email:
        # Try finding by email
        result = await db.execute(select(models.User).where(models.User.email == email))
        user = result.scalars().first()
        
    if not user:
        # Create new user
        # Ensure username is unique
        base_username = username
        counter = 1
        while True:
            exist_check = await db.execute(select(models.User).where(models.User.username == username))
            if not exist_check.scalars().first():
                break
            username = f"{base_username}{counter}"
            counter += 1
            
        user = models.User(
            username=username,
            email=email,
            role="user",
            hashed_password=None # Nullable for OAuth users
        )
        if provider == 'google':
            user.google_id = provider_id
        else:
            user.github_id = provider_id
            
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        # Update existing user's OAuth IDs if missing
        changed = False
        if provider == 'google' and not user.google_id:
            user.google_id = provider_id
            changed = True
        elif provider == 'github' and not user.github_id:
            user.github_id = provider_id
            changed = True
            
        if not user.email and email:
            user.email = email
            changed = True
            
        if changed:
            await db.commit()
            
    # Generate JWT
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    
    # Redirect to frontend with token
    redirect_url = f"{settings.frontend_url}?token={access_token}"
    return RedirectResponse(url=redirect_url)
