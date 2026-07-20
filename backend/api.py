"""
Falsky — AI Flaky Test Trust Layer
FastAPI Backend Server
Refactored to use Supabase SDK instead of psycopg2.
"""

import logging
import os
import secrets
import time
import urllib.parse

import bcrypt
import jwt

from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional

from engine.db import get_client, table, rpc, select, select_one, insert, update, delete, upsert
from engine.trust_engine import (
    process_test_run, get_dashboard_data, get_test_detail,
    get_quarantined_tests, send_alert, ensure_initialized,
)

logger = logging.getLogger("falsky.api")


# ===================== LIFESPAN =====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        ensure_initialized()
        logger.info("Falsky API started (Supabase SDK)")
    except Exception as e:
        logger.error(f"Startup init error (non-fatal): {e}")
    yield
    logger.info("Falsky API shutting down")


app = FastAPI(
    title="Falsky — AI Flaky Test Trust Layer",
    description="Production-ready flaky test detection with Bayesian scoring",
    version="3.0.0",
    lifespan=lifespan,
)

# ===================== MIDDLEWARE =====================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ===================== CONFIG =====================

# Robust base_path: works in Vercel serverless and local dev
_base = os.path.dirname(os.path.abspath(__file__))  # backend/
base_path = os.path.dirname(_base)  # project root
# Vercel fallback: if dashboard/ not found at base_path, try /var/task
if not os.path.isdir(os.path.join(base_path, "dashboard")):
    if os.path.isdir(os.path.join("/var/task", "dashboard")):
        base_path = "/var/task"
    elif os.path.isdir(os.path.join(_base, "dashboard")):
        base_path = _base  # dashboard is inside backend/

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
SITE_URL = os.environ.get("SITE_URL", "")
ALLOWED_ADMIN_EMAILS = os.environ.get("ALLOWED_ADMIN_EMAILS", "").split(",") if os.environ.get("ALLOWED_ADMIN_EMAILS") else []
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://falsky-core-vercel.vercel.app,http://localhost:3000,http://localhost:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting (in-memory, per-IP)
_login_attempts = {}
LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW = 900


def _check_rate_limit(ip: str):
    now = time.time()
    if ip in _login_attempts:
        count, first_time = _login_attempts[ip]
        if now - first_time > LOGIN_RATE_WINDOW:
            _login_attempts[ip] = (1, now)
            return
        if count >= LOGIN_RATE_LIMIT:
            logger.warning(f"Rate limit hit for IP: {ip}")
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 15 minutes.")
        _login_attempts[ip] = (count + 1, first_time)
    else:
        _login_attempts[ip] = (1, now)


# ===================== AUTH HELPERS =====================

def verify_api_key(x_falsky_api_key: Optional[str] = Header(None)):
    env_key = os.environ.get("FALSKY_API_KEY", "")
    if x_falsky_api_key and x_falsky_api_key == env_key:
        return x_falsky_api_key
    if x_falsky_api_key:
        user = select_one("users", "id", {"api_key": x_falsky_api_key, "is_active": True})
        if user:
            return x_falsky_api_key
    raise HTTPException(status_code=401, detail="Invalid API key")


FALSKY_ADMIN_SECRET = os.environ.get("FALSKY_ADMIN_SECRET", "falsky-admin-secret-key-change-in-production")


def _get_admin_session(request: Request):
    """Verify admin session — supports JWT (Google) and legacy JWT tokens."""
    token = request.cookies.get("falsky_admin_token")
    if not token:
        return None
    # Try Google OAuth JWT first
    if SUPABASE_JWT_SECRET and token.count(".") == 2:
        try:
            payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
            email = payload.get("email", "")
            if ALLOWED_ADMIN_EMAILS and email not in ALLOWED_ADMIN_EMAILS:
                logger.warning(f"Google auth rejected for: {email}")
                return None
            meta = payload.get("user_metadata") or {}
            return {
                "username": meta.get("full_name") or email.split("@")[0],
                "role": "admin",
                "email": email,
                "avatar": meta.get("avatar_url", ""),
                "auth_provider": "google",
            }
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except Exception:
            pass
    # Fallback: verify our own admin JWT token
    try:
        payload = jwt.decode(token, FALSKY_ADMIN_SECRET, algorithms=["HS256"], audience="falsky-admin")
        return {
            "username": payload.get("username", "admin"),
            "role": payload.get("role", "admin"),
            "auth_provider": "jwt",
        }
    except jwt.ExpiredSignatureError:
        logger.warning("Admin JWT expired")
        return None
    except Exception:
        return None


def require_admin(request: Request):
    admin = _get_admin_session(request)
    if not admin:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return admin


# ===================== PYDANTIC MODELS =====================

class JUnitUpload(BaseModel):
    xml_content: str
    repo_name: str
    branch: str = "main"
    commit_sha: Optional[str] = None
    environment: Optional[str] = None


class RunInput(BaseModel):
    test_results: list[dict]
    repo_name: str
    run_id: Optional[str] = None
    branch: str = "main"
    commit_sha: Optional[str] = None
    environment: Optional[str] = None


class AlertConfig(BaseModel):
    webhook_url: str
    channel_type: str = "discord"
    min_trust_drop: float = 20
    alert_on_flaky: bool = True
    alert_on_quarantine: bool = True


class AdminLogin(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    name: str
    email: str
    github_username: Optional[str] = None
    plan: str = "free"
    referrer: Optional[str] = None
    signup_source: Optional[str] = None
    notes: Optional[str] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    github_username: Optional[str] = None
    plan: Optional[str] = None
    is_active: Optional[bool] = None
    notes: Optional[str] = None
    referrer: Optional[str] = None
    signup_source: Optional[str] = None


# ===================== HEALTH =====================

@app.get("/api/health")
def health_check():
    supabase_url = os.environ.get("SUPABASE_URL", "")
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    anon_key = os.environ.get("SUPABASE_ANON_KEY", "")
    return {
        "status": "ok",
        "version": "3.0.0",
        "service": "falsky-core",
        "auth": "supabase-google" if supabase_url else "legacy",
        "db": "supabase-sdk",
        "env_check": {
            "SUPABASE_URL": "SET" if supabase_url else "MISSING",
            "SUPABASE_SERVICE_ROLE_KEY": "SET" if service_key else "MISSING",
            "SUPABASE_ANON_KEY": "SET" if anon_key else "MISSING",
        }
    }


# ===================== SUPABASE GOOGLE AUTH =====================

@app.get("/api/auth/google")
def google_login():
    if not SUPABASE_URL:
        raise HTTPException(status_code=501, detail="Google Sign-In not configured.")
    redirect_to = urllib.parse.quote(f"{SITE_URL}/api/auth/callback")
    auth_url = f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to={redirect_to}"
    return RedirectResponse(url=auth_url)


@app.get("/api/auth/callback")
def auth_callback(request: Request):
    access_token = request.query_params.get("access_token")
    error = request.query_params.get("error")
    if error:
        return RedirectResponse(url=f"/analytics?error={urllib.parse.quote(error)}")
    if not access_token:
        return RedirectResponse(url="/analytics?error=no_token")
    if SUPABASE_JWT_SECRET:
        try:
            payload = jwt.decode(access_token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
            email = payload.get("email", "")
            if ALLOWED_ADMIN_EMAILS and email not in ALLOWED_ADMIN_EMAILS:
                return RedirectResponse(url="/analytics?error=unauthorized")
        except Exception:
            return RedirectResponse(url="/analytics?error=invalid_token")
    response = RedirectResponse(url="/analytics")
    response.set_cookie(key="falsky_admin_token", value=access_token, httponly=True, secure=True, samesite="lax", max_age=86400 * 7, path="/")
    return response


@app.post("/api/auth/logout")
def auth_logout(response: Response):
    response.delete_cookie("falsky_admin_token", path="/")
    return {"status": "ok"}


@app.get("/api/auth/config")
def auth_config():
    return {"google_enabled": bool(SUPABASE_URL), "has_legacy": True}


# ===================== STATIC / ROOT =====================

def _serve_html(relative_path: str, fallback_title: str = "Falsky"):
    """Read HTML file and return as HTMLResponse. Vercel-safe."""
    full = os.path.join(base_path, relative_path)
    try:
        with open(full, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(f"<h1>{fallback_title}</h1><p>Page not found.</p>", status_code=404)


@app.get("/", response_class=HTMLResponse)
def root():
    return _serve_html(os.path.join("landing", "index.html"), "Falsky — AI Flaky Test Trust Layer")


# ===================== ADMIN AUTH =====================

@app.post("/api/admin/login")
def admin_login(data: AdminLogin, request: Request, response: Response):
    try:
        client_ip = request.client.host if request.client else "unknown"
        _check_rate_limit(client_ip)
        
        admin = select_one("admin_users", "id, username, password_hash, role", {"username": data.username})
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        pw_hash = admin["password_hash"]
        if bcrypt.checkpw(data.password.encode(), pw_hash.encode()):
            pass
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Generate JWT session token (no DB needed)
        from datetime import datetime, timezone, timedelta
        jwt_payload = {
            "username": admin["username"],
            "role": admin["role"],
            "aud": "falsky-admin",
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
        }
        token = jwt.encode(jwt_payload, FALSKY_ADMIN_SECRET, algorithm="HS256")
        
        response.set_cookie(key="falsky_admin_token", value=token, httponly=True, secure=True, samesite="lax", max_age=86400 * 7)
        logger.info(f"Admin login successful: {data.username}")
        return {"status": "ok", "username": admin["username"], "role": admin["role"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error: {type(e).__name__}")


@app.post("/api/admin/logout")
def admin_logout(request: Request, response: Response):
    response.delete_cookie("falsky_admin_token", path="/")
    return {"status": "ok"}


@app.get("/api/admin/me")
def admin_me(request: Request):
    admin = _get_admin_session(request)
    if not admin:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return admin


# ===================== ADMIN USERS API =====================

@app.get("/api/admin/users")
def admin_list_users(request: Request, search: str = "", plan: str = "", sort: str = "newest", page: int = 1, per_page: int = 20):
    try:
        require_admin(request)
        client = get_client()
        
        # Build query
        q = client.table("users").select("*", count="exact")
        if search:
            q = q.or_(f"name.ilike.%{search}%,email.ilike.%{search}%,github_username.ilike.%{search}%")
        if plan:
            q = q.eq("plan", plan)
        
        order = "created_at.desc" if sort == "newest" else "created_at.asc"
        offset = (page - 1) * per_page
        
        result = q.order("created_at", desc=(sort == "newest")).range(offset, offset + per_page - 1).execute()
        users = result.data if result.data else []
        total = result.count if result.count is not None else len(users)

        # Stats
        sources_result = client.table("users").select("signup_source").execute()
        sources_data = sources_result.data if sources_result.data else []
        source_counts = {}
        for u in sources_data:
            s = u.get("signup_source") or "unknown"
            source_counts[s] = source_counts.get(s, 0) + 1
        sources = [{"signup_source": k, "cnt": v} for k, v in sorted(source_counts.items(), key=lambda x: -x[1])]

        plans_result = client.table("users").select("plan").execute()
        plans_data = plans_result.data if plans_result.data else []
        plan_counts = {}
        for u in plans_data:
            p = u.get("plan") or "free"
            plan_counts[p] = plan_counts.get(p, 0) + 1
        plans = [{"plan": k, "cnt": v} for k, v in sorted(plan_counts.items(), key=lambda x: -x[1])]

        # Activity
        activity_result = client.table("user_activity").select("*, users(name, email)").order("created_at", desc=True).limit(10).execute()
        activity = activity_result.data if activity_result.data else []

        return {
            "users": users, "total": total, "page": page, "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
            "sources": sources, "plans": plans, "daily_signups": [],
            "recent_activity": activity,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin list users error: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing users: {str(e)}")


@app.post("/api/admin/users")
def admin_create_user(data: UserCreate, request: Request):
    try:
        require_admin(request)
        api_key = f"falsky_{secrets.token_urlsafe(24)}"
        user = insert("users", {
            "name": data.name,
            "email": data.email,
            "github_username": data.github_username,
            "api_key": api_key,
            "plan": data.plan,
            "referrer": data.referrer,
            "signup_source": data.signup_source,
            "notes": data.notes,
        })
        insert("user_activity", {
            "user_id": user["id"],
            "action": "signup",
            "detail": f"Created by admin | source: {data.signup_source or 'manual'}",
        })
        return {"status": "ok", "user_id": user["id"], "api_key": api_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin create user error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, data: UserUpdate, request: Request):
    try:
        require_admin(request)
        existing = select_one("users", "id", {"id": user_id})
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")
        updates = {k: v for k, v in data.model_dump().items() if v is not None}
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        update("users", updates, {"id": user_id})
        insert("user_activity", {"user_id": user_id, "action": "updated", "detail": f"Updated by admin: {', '.join(updates.keys())}"})
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin update user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, request: Request):
    try:
        require_admin(request)
        existing = select_one("users", "name, email", {"id": user_id})
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")
        delete("user_activity", {"user_id": user_id})
        delete("users", {"id": user_id})
        return {"status": "ok", "deleted": existing["name"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin delete user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/stats")
def admin_stats(request: Request):
    try:
        require_admin(request)
        client = get_client()
        
        result = client.rpc("get_admin_stats").execute()
        stats = result.data[0] if result.data else {}
        
        ref_result = client.rpc("get_top_referrers", {"p_limit": 5}).execute()
        stats["top_referrers"] = ref_result.data if ref_result.data else []
        
        source_result = client.rpc("get_top_sources", {"p_limit": 5}).execute()
        stats["top_sources"] = source_result.data if source_result.data else []
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===================== DIRECT SUPABASE CLIENT (fallback) =====================

import urllib.request
import json as _json

_SUPABASE_URL = "https://mzcplqfxrxfsxnwyiyym.supabase.co"
_SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
_SUPABASE_ANON = os.environ.get("SUPABASE_ANON_KEY", "")

def _supabase_rest(table, method="GET", data=None, filters=None, columns="*"):
    """Direct Supabase REST API call — bypasses db module."""
    key = _SUPABASE_SERVICE_KEY or _SUPABASE_ANON
    if not key:
        # Hardcoded fallback for user auth
        key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im16Y3BscWZ4cnhmc3hud3lpeXltIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4NDI2MTM0NiwiZXhwIjoyMDk5ODM3MzQ2fQ.hrgP5Axv2ZD0cEcxlz9pm32qE9RGKgYWAx78qyLHCxw"
    url = f"{_SUPABASE_URL}/rest/v1/{table}"
    if filters:
        params = '&'.join(f'{k}=eq.{v}' for k,v in filters.items())
        url += f"?{params}"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    req = urllib.request.Request(url, headers=headers, method=method)
    if data:
        req.data = _json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return _json.loads(resp.read().decode())
    except Exception as e:
        logger.error(f"Supabase REST error: {e}")
        return None

# ===================== USER AUTH =====================

class UserRegister(BaseModel):
    name: str
    email: str
    password: str
    github_username: Optional[str] = None
    signup_source: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

_user_sessions = {}  # token -> {user_id, email, name}

@app.post("/api/user/register")
def user_register(data: UserRegister, request: Request, response: Response):
    try:
        # Check if email exists
        existing = _supabase_rest("users", filters={"email": data.email}, columns="id")
        if existing and len(existing) > 0:
            raise HTTPException(status_code=400, detail="Email already registered")
        # Hash password
        pw_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
        # Generate API key
        api_key = "fky_" + secrets.token_hex(20)
        # Insert user
        result = _supabase_rest("users", method="POST", data={
            "name": data.name,
            "email": data.email,
            "password_hash": pw_hash,
            "github_username": data.github_username,
            "api_key": api_key,
            "plan": "free",
            "is_active": True,
            "signup_source": data.signup_source or "direct",
        })
        if not result or len(result) == 0:
            raise HTTPException(status_code=500, detail="Failed to create user")
        user = result[0]
        # Create session
        token = secrets.token_hex(32)
        _user_sessions[token] = {"user_id": user["id"], "email": data.email, "name": data.name}
        response.set_cookie(key="falsky_user_token", value=token, httponly=True, secure=True, samesite="lax", max_age=86400 * 30)
        return {"status": "ok", "name": data.name, "email": data.email, "api_key": api_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User register error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/user/login")
def user_login(data: UserLogin, request: Request, response: Response):
    try:
        users = _supabase_rest("users", filters={"email": data.email}, columns="id,name,email,password_hash,api_key,is_active")
        if not users or len(users) == 0:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        user = users[0]
        if not user.get("is_active", True):
            raise HTTPException(status_code=403, detail="Account is disabled")
        if not user.get("password_hash"):
            raise HTTPException(status_code=401, detail="Account has no password set. Please register again.")
        if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token = secrets.token_hex(32)
        _user_sessions[token] = {"user_id": user["id"], "email": user["email"], "name": user.get("name", "")}
        response.set_cookie(key="falsky_user_token", value=token, httponly=True, secure=True, samesite="lax", max_age=86400 * 30)
        return {"status": "ok", "name": user.get("name", ""), "email": user["email"], "api_key": user.get("api_key", "")}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/user/me")
def user_me(request: Request):
    token = request.cookies.get("falsky_user_token")
    if not token or token not in _user_sessions:
        raise HTTPException(status_code=401, detail="Not logged in")
    session = _user_sessions[token]
    users = _supabase_rest("users", filters={"id": session["user_id"]}, columns="id,name,email,api_key,plan,is_active")
    if not users or len(users) == 0 or not users[0].get("is_active", True):
        raise HTTPException(status_code=401, detail="Account not found")
    user = users[0]
    return {"name": user.get("name", ""), "email": user["email"], "api_key": user.get("api_key", ""), "plan": user.get("plan", "free")}

@app.post("/api/user/logout")
def user_logout(request: Request, response: Response):
    token = request.cookies.get("falsky_user_token")
    if token and token in _user_sessions:
        del _user_sessions[token]
    response.delete_cookie("falsky_user_token")
    return {"status": "ok"}

@app.get("/login", response_class=HTMLResponse)
def serve_login():
    return _serve_html(os.path.join("dashboard", "auth.html"), "Falsky — Sign In")

# ===================== EXISTING API ROUTES =====================

@app.post("/api/junit", dependencies=[Depends(verify_api_key)])
def ingest_junit(data: JUnitUpload):
    try:
        result = process_test_run(
            xml_content=data.xml_content,
            repo_name=data.repo_name,
            branch=data.branch,
            commit_sha=data.commit_sha,
            environment=data.environment,
        )
        return result
    except Exception as e:
        logger.error(f"JUnit ingest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/runs", dependencies=[Depends(verify_api_key)])
def create_run(data: RunInput):
    try:
        import xml.etree.ElementTree as ET
        testsuites = ET.Element("testsuites")
        testsuite = ET.SubElement(testsuites, "testsuite", name="custom", tests=str(len(data.test_results)))
        for t in data.test_results:
            attrs = {"name": t.get("name", "unknown"), "classname": t.get("classname", ""), "time": str(t.get("duration", 0))}
            tc = ET.SubElement(testsuite, "testcase", **attrs)
            if t.get("status") == "failed":
                ET.SubElement(tc, "failure", message=t.get("error_message", "Test failed"))
            elif t.get("status") == "skipped":
                ET.SubElement(tc, "skipped")
        xml_str = ET.tostring(testsuites, encoding="unicode")
        result = process_test_run(xml_content=xml_str, repo_name=data.repo_name, run_id=data.run_id, branch=data.branch, commit_sha=data.commit_sha, environment=data.environment)
        return result
    except Exception as e:
        logger.error(f"Create run error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dashboard")
def dashboard(repo_name: str = Query(...)):
    try:
        # Get repo
        repos = _supabase_rest("repositories", filters={"name": repo_name}, columns="id,name")
        if not repos or len(repos) == 0:
            return {"repo": repo_name, "tests": [], "total": 0}
        repo_id = repos[0]["id"]
        # Get test results
        tests = _supabase_rest("test_results", filters={"repo_id": str(repo_id)}, columns="test_name,status,trust_score,flaky_category,duration,run_id")
        if not tests:
            return {"repo": repo_name, "tests": [], "total": 0}
        # Aggregate by test name
        from collections import defaultdict
        agg = defaultdict(lambda: {"scores": [], "passes": 0, "total": 0, "category": None, "durations": []})
        for t in tests:
            name = t.get("test_name", "unknown")
            agg[name]["scores"].append(t.get("trust_score", 100))
            agg[name]["total"] += 1
            if t.get("status") == "passed":
                agg[name]["passes"] += 1
            if t.get("flaky_category"):
                agg[name]["category"] = t["flaky_category"]
            if t.get("duration"):
                agg[name]["durations"].append(t["duration"])
        result = []
        for name, d in agg.items():
            result.append({
                "test_name": name,
                "trust_score": round(sum(d["scores"]) / len(d["scores"]), 1),
                "pass_rate": round(d["passes"] / d["total"], 3) if d["total"] > 0 else 0,
                "runs": d["total"],
                "flaky_category": d["category"],
                "avg_duration": round(sum(d["durations"]) / len(d["durations"]), 1) if d["durations"] else 0,
            })
        return {"repo": repo_name, "tests": result, "total": len(result)}
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return {"repo": repo_name, "tests": [], "total": 0}


@app.get("/api/tests")
def list_tests(repo_name: str = Query(...)):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        tests = select("test_results", 
                       "test_name, avg(trust_score) as trust_score, count(*) as runs, flaky_category, avg(case when status='passed' then 1.0 else 0.0 end) as pass_rate, avg(duration) as avg_duration",
                       filters={"repo_id": repo["id"]})
        return {"repo": repo_name, "tests": tests, "total": len(tests)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List tests error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tests/{test_name:path}")
def test_detail(test_name: str, repo_name: str = Query(...)):
    try:
        result = get_test_detail(repo_name, test_name)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test detail error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/quarantined")
def quarantined(repo_name: str = Query(...), threshold: float = Query(30)):
    try:
        return {"repo": repo_name, "threshold": threshold, "quarantined": get_quarantined_tests(repo_name, threshold)}
    except Exception as e:
        logger.error(f"Quarantined error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/runs")
def list_runs(repo_name: str = Query(...), limit: int = Query(20, le=100)):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        runs = select("ci_runs", "*", filters={"repo_id": repo["id"]}, order="-timestamp", limit=limit)
        return {"repo": repo_name, "runs": runs}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List runs error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/repos")
def list_repos():
    try:
        repos = _supabase_rest("repositories", columns="id,name,created_at")
        return {"repos": repos or []}
    except Exception as e:
        logger.error(f"List repos error: {e}")
        return {"repos": []}


@app.post("/api/alerts/config", dependencies=[Depends(verify_api_key)])
def set_alert_config(repo_name: str = Query(...), config: AlertConfig = ...):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            repo = insert("repositories", {"name": repo_name})
        repo_id = repo["id"]
        upsert("alerts_config", {
            "repo_id": repo_id,
            "webhook_url": config.webhook_url,
            "channel_type": config.channel_type,
            "min_trust_drop": config.min_trust_drop,
            "alert_on_flaky": config.alert_on_flaky,
            "alert_on_quarantine": config.alert_on_quarantine,
        }, on_conflict="repo_id")
        return {"status": "ok", "repo": repo_name}
    except Exception as e:
        logger.error(f"Alert config error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/test", dependencies=[Depends(verify_api_key)])
def test_alert(repo_name: str = Query(...)):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        cfg = select_one("alerts_config", "*", {"repo_id": repo["id"]})
        if not cfg:
            raise HTTPException(status_code=404, detail="No alert config found")
        ok = send_alert(repo_name=repo_name, webhook_url=cfg["webhook_url"], channel_type=cfg["channel_type"], alert_data={"Test": "Falsky connectivity test", "Status": "Alert channel working"})
        return {"status": "sent" if ok else "failed"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert test error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/tests/{test_name:path}", dependencies=[Depends(verify_api_key)])
def delete_test(test_name: str, repo_name: str = Query(...)):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        deleted = delete("test_results", {"repo_id": repo["id"], "test_name": test_name})
        return {"status": "ok", "deleted": len(deleted) if deleted else 0}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete test error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _badge_svg(score: float, label: str = "falsky trust") -> str:
    if score >= 90: color = "#22c55e"
    elif score >= 70: color = "#eab308"
    elif score >= 50: color = "#f97316"
    else: color = "#ef4444"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="220" height="30">'
            f'<rect width="220" height="30" rx="6" fill="#0f0f11"/>'
            f'<rect x="110" width="110" height="30" rx="6" fill="{color}"/>'
            f'<text x="10" y="20" fill="#a1a1aa" font-family="system-ui,sans-serif" font-size="11" font-weight="600">{label}</text>'
            f'<text x="120" y="20" fill="#fff" font-family="system-ui,sans-serif" font-size="11" font-weight="700">{int(score)}%</text></svg>')


@app.get("/badge/{repo_name}")
def trust_badge(repo_name: str):
    try:
        repo = select_one("repositories", "id", {"name": repo_name})
        if not repo:
            return HTMLResponse(content=_badge_svg(100, "no data"), media_type="image/svg+xml")
        client = get_client()
        result = client.table("test_results").select("trust_score").eq("repo_id", repo["id"]).execute()
        scores = [r["trust_score"] for r in result.data if r.get("trust_score") is not None]
        avg = round(sum(scores) / len(scores), 0) if scores else 100
        return HTMLResponse(content=_badge_svg(avg), media_type="image/svg+xml")
    except Exception:
        return HTMLResponse(content=_badge_svg(100, "no data"), media_type="image/svg+xml")


# ===================== AUTH MIDDLEWARE =====================

def _check_user_auth(request: Request):
    """Check if user is authenticated via cookie."""
    token = request.cookies.get("falsky_user_token")
    if token and token in _user_sessions:
        return True
    # Also check admin token
    admin_token = request.cookies.get("falsky_admin_token")
    if admin_token:
        try:
            if _get_admin_session(request):
                return True
        except:
            pass
    return False

# ===================== PAGE ROUTES =====================

@app.get("/dashboard/", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    if not _check_user_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return _serve_html(os.path.join("dashboard", "index.html"), "Falsky Dashboard")

@app.get("/dashboard/test-detail.html", response_class=HTMLResponse)
def serve_test_detail(request: Request):
    if not _check_user_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return _serve_html(os.path.join("dashboard", "test-detail.html"), "Test Detail")

@app.get("/dashboard/guide.html", response_class=HTMLResponse)
def serve_guide(request: Request):
    if not _check_user_auth(request):
        return RedirectResponse(url="/login", status_code=302)
    return _serve_html(os.path.join("dashboard", "guide.html"), "Falsky Guide")

@app.get("/analytics", response_class=HTMLResponse)
def serve_admin():
    return _serve_html(os.path.join("dashboard", "admin.html"), "Falsky Admin")

@app.get("/landing/", response_class=HTMLResponse)
def serve_landing():
    return RedirectResponse(url="/")


@app.get("/favicon.ico")
def favicon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           '<rect width="32" height="32" rx="8" fill="#121212"/>'
           '<text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" '
           'fill="#C8A95A" font-family="system-ui" font-weight="800" font-size="18">F</text></svg>')
    return HTMLResponse(content=svg, media_type="image/svg+xml")


@app.get("/robots.txt")
def robots():
    return HTMLResponse(content="User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /admin/", media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
