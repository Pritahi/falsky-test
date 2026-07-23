"""
Poly — AI Flaky Test Trust Layer
FastAPI Backend Server
"""

import logging
import os
import secrets
import time
import urllib.parse

# Optional imports — won't crash if missing
try:
    import bcrypt
except ImportError:
    bcrypt = None
try:
    import jwt
except ImportError:
    jwt = None
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None
    psycopg2.extras = None

# Supabase SDK (used for Google OAuth session verification)
try:
    from supabase import create_client, Client
    _SUPABASE_SDK = True
except ImportError:
    create_client = None
    Client = None
    _SUPABASE_SDK = False

logger = logging.getLogger("poly.api")

# Lazy Supabase client (thread-safe enough for token verification)
_supabase_client = None


def get_supabase_client():
    """Return a Supabase client using SUPABASE_URL + SUPABASE_ANON_KEY, or None if unconfigured."""
    global _supabase_client
    if not _SUPABASE_SDK or not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return None
    if _supabase_client is None:
        try:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        except Exception as e:
            logger.error(f"Failed to create Supabase client: {e}")
            return None
    return _supabase_client


def verify_supabase_token(access_token: str):
    """Verify a Supabase access token using the SDK and return user info dict, or None."""
    client = get_supabase_client()
    if client is None:
        return None
    try:
        user_resp = client.auth.get_user(access_token)
        user = getattr(user_resp, "user", None)
        if not user:
            return None
        email = getattr(user, "email", "") or ""
        meta = getattr(user, "user_metadata", {}) or {}
        return {
            "email": email,
            "username": (meta.get("full_name") or email.split("@")[0]) if email else "",
            "avatar": meta.get("avatar_url", ""),
        }
    except Exception as e:
        logger.error(f"Supabase token verification failed: {e}")
        return None


from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional

from engine.trust_engine import (
    process_test_run, get_dashboard_data, get_test_detail,
    get_quarantined_tests, send_alert, _get_db, _DB_DRIVER,
    _cursor, _to_dict, _to_dicts,
)

logger = logging.getLogger("poly.api")


# ===================== LIFESPAN =====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — graceful, won't crash if DB not configured
    try:
        from engine.trust_engine import ensure_initialized
        ensure_initialized()
        logger.info("Poly API started")
    except Exception as e:
        logger.error(f"Startup init error (non-fatal): {e}")
    yield
    # Shutdown
    logger.info("Poly API shutting down")


app = FastAPI(
    title="Poly — AI Flaky Test Trust Layer",
    description="Production-ready flaky test detection with Bayesian scoring",
    version="2.1.0",
    lifespan=lifespan,
)

# ===================== MIDDLEWARE =====================

# Security headers middleware
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

base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
SITE_URL = os.environ.get("SITE_URL", "")
ALLOWED_ADMIN_EMAILS = os.environ.get("ALLOWED_ADMIN_EMAILS", "").split(",") if os.environ.get("ALLOWED_ADMIN_EMAILS") else []
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://poly-core-vercel.vercel.app,http://localhost:3000,http://localhost:8000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting (in-memory, per-IP)
_login_attempts = {}  # ip -> (count, first_attempt_time)
LOGIN_RATE_LIMIT = 5  # max attempts per window
LOGIN_RATE_WINDOW = 900  # 15 minutes in seconds


def _check_rate_limit(ip: str):
    """Check if IP is rate-limited for login attempts."""
    now = time.time()
    if ip in _login_attempts:
        count, first_time = _login_attempts[ip]
        if now - first_time > LOGIN_RATE_WINDOW:
            # Window expired, reset
            _login_attempts[ip] = (1, now)
            return
        if count >= LOGIN_RATE_LIMIT:
            logger.warning(f"Rate limit hit for IP: {ip}")
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 15 minutes.")
        _login_attempts[ip] = (count + 1, first_time)
    else:
        _login_attempts[ip] = (1, now)


# ===================== AUTH HELPERS =====================

def verify_api_key(x_poly_api_key: Optional[str] = Header(None)):
    env_key = os.environ.get("POLY_API_KEY", "")
    if x_poly_api_key and x_poly_api_key == env_key:
        return x_poly_api_key
    # Also check DB user API keys
    if x_poly_api_key:
        try:
            with _get_db() as conn:
                with _cursor(conn) as c:
                    c.execute("SELECT id FROM users WHERE api_key=%s AND is_active=TRUE", (x_poly_api_key,))
                    if c.fetchone():
                        return x_poly_api_key
        except Exception:
            pass
    raise HTTPException(status_code=401, detail="Invalid API key")


def _get_admin_session(request: Request):
    """Verify admin session — supports both Supabase Google JWT (via SDK) and legacy tokens."""
    token = request.cookies.get("poly_admin_token")
    if not token:
        return None
    # Try Supabase SDK verification (preferred — uses SUPABASE_ANON_KEY, no JWT secret needed)
    user_info = verify_supabase_token(token)
    if user_info:
        email = user_info.get("email", "")
        if ALLOWED_ADMIN_EMAILS and email not in ALLOWED_ADMIN_EMAILS:
            logger.warning(f"Google auth rejected (not in allowed list): {email}")
            return None
        logger.info(f"Google auth success via SDK: {email}")
        return {
            "username": user_info.get("username") or email.split("@")[0],
            "role": "admin",
            "email": email,
            "avatar": user_info.get("avatar", ""),
            "auth_provider": "google",
        }
    # Fallback: legacy session token verification (DB-backed)
    if len(token) >= 32:
        try:
            with _get_db() as conn:
                with _cursor(conn) as c:
                    # Verify token against stored session in admin_sessions table
                    c.execute(
                        "SELECT u.username, u.role FROM admin_users u "
                        "JOIN admin_sessions s ON u.id = s.admin_id "
                        "WHERE s.token = %s AND s.expires_at > NOW()",
                        (token,)
                    )
                    return _to_dict(c)
        except Exception:
            pass
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
    return {"status": "ok", "version": "2.1.0", "service": "poly-core", "auth": "supabase-google" if SUPABASE_URL else "legacy"}

@app.get("/api/debug/outbound-test")
def outbound_test():
    import ssl, urllib.request, json as _json, traceback
    key = _SUPABASE_SERVICE_KEY or _SUPABASE_ANON
    url = f"{_SUPABASE_URL}/rest/v1/users?select=id&limit=1"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode()
            return {"status": resp.status, "headers": dict(resp.headers), "body": _json.loads(body)[:100] if body else ""}
    except ssl.SSLError as e:
        return {"error": f"SSL Error: {e}", "traceback": traceback.format_exc()}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        return {"error": f"HTTP {e.code}: {e.reason}", "body": body}
    except Exception as e:
        return {"error": str(e), "type": type(e).__name__, "traceback": traceback.format_exc()}


# ===================== SUPABASE GOOGLE AUTH =====================

@app.get("/api/auth/google")
def google_login(request: Request):
    """Redirect to Supabase Google OAuth."""
    if not SUPABASE_URL:
        raise HTTPException(
            status_code=501,
            detail="Google Sign-In not configured. Missing env var SUPABASE_URL. "
                   "Set it in your hosting dashboard (e.g. https://xxxx.supabase.co).",
        )
    if not SUPABASE_ANON_KEY:
        raise HTTPException(
            status_code=501,
            detail="Google Sign-In not configured. Missing env var SUPABASE_ANON_KEY "
                   "(project anon/public key). Set it in your hosting dashboard.",
        )
    if not SITE_URL:
        raise HTTPException(
            status_code=501,
            detail="Google Sign-In not configured. Set SITE_URL env var to the public base URL (e.g. https://your-app.vercel.app).",
        )
    base = SITE_URL.rstrip("/")
    # Guard against misconfiguration that sends users to localhost after Google login.
    if base.startswith("http://localhost") or base.startswith("http://127.0.0.1") or base.startswith("http://0.0.0.0"):
        raise HTTPException(
            status_code=501,
            detail=(
                "SITE_URL is set to a localhost URL — Supabase will redirect users back to "
                f"{base}/api/auth/callback after Google login, which fails with ERR_CONNECTION_REFUSED. "
                "Set SITE_URL to your public app URL (e.g. https://poly-core-vercel.vercel.app) and add "
                f"that URL + '/api/auth/callback' as an authorized redirect URI in Supabase → Auth → Providers → Google."
            ),
        )
    redirect_to = urllib.parse.quote(f"{base}/api/auth/callback")
    auth_url = f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to={redirect_to}"
    logger.info("Redirecting to Google OAuth")
    return RedirectResponse(url=auth_url)


@app.get("/api/auth/callback")
def auth_callback(request: Request):
    """Handle Supabase OAuth callback — set JWT cookie and redirect to admin."""
    params = dict(request.query_params)

    # Supabase OAuth (implicit/PKCE) may return tokens in the URL fragment (#access_token=...)
    # when the callback is loaded as a full-page redirect. The browser does not send the
    # fragment to the server, so we render a tiny page that forwards the fragment to us as
    # a query string via a same-origin POST-style redirect.
    access_token = params.get("access_token")
    refresh_token = params.get("refresh_token")
    error = params.get("error")

    if error:
        logger.error(f"OAuth error: {error}")
        return RedirectResponse(url=f"/admin/?error={urllib.parse.quote(error)}")

    if not access_token:
        # No token in query string — assume it's in the URL fragment. Serve a bridge page
        # that re-submits the fragment to this same endpoint as query params.
        bridge = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Signing in...</title></head><body>"
            "<script>"
            "var h = window.location.hash.substring(1);"
            "if (h) { window.location.replace(window.location.pathname + '?' + h); }"
            "else { window.location.replace('/admin/?error=no_token'); }"
            "</script></body></html>"
        )
        return HTMLResponse(content=bridge)

    # Verify the token via Supabase SDK (no JWT secret needed)
    user_info = verify_supabase_token(access_token)
    if not user_info:
        logger.error("Supabase token verification failed")
        return RedirectResponse(url="/admin/?error=invalid_token")
    email = user_info.get("email", "")
    if ALLOWED_ADMIN_EMAILS and email not in ALLOWED_ADMIN_EMAILS:
        logger.warning(f"Google auth rejected (not in allowed list): {email}")
        return RedirectResponse(url="/admin/?error=unauthorized")
    logger.info(f"Google auth success via callback: {email}")

    response = RedirectResponse(url="/admin/")
    response.set_cookie(
        key="poly_admin_token", value=access_token,
        httponly=True, secure=True, samesite="lax", max_age=86400 * 7,
        path="/"
    )
    return response


@app.post("/api/auth/logout")
def auth_logout(response: Response):
    try:
        response.delete_cookie("poly_admin_token", path="/")
        logger.info("User logged out")
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/api/auth/config")
def auth_config():
    """Return auth configuration for the frontend (public info only)."""
    return {
        "google_enabled": bool(SUPABASE_URL),
        "has_legacy": True,
    }


# ===================== STATIC / ROOT =====================

@app.get("/", response_class=HTMLResponse)
def root():
    landing_path = os.path.join(base_path, "landing", "index.html")
    if os.path.exists(landing_path):
        return FileResponse(landing_path)
    return HTMLResponse("<h1>Poly — AI Flaky Test Trust Layer</h1><p>Landing page not found. Visit <a href='/dashboard/'>Dashboard</a> or <a href='/docs'>API Docs</a></p>", status_code=404)


# ===================== ADMIN AUTH =====================

@app.post("/api/admin/login")
def admin_login(data: AdminLogin, request: Request, response: Response):
    try:
        # Rate limit by IP
        client_ip = request.client.host if request.client else "unknown"
        _check_rate_limit(client_ip)
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id, username, password_hash, role FROM admin_users WHERE username=%s", (data.username,))
                row = _to_dict(c)
        if not row:
            logger.warning(f"Failed login: user not found: {data.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        pw_hash = row["password_hash"]
        if bcrypt and bcrypt.checkpw(data.password.encode(), pw_hash.encode()):
            pass  # valid
        elif not bcrypt:
            import hashlib
            if hashlib.sha256(data.password.encode()).hexdigest() != pw_hash:
                logger.warning(f"Failed login for: {data.username}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
        else:
            logger.warning(f"Failed login for: {data.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Generate secure session token and store in DB
        token = secrets.token_hex(32)
        with _get_db() as conn:
            with _cursor(conn) as c:
                # Clean expired sessions
                c.execute("DELETE FROM admin_sessions WHERE expires_at < NOW()")
                # Store new session (7 day expiry)
                c.execute(
                    "INSERT INTO admin_sessions (admin_id, token, expires_at) VALUES (%s, %s, NOW() + INTERVAL '7 days')",
                    (row["id"], token)
                )
            conn.commit()
        response.set_cookie(key="poly_admin_token", value=token, httponly=True, secure=True, samesite="lax", max_age=86400 * 7)
        logger.info(f"Admin login successful: {data.username}")
        return {"status": "ok", "username": row["username"], "role": row["role"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


@app.post("/api/admin/logout")
def admin_logout(request: Request, response: Response):
    try:
        token = request.cookies.get("poly_admin_token")
        if token:
            try:
                with _get_db() as conn:
                    with _cursor(conn) as c:
                        c.execute("DELETE FROM admin_sessions WHERE token=%s", (token,))
                    conn.commit()
            except Exception:
                pass
        response.delete_cookie("poly_admin_token", path="/")
        logger.info("Admin logout")
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/api/admin/me")
def admin_me(request: Request):
    try:
        admin = _get_admin_session(request)
        if not admin:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return admin
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin me error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


# ===================== ADMIN USERS API =====================

@app.get("/api/admin/users")
def admin_list_users(request: Request, search: str = "", plan: str = "", sort: str = "newest", page: int = 1, per_page: int = 20):
    try:
        require_admin(request)
        with _get_db() as conn:
            with _cursor(conn) as c:
                where = []
                params = []
                if search:
                    where.append("(name LIKE %s OR email LIKE %s OR github_username LIKE %s)")
                    params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
                if plan:
                    where.append("plan=%s")
                    params.append(plan)
                where_sql = f"WHERE {' AND '.join(where)}" if where else ""
                order = "DESC" if sort == "newest" else "ASC"
                offset = (page - 1) * per_page

                c.execute(f"SELECT COUNT(*) as cnt FROM users {where_sql}", params)
                total = _to_dict(c)["cnt"]

                c.execute(
                    f"SELECT * FROM users {where_sql} ORDER BY created_at {order} LIMIT %s OFFSET %s",
                    params + [per_page, offset]
                )
                users = _to_dicts(c)

                # Signup source breakdown
                c.execute("SELECT signup_source, COUNT(*) as cnt FROM users GROUP BY signup_source ORDER BY cnt DESC")
                sources = _to_dicts(c)

                # Plan breakdown
                c.execute("SELECT plan, COUNT(*) as cnt FROM users GROUP BY plan ORDER BY cnt DESC")
                plans = _to_dicts(c)

                # Daily signups (last 30 days)
                c.execute("""
                    SELECT DATE(created_at) as day, COUNT(*) as cnt FROM users
                    WHERE created_at >= NOW() - INTERVAL '30 days'
                    GROUP BY DATE(created_at) ORDER BY day
                """)
                daily = _to_dicts(c)

                # Recent activity
                c.execute("""
                    SELECT ua.action, ua.detail, ua.created_at, u.name, u.email
                    FROM user_activity ua LEFT JOIN users u ON ua.user_id = u.id
                    ORDER BY ua.created_at DESC LIMIT 10
                """)
                activity = _to_dicts(c)

        logger.info(f"Admin listed users: page={page}, total={total}")
        return {
            "users": users, "total": total, "page": page, "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
            "sources": sources, "plans": plans, "daily_signups": daily,
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
        api_key = f"poly_{secrets.token_urlsafe(24)}"
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute(
                    "INSERT INTO users (name, email, github_username, api_key, plan, referrer, signup_source, notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (data.name, data.email, data.github_username, api_key, data.plan, data.referrer, data.signup_source, data.notes)
                )
                user_id = _to_dict(c)["id"]
                c.execute("INSERT INTO user_activity (user_id, action, detail) VALUES (%s,%s,%s)",
                           (user_id, "signup", f"Created by admin | source: {data.signup_source or 'manual'}"))
            conn.commit()
        logger.info(f"Admin created user: {data.email} (id={user_id})")
        return {"status": "ok", "user_id": user_id, "api_key": api_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin create user error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, data: UserUpdate, request: Request):
    try:
        require_admin(request)
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id FROM users WHERE id=%s", (user_id,))
                if not c.fetchone():
                    raise HTTPException(status_code=404, detail="User not found")
                updates = []
                params = []
                for field, value in data.model_dump().items():
                    if value is not None:
                        updates.append(f"{field}=%s")
                        params.append(value)
                if not updates:
                    raise HTTPException(status_code=400, detail="No fields to update")
                params.append(user_id)
                c.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=%s", params)
                c.execute("INSERT INTO user_activity (user_id, action, detail) VALUES (%s,%s,%s)",
                           (user_id, "updated", f"Updated by admin: {', '.join(updates)}"))
            conn.commit()
        logger.info(f"Admin updated user: id={user_id}")
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin update user error: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating user: {str(e)}")


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, request: Request):
    try:
        require_admin(request)
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT name, email FROM users WHERE id=%s", (user_id,))
                row = _to_dict(c)
                if not row:
                    raise HTTPException(status_code=404, detail="User not found")
                c.execute("DELETE FROM user_activity WHERE user_id=%s", (user_id,))
                c.execute("DELETE FROM users WHERE id=%s", (user_id,))
            conn.commit()
        logger.info(f"Admin deleted user: {row['name']} (id={user_id})")
        return {"status": "ok", "deleted": row["name"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin delete user error: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting user: {str(e)}")


@app.get("/api/admin/stats")
def admin_stats(request: Request):
    try:
        require_admin(request)
        stats = {}
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT COUNT(*) as cnt FROM users")
                stats["total_users"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM users WHERE plan='pro'")
                stats["pro_users"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM users WHERE plan='enterprise'")
                stats["enterprise_users"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM users WHERE is_active=TRUE")
                stats["active_users"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM users WHERE created_at >= NOW() - INTERVAL '7 days'")
                stats["new_this_week"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM users WHERE created_at >= NOW() - INTERVAL '1 day'")
                stats["new_today"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(DISTINCT repo_id) as cnt FROM ci_runs")
                stats["total_repos"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM ci_runs WHERE timestamp >= NOW() - INTERVAL '24 hours'")
                stats["runs_today"] = _to_dict(c)["cnt"]
                c.execute("SELECT COUNT(*) as cnt FROM test_results")
                stats["total_test_results"] = _to_dict(c)["cnt"]

                # Top referrers
                c.execute("SELECT referrer, COUNT(*) as cnt FROM users WHERE referrer IS NOT NULL GROUP BY referrer ORDER BY cnt DESC LIMIT 5")
                stats["top_referrers"] = _to_dicts(c)

                # Top signup sources
                c.execute("SELECT signup_source, COUNT(*) as cnt FROM users WHERE signup_source IS NOT NULL GROUP BY signup_source ORDER BY cnt DESC LIMIT 5")
                stats["top_sources"] = _to_dicts(c)

        logger.info("Admin fetched stats")
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching stats: {str(e)}")

import urllib.request
import json as _json

_SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
_SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
_SUPABASE_ANON = os.environ.get("SUPABASE_ANON_KEY", "")

def _supabase_rest(table, method="GET", data=None, filters=None, columns="*"):
    """Direct Supabase REST API call — bypasses db module."""
    key = _SUPABASE_SERVICE_KEY or _SUPABASE_ANON
    if not key:
        logger.error("No Supabase credentials configured — set SUPABASE_SERVICE_ROLE_KEY")
        return None
    url = f"{_SUPABASE_URL}/rest/v1/{table}"
    params = []
    if columns:
        params.append(f"select={columns}")
    if filters:
        for k,v in filters.items():
            params.append(f"{k}=eq.{v}")
    if params:
        url += "?" + "&".join(params)
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
        logger.error(f"Supabase REST error: {_SUPABASE_URL}: {e}")
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

# JWT-based user sessions (survives serverless cold starts)
_USER_JWT_SECRET = os.environ.get("FALSKY_USER_SECRET", "falsky-user-secret-change-in-production")

def _create_user_token(user_id, email, name):
    """Create a JWT token for user session."""
    from datetime import datetime, timezone, timedelta
    payload = {
        "uid": user_id,
        "email": email,
        "name": name,
        "aud": "falsky-user",
        "exp": datetime.now(timezone.utc) + timedelta(days=30),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _USER_JWT_SECRET, algorithm="HS256")

def _decode_user_token(token):
    """Decode and verify a user JWT token."""
    try:
        payload = jwt.decode(token, _USER_JWT_SECRET, algorithms=["HS256"], audience="falsky-user")
        return {"user_id": payload["uid"], "email": payload["email"], "name": payload.get("name", "")}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

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
        # Create JWT session (survives cold starts)
        token = _create_user_token(user["id"], data.email, data.name)
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
        token = _create_user_token(user["id"], user["email"], user.get("name", ""))
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
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")
    session = _decode_user_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    users = _supabase_rest("users", filters={"id": session["user_id"]}, columns="id,name,email,api_key,plan,is_active")
    if not users or len(users) == 0 or not users[0].get("is_active", True):
        raise HTTPException(status_code=401, detail="Account not found")
    user = users[0]
    return {"name": user.get("name", ""), "email": user["email"], "api_key": user.get("api_key", ""), "plan": user.get("plan", "free")}

@app.post("/api/user/logout")
def user_logout(request: Request, response: Response):
    response.delete_cookie("falsky_user_token")
    return {"status": "ok"}

@app.get("/login", response_class=HTMLResponse)
def serve_login():
    return _serve_html(os.path.join("dashboard", "auth.html"), "Falsky — Sign In")

# ===================== EXISTING API ROUTES =====================

@app.post("/api/junit", dependencies=[Depends(verify_api_key)])
async def ingest_junit(request: Request, repo_name: str = Query(...), branch: str = Query("main"), commit_sha: Optional[str] = Query(None), environment: Optional[str] = Query(None)):
    try:
        content_type = request.headers.get("content-type", "")
        body_bytes = await request.body()
        if "application/xml" in content_type or "text/xml" in content_type:
            xml_content = body_bytes.decode("utf-8")
        else:
            data = JUnitUpload.parse_raw(body_bytes)
            xml_content = data.xml_content
            repo_name = data.repo_name or repo_name
            branch = data.branch or branch
            commit_sha = data.commit_sha or commit_sha
            environment = data.environment or environment
        result = process_test_run(
            xml_content=xml_content,
            repo_name=repo_name,
            branch=branch,
            commit_sha=commit_sha,
            environment=environment,
        )
        logger.info(f"Processed JUnit: {data.repo_name}, {result.get('total', 0)} tests")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"JUnit ingest error: {e}")
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")


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
            elif t.get("status") == "error":
                ET.SubElement(tc, "error", message=t.get("error_message", "Test errored"))
            elif t.get("status") == "skipped":
                ET.SubElement(tc, "skipped")
        xml_str = ET.tostring(testsuites, encoding="unicode")
        result = process_test_run(xml_content=xml_str, repo_name=data.repo_name, run_id=data.run_id, branch=data.branch, commit_sha=data.commit_sha, environment=data.environment)
        logger.info(f"Created run: {data.repo_name}, {len(data.test_results)} test results")
        return result
    except Exception as e:
        logger.error(f"Create run error: {e}")
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")


@app.get("/api/dashboard")
def dashboard(repo_name: str = Query(...), threshold: float = Query(50)):
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
        flaky_count = 0
        total_trust = 0
        for name, d in agg.items():
            trust = round(sum(d["scores"]) / len(d["scores"]), 1)
            total_trust += trust
            if d["category"]:
                flaky_count += 1
            result.append({
                "test_name": name,
                "trust_score": trust,
                "pass_rate": round(d["passes"] / d["total"], 3) if d["total"] > 0 else 0,
                "runs": d["total"],
                "flaky_category": d["category"],
                "avg_duration": round(sum(d["durations"]) / len(d["durations"]), 1) if d["durations"] else 0,
            })
        avg_trust = round(total_trust / len(result), 1) if result else 0
        return {
            "repo": repo_name,
            "tests": result,
            "total": len(result),
            "avg_trust": avg_trust,
            "flaky_count": flaky_count,
            "total_tests": len(result),
        }
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return {"repo": repo_name, "tests": [], "total": 0, "avg_trust": 0, "flaky_count": 0, "total_tests": 0}


@app.get("/api/tests")
def list_tests(repo_name: str = Query(...)):
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = _to_dict(c)
                if not row:
                    raise HTTPException(status_code=404, detail="Repository not found")
                repo_id = row["id"]
                c.execute(
                    "SELECT test_name, AVG(trust_score) as trust_score, COUNT(*) as runs, flaky_category, "
                    "AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0.0 END) as pass_rate, AVG(duration) as avg_duration "
                    "FROM test_results WHERE repo_id=%s GROUP BY test_name ORDER BY trust_score ASC",
                    (repo_id,)
                )
                tests = _to_dicts(c)
        logger.info(f"Listed tests: {repo_name}, {len(tests)} tests")
        return {"repo": repo_name, "tests": tests, "total": len(tests)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List tests error for {repo_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing tests: {str(e)}")


@app.get("/api/tests/{test_name:path}")
def test_detail(test_name: str, repo_name: str = Query(...)):
    try:
        result = get_test_detail(repo_name, test_name)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        logger.info(f"Test detail: {repo_name}/{test_name}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test detail error for {repo_name}/{test_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching test detail: {str(e)}")


@app.get("/api/quarantined")
def quarantined(repo_name: str = Query(...), threshold: float = Query(30)):
    try:
        result = {"repo": repo_name, "threshold": threshold, "quarantined": get_quarantined_tests(repo_name, threshold)}
        logger.info(f"Quarantined tests: {repo_name}, threshold={threshold}")
        return result
    except Exception as e:
        logger.error(f"Quarantined error for {repo_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching quarantined tests: {str(e)}")


@app.get("/api/runs")
def list_runs(repo_name: str = Query(...), limit: int = Query(20, le=100)):
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = _to_dict(c)
                if not row:
                    raise HTTPException(status_code=404, detail="Repository not found")
                repo_id = row["id"]
                c.execute(
                    "SELECT run_id, branch, commit_sha, total_tests, passed, failed, avg_trust_score, timestamp "
                    "FROM ci_runs WHERE repo_id=%s ORDER BY timestamp DESC LIMIT %s",
                    (repo_id, limit)
                )
                runs = _to_dicts(c)
        logger.info(f"Listed runs: {repo_name}, {len(runs)} runs")
        return {"repo": repo_name, "runs": runs}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List runs error for {repo_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing runs: {str(e)}")


@app.get("/api/repos")
def list_repos():
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute(
                    "SELECT r.name, COUNT(DISTINCT tr.run_id) as total_runs, COUNT(DISTINCT tr.test_name) as total_tests, AVG(tr.trust_score) as avg_trust "
                    "FROM repositories r LEFT JOIN test_results tr ON r.id = tr.repo_id GROUP BY r.name ORDER BY r.name"
                )
                repos = _to_dicts(c)
        logger.info(f"Listed repos: {len(repos)} repos")
        return {"repos": repos}
    except Exception as e:
        logger.error(f"List repos error: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing repos: {str(e)}")


@app.post("/api/alerts/config", dependencies=[Depends(verify_api_key)])
def set_alert_config(repo_name: str = Query(...), config: AlertConfig = ...):
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                # Ensure repo exists
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = _to_dict(c)
                if not row:
                    c.execute("INSERT INTO repositories (name) VALUES (%s) RETURNING id", (repo_name,))
                    row = _to_dict(c)
                if not row:
                    raise HTTPException(status_code=404, detail="Not found")
                repo_id = row["id"]
                c.execute(
                    "INSERT INTO alerts_config (repo_id, webhook_url, channel_type, min_trust_drop, alert_on_flaky, alert_on_quarantine) VALUES (%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (repo_id) DO UPDATE SET webhook_url=EXCLUDED.webhook_url, channel_type=EXCLUDED.channel_type, "
                    "min_trust_drop=EXCLUDED.min_trust_drop, alert_on_flaky=EXCLUDED.alert_on_flaky, alert_on_quarantine=EXCLUDED.alert_on_quarantine",
                    (repo_id, config.webhook_url, config.channel_type, config.min_trust_drop, config.alert_on_flaky, config.alert_on_quarantine)
                )
                conn.commit()
        logger.info(f"Alert config set: {repo_name}")
        return {"status": "ok", "repo": repo_name}
    except Exception as e:
        logger.error(f"Alert config error for {repo_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error setting alert config: {str(e)}")


@app.post("/api/alerts/test", dependencies=[Depends(verify_api_key)])
def test_alert(repo_name: str = Query(...)):
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT * FROM alerts_config WHERE repo_id=(SELECT id FROM repositories WHERE name=%s)", (repo_name,))
                cfg = _to_dict(c)
        if not cfg:
            raise HTTPException(status_code=404, detail="No alert config found")
        ok = send_alert(repo_name=repo_name, webhook_url=cfg["webhook_url"], channel_type=cfg["channel_type"], alert_data={"Test": "Poly connectivity test", "Status": "Alert channel working"})
        logger.info(f"Alert test sent: {repo_name}, result={'ok' if ok else 'failed'}")
        return {"status": "sent" if ok else "failed"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert test error for {repo_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error testing alert: {str(e)}")


@app.delete("/api/tests/{test_name:path}", dependencies=[Depends(verify_api_key)])
def delete_test(test_name: str, repo_name: str = Query(...)):
    try:
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = _to_dict(c)
                if not row:
                    raise HTTPException(status_code=404, detail="Repository not found")
                c.execute("DELETE FROM test_results WHERE repo_id=%s AND test_name=%s", (row["id"], test_name))
                deleted = c.rowcount
            conn.commit()
        logger.info(f"Deleted test: {repo_name}/{test_name}, {deleted} rows")
        return {"status": "ok", "deleted": deleted}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete test error for {repo_name}/{test_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting test: {str(e)}")


def _badge_svg(score: float, label: str = "poly trust") -> str:
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
        with _get_db() as conn:
            with _cursor(conn) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = _to_dict(c)
                if not row:
                    return HTMLResponse(content=_badge_svg(100, "no data"), media_type="image/svg+xml")
                c.execute("SELECT AVG(trust_score) as avg_trust FROM test_results WHERE repo_id=%s", (row["id"],))
                row = _to_dict(c)
        score = round((row or {}).get("avg_trust") or 100, 0)
        return HTMLResponse(content=_badge_svg(score), media_type="image/svg+xml")
    except Exception:
        # DB not configured or any error — return safe default badge
        return HTMLResponse(content=_badge_svg(100, "no data"), media_type="image/svg+xml")


# ===================== PAGE ROUTES =====================

@app.get("/dashboard/", response_class=HTMLResponse)
def serve_dashboard():
    return FileResponse(os.path.join(base_path, "dashboard", "index.html"))


@app.get("/dashboard/test-detail.html", response_class=HTMLResponse)
def serve_test_detail():
    path = os.path.join(base_path, "dashboard", "test-detail.html")
    if os.path.exists(path):
        return FileResponse(path)
    return HTMLResponse("<h1>Test Detail</h1>", status_code=404)


@app.get("/dashboard/guide.html", response_class=HTMLResponse)
def serve_guide():
    path = os.path.join(base_path, "dashboard", "guide.html")
    if os.path.exists(path):
        return FileResponse(path)
    return HTMLResponse("<h1>Guide</h1>", status_code=404)


@app.get("/admin/", response_class=HTMLResponse)
def serve_admin():
    return FileResponse(os.path.join(base_path, "dashboard", "admin.html"))


@app.get("/landing/", response_class=HTMLResponse)
def serve_landing():
    return RedirectResponse(url="/")


# ===================== FAVICON & 404 =====================

@app.get("/favicon.ico")
def favicon():
    """Inline SVG favicon — no file needed."""
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           '<rect width="32" height="32" rx="8" fill="#8b5cf6"/>'
           '<text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" '
           'fill="#fff" font-family="system-ui" font-weight="800" font-size="18">P</text></svg>')
    return HTMLResponse(content=svg, media_type="image/svg+xml")


@app.get("/robots.txt")
def robots():
    return HTMLResponse(content="User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /admin/", media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)