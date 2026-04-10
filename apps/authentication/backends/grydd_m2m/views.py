"""
apps/authentication/backends/grydd_m2m/views.py

Two endpoints:

POST /api/v1/authentication/m2m/session/
    Called by IAM extension to create a JumpServer session for a user.
    Secured by IAMM2MMiddleware (Basic auth + X-User-Token validation).
    Returns {session_id, csrf_token, expires_in}.
    The IAM extension stores these in UserSessionModel notes — that IS
    the cache. No redundant Redis caching of session credentials here.

POST /api/v1/authentication/iam/backchannel-logout/
    Called by IAM when a user logs out.
    Validates the signed logout_token JWT.
    Looks up the Django session_key via a minimal iam_sid → session_key
    mapping in Redis (stored at session creation time for this purpose only).
    Deletes the Django session immediately.
"""

import logging
import os
import secrets

import jwt
import requests as http_requests
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from jumpserver.const import CONFIG

logger = logging.getLogger(__name__)
User   = get_user_model()

# PLATFORM_IAM_SERVER_URL = os.environ.get("PLATFORM_IAM_SERVER_URL", "")
# PLATFORM_MASTER_TENANT = os.environ.get("PLATFORM_MASTER_TENANT", "")  
# IAM_BASE           = f"{PLATFORM_IAM_SERVER_URL}/tenants/{PLATFORM_MASTER_TENANT}"
# IAM_JWKS_URL       = f"{IAM_BASE}/protocol/openid-connect/certs"
# IAM_TOKEN_URL      = f"{IAM_BASE}/protocol/openid-connect/token"
# IAM_USERINFO_URL   = f"{IAM_BASE}/protocol/openid-connect/userinfo"

# M2M_CLIENT_ID     = os.environ.get("JMS_M2M_CLIENT_ID",     "jumpserver-bridge")
# M2M_CLIENT_SECRET = os.environ.get("JMS_M2M_CLIENT_SECRET", "your-client-secret")
# JMS_OIDC_CLIENT   = os.environ.get("JMS_OIDC_CLIENT_ID",    "jumpserver")

PLATFORM_IAM_SERVER_URL = CONFIG.get('PLATFORM_IAM_SERVER_URL', '')
PLATFORM_MASTER_TENANT = CONFIG.get('PLATFORM_MASTER_TENANT', '')  
IAM_BASE           = f"{PLATFORM_IAM_SERVER_URL}/tenants/{PLATFORM_MASTER_TENANT}"
IAM_JWKS_URL       = f"{IAM_BASE}/protocol/openid-connect/certs"
IAM_TOKEN_URL      = f"{IAM_BASE}/protocol/openid-connect/token"
IAM_USERINFO_URL   = f"{IAM_BASE}/protocol/openid-connect/userinfo"

M2M_CLIENT_ID     = CONFIG.get('JMS_M2M_CLIENT_ID',     'jumpserver-bridge')
M2M_CLIENT_SECRET = CONFIG.get('JMS_M2M_CLIENT_SECRET', 'your-client-secret')
JMS_OIDC_CLIENT   = CONFIG.get('JMS_OIDC_CLIENT_ID',    'jumpserver')

# Minimal Redis keys for logout only — NOT a session cache
# iam_sid → Django session_key  (precise per-session logout)
# iam_sub → Django session_key  (admin forced logout, all sessions)
_LOGOUT_BY_SID = "m2m:logout:sid:{iam_sid}"
_LOGOUT_BY_SUB = "m2m:logout:sub:{iam_sub}"


# ─────────────────────────────────────────────────────────────────────────────
# Session creation
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def create_m2m_session(request):
    """
    Creates a real JumpServer Django session for the IAM user.

    By the time this view runs, IAMM2MMiddleware has already:
      ✓ Validated Authorization: Basic header (jumpserver-bridge credentials)
      ✓ Validated X-User-Token RS256 signature and issuer
      ✓ Cross-checked X-Impersonate-User == token.preferred_username
      ✓ Set request.m2m_username and request.m2m_iam_payload

    This view:
      1. Token exchange: JumpServer calls IAM as jumpserver-bridge
         (HTTP Basic auth) to exchange alice's raw token for one scoped
         to aud=jumpserver
      2. Validates the exchanged token (aud, iss, exp)
      3. Fetches userinfo with the exchanged token
      4. Gets or creates the local JumpServer user
      5. Creates a Django session owned by alice
      6. Generates CSRF secret stored in the session
      7. Stores a minimal iam_sid → session_key mapping in Redis for logout
      8. Returns {session_id, csrf_token, expires_in}

    The IAM extension stores the returned credentials in UserSessionModel
    notes. That is the authoritative cache — no additional Redis caching here.
    """

    # Set by middleware after validation
    username        = getattr(request, "m2m_username", None)
    alice_raw_token = request.META.get("HTTP_X_USER_TOKEN", "").strip()

    if not username or not alice_raw_token:
        return JsonResponse({"error": "Middleware validation missing"}, status=500)

    # ── Step 1: Token Exchange ────────────────────────────────────────────────
    # JumpServer authenticates to IAM as jumpserver-bridge via HTTP Basic.
    # alice's raw token is the subject_token. Result is scoped to aud=jumpserver.
    #
    # Equivalent curl:
    #   curl -u "jumpserver-bridge:secret"
    #        -d "grant_type=token-exchange"
    #        -d "subject_token=<alice-raw-token>"
    #        -d "audience=jumpserver"
    try:
        exchange_resp = http_requests.post(
            IAM_TOKEN_URL,
            auth=(M2M_CLIENT_ID, M2M_CLIENT_SECRET),
            data={
                "grant_type":
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token":
                    alice_raw_token,
                "subject_token_type":
                    "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type":
                    "urn:ietf:params:oauth:token-type:access_token",
                # "audience":
                #     JMS_OIDC_CLIENT,
                "scope":
                    "openid profile email",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
    except http_requests.RequestException as exc:
        logger.error("M2M token exchange: IAM unreachable: %s", exc)
        return JsonResponse({"error": f"IAM unreachable: {exc}"}, status=503)

    if exchange_resp.status_code != 200:
        logger.error(
            "M2M token exchange failed user=%s HTTP=%d %s",
            username, exchange_resp.status_code, exchange_resp.text
        )
        return JsonResponse(
            {"error": f"Token exchange failed: {exchange_resp.text}"},
            status=503
        )

    exchange_data   = exchange_resp.json()
    exchanged_token = exchange_data.get("access_token")
    expires_in      = exchange_data.get("expires_in", 300)

    if not exchanged_token:
        return JsonResponse({"error": "No access_token in exchange response"}, status=503)

    # ── Step 2: Validate the exchanged token ──────────────────────────────────
    # aud MUST be "jumpserver" — confirms the exchange scoped correctly.
    try:
        jwks        = jwt.PyJWKClient(IAM_JWKS_URL)
        sign_key    = jwks.get_signing_key_from_jwt(exchanged_token)
        exc_payload = jwt.decode(
            exchanged_token,
            sign_key.key,
            algorithms=["RS256"],
#            audience=JMS_OIDC_CLIENT,
            issuer=IAM_BASE,
        )
    except Exception as exc:
        logger.error("M2M exchanged token invalid: %s", exc)
        return JsonResponse({"error": f"Exchanged token invalid: {exc}"}, status=500)

    iam_sub = exc_payload.get("sub", "")
    iam_sid = exc_payload.get("sid", "")   # IAM session ID — needed for logout

    # ── Step 3: Fetch userinfo ─────────────────────────────────────────────────
    try:
        userinfo_resp = http_requests.get(
            IAM_USERINFO_URL,
            headers={"Authorization": f"Bearer {exchanged_token}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
    except http_requests.RequestException as exc:
        logger.error("M2M userinfo fetch failed user=%s: %s", username, exc)
        return JsonResponse({"error": f"Userinfo fetch failed: {exc}"}, status=503)

    userinfo = userinfo_resp.json()
    email    = userinfo.get("email", "")
    name     = userinfo.get("name", username)

    # ── Step 4: Get or create local JumpServer user ───────────────────────────
    # Mirrors JumpServer's OIDC backend — keeps profile in sync with IAM.
    try:
        local_user, created = User.objects.update_or_create(
            username=username,
            defaults={
                "email":     email,
                "name":      name,
                "source":    "openid",
                "is_active": True,
            },
        )
    except Exception as exc:
        logger.error("M2M user update_or_create failed user=%s: %s", username, exc)
        return JsonResponse({"error": "Database error"}, status=500)

    if not local_user.is_active:
        logger.warning("M2M session denied: user=%s is disabled", username)
        return JsonResponse({"error": "User is disabled in JumpServer"}, status=403)

    if created:
        logger.info("M2M: auto-created JumpServer user=%s", username)

    # ── Step 5: Create Django session owned by alice ───────────────────────────
    # Identical to what JumpServer's OIDC backend creates on browser login.
    # _auth_user_id = alice.pk → all audit logs record alice's username.
    session = SessionStore()
    session.create()
    session["_auth_user_id"]      = str(local_user.pk)
    session["_auth_user_backend"] = (
        "authentication.backends.grydd_iam.IAMOIDCBackend"
    )
    session["_auth_user_hash"]    = local_user.get_session_auth_hash()

    # ── Step 6: Generate CSRF secret ──────────────────────────────────────────
    # Stored inside the session. Django's CsrfViewMiddleware reads _csrf_token
    # from the session and compares it to the X-CSRFToken header value.
    csrf_secret            = secrets.token_hex(32)
    session["_csrf_token"] = csrf_secret
    session.save()

    session_key = session.session_key
    ttl         = max(expires_in - 60, 60)

    logger.info(
        "M2M Django session created user=%s session=%s ttl=%ds",
        username, session_key, ttl
    )

    # ── Step 7: Store minimal logout mapping in Redis ──────────────────────────
    # We store ONLY what is needed to delete the Django session on backchannel
    # logout. We do NOT store session credentials here — those live in the
    # IAM extension's UserSessionModel notes, which is the real cache.
    if iam_sid:
        cache.set(
            _LOGOUT_BY_SID.format(iam_sid=iam_sid),
            session_key,
            timeout=ttl
        )
    if iam_sub:
        cache.set(
            _LOGOUT_BY_SUB.format(iam_sub=iam_sub),
            session_key,
            timeout=ttl
        )

    # ── Step 8: Return to IAM extension ──────────────────────────────────
    # The extension stores these in UserSessionModel notes.
    # That is the authoritative store — no further caching needed here.
    return JsonResponse({
        "session_id": session_key,
        "csrf_token": csrf_secret,
        "expires_in": ttl,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Backchannel logout
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def backchannel_logout(request):
    """
    Called by IAM when a user logs out from any client in the realm.

    Validates the signed logout_token JWT per OIDC Back-Channel Logout spec.
    Uses the minimal iam_sid → session_key Redis mapping (stored at session
    creation time) to find and delete the Django session immediately.

    IAM setup:
      Clients → jumpserver → Settings
        Backchannel logout URL:
          https://your-jumpserver/api/v1/authentication/iam/backchannel-logout/
        Backchannel logout session required: ON
          (ensures sid is present in the logout token)
    """
    logout_token = request.POST.get("logout_token", "").strip()
    if not logout_token:
        return JsonResponse({"error": "logout_token missing"}, status=400)

    # ── Validate logout token ──────────────────────────────────────────────────
    try:
        jwks    = jwt.PyJWKClient(IAM_JWKS_URL)
        key     = jwks.get_signing_key_from_jwt(logout_token)
        payload = jwt.decode(
            logout_token,
            key.key,
            algorithms=["RS256"],
#            audience=JMS_OIDC_CLIENT,
            issuer=IAM_BASE,
        )
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "logout_token has expired"}, status=400)
    except Exception as exc:
        logger.warning("Backchannel logout: invalid token: %s", exc)
        return JsonResponse({"error": f"Invalid logout_token: {exc}"}, status=400)

    if payload.get("typ") != "Logout":
        return JsonResponse({"error": "Token type is not Logout"}, status=400)

    if "nonce" in payload:
        return JsonResponse({"error": "Logout token must not contain nonce"}, status=400)

    if "http://schemas.openid.net/event/backchannel-logout" not in payload.get("events", {}):
        return JsonResponse({"error": "Missing backchannel-logout event"}, status=400)

    # ── Delete the Django session ──────────────────────────────────────────────
    iam_sid = payload.get("sid")
    iam_sub = payload.get("sub")

    session_key = None

    if iam_sid:
        # Precise: delete this specific session
        session_key = cache.get(_LOGOUT_BY_SID.format(iam_sid=iam_sid))
        cache.delete(_LOGOUT_BY_SID.format(iam_sid=iam_sid))

    if not session_key and iam_sub:
        # Fallback: admin forced logout — no sid in token
        session_key = cache.get(_LOGOUT_BY_SUB.format(iam_sub=iam_sub))
        cache.delete(_LOGOUT_BY_SUB.format(iam_sub=iam_sub))

    if session_key:
        SessionStore(session_key=session_key).delete()
        logger.info(
            "Backchannel logout: deleted Django session=%s sid=%s sub=%s",
            session_key, iam_sid, iam_sub
        )
    else:
        # Session already expired in Redis — nothing to delete, not an error
        logger.debug(
            "Backchannel logout: no active session found for sid=%s sub=%s",
            iam_sid, iam_sub
        )

    # Spec: return 200 with empty body regardless
    return HttpResponse(status=200)