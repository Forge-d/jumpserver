"""
apps/authentication/backends/grydd_m2m/middleware.py

Responsibility: guard the session creation endpoint ONLY.

This middleware activates ONLY when X-User-Token header is present.
That header only appears on calls to /api/v1/authentication/m2m/session/.

Once the IAM extension has a JumpServer session and CSRF token
(stored in UserSessionModel notes), it sends them directly as:
    Cookie: jms_sessionid=...; jms_csrftoken=...
    X-CSRFToken: ...

Those requests reach JumpServer's existing session and CSRF machinery
with no middleware involvement. Django resolves the user from jms_sessionid
exactly as it would for a normal browser login.

This middleware is NOT involved in those calls at all.
"""

import base64
import logging
import os

import jwt
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from jumpserver.const import CONFIG

logger = logging.getLogger(__name__)
PLATFORM_IAM_SERVER_URL = CONFIG.get('PLATFORM_IAM_SERVER_URL', '')
PLATFORM_MASTER_TENANT = CONFIG.get('PLATFORM_MASTER_TENANT', '')   
IAM_BASE                = f"{PLATFORM_IAM_SERVER_URL}/tenants/{PLATFORM_MASTER_TENANT}" 
IAM_JWKS_URL            = f"{IAM_BASE}/protocol/openid-connect/certs"

M2M_CLIENT_ID     = CONFIG.get('JMS_M2M_CLIENT_ID',     'jumpserver-bridge')
M2M_CLIENT_SECRET = CONFIG.get('JMS_M2M_CLIENT_SECRET', 'your-client-secret')

SESSION_CREATION_PATH = "/api/v1/authentication/m2m/session/"


class IAMM2MMiddleware(MiddlewareMixin):
    """
    Activated only when X-User-Token header is present.
    All other requests — including all API calls from the IAM extension
    once they have a session — pass through with zero overhead.
    """

    def process_request(self, request):
        user_token = request.META.get("HTTP_X_USER_TOKEN", "").strip()

        # No X-User-Token → not a session creation request.
        # This covers ALL normal API calls from the IAM extension
        # (which send jms_sessionid cookie + X-CSRFToken header directly).
        # Django's existing session and CSRF middleware handle those normally.
        if not user_token:
            return None

        # X-User-Token is only valid on the session creation endpoint.
        if request.path != SESSION_CREATION_PATH:
            return JsonResponse(
                {"error": "X-User-Token is only accepted on the session creation endpoint"},
                status=403
            )

        # ── Validate Basic auth — WHO is calling ──────────────────────────────
        # Confirms the caller is the authorised jumpserver-bridge M2M client.
        auth_error = self._validate_basic_auth(request)
        if auth_error:
            return auth_error

        # ── Validate X-User-Token — FOR WHOM ─────────────────────────────────
        # Confirms the token is genuinely from our IAM realm (RS256).
        # Audience is not verified here — the raw token has a broad audience.
        # The EXCHANGED token's audience is verified in the view after exchange.
        try:
            jwks     = jwt.PyJWKClient(IAM_JWKS_URL)
            sign_key = jwks.get_signing_key_from_jwt(user_token)
            payload  = jwt.decode(
                user_token,
                sign_key.key,
                algorithms=["RS256"],
                issuer=IAM_BASE,
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "X-User-Token has expired"}, status=401)
        except Exception as e:
            logger.warning("M2M middleware: invalid X-User-Token: %s", e)
            return JsonResponse({"error": f"Invalid X-User-Token: {e}"}, status=401)

        # ── Cross-check username ───────────────────────────────────────────────
        # Prevents sending a valid token for alice but claiming to be admin.
       # token_username   = payload.get("preferred_username", "")
        token_username   = payload.get("sub", "")
        impersonate_user = request.META.get("HTTP_X_IMPERSONATE_USER", "").strip()

        if not impersonate_user:
            return JsonResponse(
                {"error": "X-Impersonate-User header required"},
                status=400
            )

        if token_username != impersonate_user:
            logger.warning(
                "M2M middleware: username mismatch token=%s header=%s",
                token_username, impersonate_user
            )
            return JsonResponse(
                {"error": "X-Impersonate-User does not match token subject"},
                status=403
            )

        # Attach validated data for the view — avoids re-parsing the token
        request.m2m_username   = token_username
        request.m2m_kc_payload = payload

        # Pass through to create_m2m_session view
        return None

    def _validate_basic_auth(self, request) -> JsonResponse | None:
        """
        Validates Authorization: Basic <base64(client_id:client_secret)>.
        Returns a JsonResponse error if invalid, None if valid.
        """
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Basic "):
            return JsonResponse(
                {"error": "Authorization: Basic header required"},
                status=401
            )

        try:
            decoded       = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return JsonResponse({"error": "Malformed Basic auth header"}, status=401)

        if client_id != M2M_CLIENT_ID or client_secret != M2M_CLIENT_SECRET:
            logger.warning(
                "M2M middleware: invalid Basic auth client_id=%s", client_id
            )
            return JsonResponse({"error": "Invalid client credentials"}, status=401)

        return None