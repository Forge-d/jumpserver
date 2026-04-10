"""
apps/authentication/backends/grydd_m2m/urls.py

Register in apps/jumpserver/urls.py:
    path("", include("authentication.backends.grydd_m2m.urls")),
"""

from django.urls import path
from .views import create_m2m_session, backchannel_logout

urlpatterns = [

    # ── Session creation ───────────────────────────────────────────────────────
    # Called by IAM extension (server-side, not browser).
    # Auth:    Authorization: Basic <jumpserver-bridge:secret>
    #          X-User-Token: <alice's raw IAM access token>
    #          X-Impersonate-User: alice
    # Returns: {session_id, csrf_token, expires_in}
    path(
        "api/v1/authentication/m2m/session/",
        create_m2m_session,
        name="m2m-session-create",
    ),

    # ── Backchannel logout ─────────────────────────────────────────────────────
    # Called by IAM when a user logs out.
    # Auth:    logout_token JWT in POST body (signed by IAM RS256)
    # Action:  deletes Django session + Redis keys immediately
    # Register this URL in IAM:
    #   Clients → jumpserver → Settings → Backchannel logout URL
    path(
        "api/v1/authentication/iam/backchannel-logout/",
        backchannel_logout,
        name="iam-backchannel-logout",
    ),
]