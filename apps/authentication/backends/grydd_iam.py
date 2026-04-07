"""
IAM OIDC + OAuth2 Authorization Code + PKCE authentication backend.
"""
import base64
import hashlib
import logging
import os

import requests
from django.contrib.auth import get_user_model

from authentication.backends.base import JMSModelBackend

logger = logging.getLogger(__name__)
User = get_user_model()


# ── PKCE Helpers ──────────────────────────────────────────────────────────────

def generate_code_verifier(length=64) -> str:
    """RFC 7636 code_verifier: 43-128 chars, URL-safe chars only."""
    token = os.urandom(length)
    return base64.urlsafe_b64encode(token).rstrip(b'=').decode('ascii')


def generate_code_challenge(verifier: str, method: str = 'S256') -> str:
    """RFC 7636 code_challenge."""
    if method == 'S256':
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier  # plain


def generate_state() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')


# ── Token Validation ──────────────────────────────────────────────────────────

def validate_id_token(id_token: str, iam_config) -> dict:
    """
    Validate the IAM id_token JWT.
    Verifies signature, iss, aud, exp.
    Returns decoded claims dict.
    """
    import jwt  # PyJWT

    jwks = jwt.PyJWKClient(iam_config.jwks_uri)
    signing_key = jwks.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=iam_config.client_id,
        options={"verify_exp": True},
    )

    expected_iss = iam_config.issuer
    if claims.get('iss') != expected_iss:
        raise ValueError(
            f"Token issuer mismatch: expected {expected_iss}, "
            f"got {claims.get('iss')}"
        )

    return claims


# ── Token Exchange ────────────────────────────────────────────────────────────

def exchange_code_for_tokens(code: str, code_verifier: str,
                              redirect_uri: str, iam_config) -> dict:
    """
    Exchange authorization code + PKCE verifier for tokens.
    Returns {'access_token', 'id_token', 'refresh_token', ...}
    """
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': iam_config.client_id,
        'code_verifier': code_verifier,
    }
    if iam_config.client_secret:
        data['client_secret'] = iam_config.client_secret

    resp = requests.post(
        iam_config.token_endpoint,
        data=data,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


# ── Django Auth Backend ───────────────────────────────────────────────────────

class IAMOIDCBackend(JMSModelBackend):
    """
    Django authentication backend for IAM OIDC.
    Called after token validation — receives validated claims + tenant.
    """

    def authenticate(self, request, iam_claims=None, iam_config=None, **kwargs):
        if iam_claims is None or iam_config is None:
            return None
        return self._get_or_create_user(iam_claims, iam_config)

    def _get_or_create_user(self, claims: dict, iam_config):
        username = claims.get(iam_config.claim_username)
        email = claims.get(iam_config.claim_email, '')
        name = claims.get(iam_config.claim_name, username)

        if not username:
            logger.error(
                "IAM token missing username claim '%s'",
                iam_config.claim_username
            )
            return None

         # Simple username — no tenant namespace needed
        user = User.objects.filter(username=username).first()

        if user:
            # Sync mutable fields on every login
            changed = False
            if email and user.email != email:
                user.email = email
                changed = True
            if name and user.name != name:
                user.name = name
                changed = True
            if changed:
                user.save(update_fields=['email', 'name'])

        else:
            # Step 2: check if email already exists
            existing_by_email = (
                User.objects.filter(email=email).first() if email else None
            )

            if existing_by_email:
                existing_by_email.username = username
                existing_by_email.is_active = True
                existing_by_email.source = 'grydd-iam'
                existing_by_email.save(
                    update_fields=['username', 'is_active', 'source']
                )
                user = existing_by_email

            else:
                
                user = User(
                    username=username,
                    email=email,
                    name=name or username,
                    is_active=True,
                    source='grydd-iam',
                )
                user.set_unusable_password()
                user.save()

        return user   
  

    # ── Django Backend Required Method ────────────────────────────────────────

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None