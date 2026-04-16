"""
IAM OIDC + OAuth2 Authorization Code + PKCE authentication backend.
"""
import base64
import hashlib
import logging
import os
import threading

import requests
from django.contrib.auth import get_user_model

from authentication.backends.base import JMSModelBackend

logger = logging.getLogger('jumpserver.authentication.iam')
User = get_user_model()


def trigger_iam_backchannel_logout(id_token_hint: str, iam_config) -> None:
    """
    Terminate the IAM SSO session server-to-server (backchannel logout).

    Called when a JumpServer user logs out so the IAM provider won't silently
    re-authenticate them on the very next request.  Runs in a daemon thread so
    it never blocks the HTTP response.
    """
    endpoint = getattr(iam_config, 'end_session_endpoint', None)
    if not endpoint:
        return

    def _call():
        params = {}
        if id_token_hint:
            params['id_token_hint'] = id_token_hint
        try:
            requests.get(endpoint, params=params, timeout=5, allow_redirects=False)
            logger.info("IAM backchannel logout: SSO session cleared")
        except Exception as exc:
            logger.warning("IAM backchannel logout failed: %s", exc)

    threading.Thread(target=_call, daemon=True).start()

# ── Default Role Mapping ──────────────────────────────────────────────────────
# Maps Keycloak group names (from 'groups' claim) → JumpServer role names.
# Override via IAMConfig.role_mapping in DB (shell or API).
# Valid JumpServer system roles: SystemAdmin, SystemAuditor, User
DEFAULT_ROLE_MAPPING = {
    'System_Administrator': 'SystemAdmin',
    'System_Auditors': 'SystemAuditor',
    'System_Users': 'User',
}


# ── IAM ACR Namespace Constants ───────────────────────────────────────────────
# urn:iam:acr:<factors>:<method> namespace used by this IAM deployment.
# Any value starting with this prefix confirms two-factor (MFA) authentication.
IAM_ACR_2FA_PREFIX = 'urn:iam:acr:2fa:'

# Explicit single-factor ACR values — these are definitively NOT MFA.
IAM_ACR_1FA_VALUES = {
    'urn:iam:acr:1fa:any',
    'urn:iam:acr:1fa:pwd',
}

# AMR method identifiers that indicate a second authentication factor was used.
_MFA_AMR_METHODS = {
    'otp', 'mfa', 'totp', 'hotp', 'sms', 'email',
    'push', 'u2f', 'fido', 'fido2', 'webauthn', 'kc_otp',
}


def check_iam_mfa_from_claims(claims: dict, iam_config) -> bool:
    """
    Return True if the IAM ID token proves MFA (two factors) was performed.

    Evaluation order:
    1. ACR claim — urn:iam:acr:2fa:* prefix → MFA confirmed (LoA 2 / AAL2).
                   urn:iam:acr:1fa:* values → single factor only, return False.
                   iam_config.mfa_acr_values (JSON list) → extra configured values.
    2. AMR claim — presence of any known second-factor method identifier
                   (fallback when ACR is absent or unrecognised).

    Never modifies JumpServer's existing MFA backends or session logic — it only
    informs the IAM callback view whether to pre-populate auth_mfa session keys.
    """
    acr = claims.get('acr', '')

    # ── ACR-based check (primary) ─────────────────────────────────────────────
    if acr:
        if acr.startswith(IAM_ACR_2FA_PREFIX):
            # e.g. urn:iam:acr:2fa:any  ←  MFA confirmed
            return True

        if acr in IAM_ACR_1FA_VALUES:
            # Explicitly single-factor; skip AMR fallback
            return False

        # Administrator-configured extra ACR values stored in IAMConfig
        extra = getattr(iam_config, 'mfa_acr_values', None) or []
        if acr in extra:
            return True

    # ── AMR-based fallback ────────────────────────────────────────────────────
    amr = claims.get('amr', [])
    if isinstance(amr, list) and _MFA_AMR_METHODS.intersection(set(amr)):
        return True

    return False


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

        # Sync roles from token on every login
        self._sync_roles(user, claims, iam_config)

        return user   
    

    def _get_role_mapping(self, iam_config) -> dict:
        """
        Get effective role mapping.
        Uses DB config if set, otherwise falls back to DEFAULT_ROLE_MAPPING.
        """
        db_mapping = getattr(iam_config, 'role_mapping', None) or {}
        if db_mapping:
            logger.debug("Using role_mapping from DB: %s", db_mapping)
            return db_mapping
        logger.debug("Using DEFAULT_ROLE_MAPPING: %s", DEFAULT_ROLE_MAPPING)
        return DEFAULT_ROLE_MAPPING

    def _sync_roles(self, user, claims: dict, iam_config):
        """
        Sync JumpServer system roles from the 'groups' claim on every login.

        IAM sends groups as:
            {"groups": ["System_Administrator", "System_Users"]}

        role_mapping (from DB or DEFAULT_ROLE_MAPPING) maps:
            {"System_Administrator": "SystemAdmin", "System_Users": "User"}

        On every login:
          - Groups present in token → roles assigned in JumpServer
          - Groups removed in IAM → roles removed in JumpServer on next login
          - Only roles listed as values in role_mapping are managed here
            (manually assigned roles outside the mapping are never touched)
        """
        try:
            from rbac.models import Role, RoleBinding
            from django.db import connection

            role_mapping = self._get_role_mapping(iam_config)

            # ── Read 'groups' claim only ───────────────────────────────────
            raw_groups = claims.get('groups', [])
            # Normalise: strip leading slash in case full path is used
            token_groups = {g.lstrip('/') for g in raw_groups}

            logger.info(
                "Role sync: user=%s token_groups=%s role_mapping=%s",
                user.username, token_groups, role_mapping
            )

            # ── Determine which JumpServer roles the user should have ──────
            target_role_names = {
                js_role
                for iam_group, js_role in role_mapping.items()
                if iam_group in token_groups
            }

            logger.info(
                "Role sync: user=%s target_roles=%s",
                user.username, target_role_names
            )

            # ── Managed role names — only roles we control ─────────────────
            managed_role_names = set(role_mapping.values())

            # ── Get current managed bindings via raw SQL ───────────────────
            # Raw SQL needed because RoleBinding's custom manager
            # applies org context filters that hide system-scoped bindings
            with connection.cursor() as cursor:
                cursor.execute('''
                    SELECT rb.id, r.name
                    FROM rbac_rolebinding rb
                    JOIN rbac_role r ON rb.role_id = r.id
                    WHERE rb.user_id = %s
                    AND r.name = ANY(%s)
                    AND rb.org_id IS NULL
                ''', [str(user.id), list(managed_role_names)])
                current_bindings = {
                    row[1]: row[0]   # role_name → binding_id
                    for row in cursor.fetchall()
                }

            logger.info(
                "Role sync: user=%s current_managed_roles=%s",
                user.username, list(current_bindings.keys())
            )

            # ── Remove roles no longer in token ───────────────────────────
            roles_to_remove = set(current_bindings.keys()) - target_role_names
            if roles_to_remove:
                binding_ids_to_delete = [
                    current_bindings[name]
                    for name in roles_to_remove
                ]
                with connection.cursor() as cursor:
                    cursor.execute(
                        'DELETE FROM rbac_rolebinding WHERE id = ANY(%s)',
                        [binding_ids_to_delete]
                    )
                logger.info(
                    "Role sync: removed roles=%s from user=%s",
                    roles_to_remove, user.username
                )

            # ── Add roles now in token ─────────────────────────────────────
            roles_to_add = target_role_names - set(current_bindings.keys())
            if roles_to_add:
                # Fetch role objects for roles to add
                roles = {
                    r.name: r
                    for r in Role.objects.filter(
                        name__in=roles_to_add,
                        scope='system'
                    )
                }
                for role_name in roles_to_add:
                    role = roles.get(role_name)
                    if not role:
                        logger.warning(
                            "Role '%s' not found in JumpServer — skipping",
                            role_name
                        )
                        continue
                    RoleBinding.objects.create(
                        user=user,
                        role=role,
                        org=None,
                    )
                    logger.info(
                        "Role sync: assigned role=%s to user=%s",
                        role_name, user.username
                    )

            if not roles_to_remove and not roles_to_add:
                logger.info(
                    "Role sync: no changes needed for user=%s",
                    user.username
                )

        except Exception as e:
            # Never block login due to role sync failure
            logger.error(
                "Role sync failed for user=%s: %s",
                user.username, e,
                exc_info=True
            )
  

    # ── Django Backend Required Method ────────────────────────────────────────

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None