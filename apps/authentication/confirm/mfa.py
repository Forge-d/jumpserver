import time

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from users.models import User

from .base import BaseConfirm
from ..const import ConfirmType


class ConfirmMFA(BaseConfirm):
    name = ConfirmType.MFA.value
    display_name = ConfirmType.MFA.name

    # ── IAM helpers ──────────────────────────────────────────────────────────

    def _is_iam_user(self) -> bool:
        return getattr(self.user, 'source', '') == 'grydd-iam'

    def _iam_mfa_session_valid(self) -> bool:
        """
        Return True if the current session carries a valid IAM MFA marker that
        has not yet exceeded SECURITY_MFA_VERIFY_TTL.
        """
        if self.request.session.get('auth_mfa_type') != 'iam':
            return False
        mfa_time = self.request.session.get('auth_mfa_time', 0)
        ttl = getattr(settings, 'SECURITY_MFA_VERIFY_TTL', 3600)
        return (time.time() - mfa_time) < ttl

    # ── BaseConfirm interface ─────────────────────────────────────────────────

    def check(self) -> bool:
        # IAM users always satisfy the MFA check requirement — their second
        # factor was performed at the IAM provider during login.
        if self._is_iam_user():
            return True
        return bool(self.user.active_mfa_backends and self.user.mfa_enabled)

    @property
    def content(self):
        # IAM users need no local code input — MFA was done at IAM.
        # Returning an empty list signals to the UI that no input is required.
        if self._is_iam_user():
            return []
        backends = User.get_user_mfa_backends(self.user)
        return [{
            'name': backend.name,
            'disabled': not bool(backend.is_active()),
            'display_name': backend.display_name,
            'placeholder': backend.placeholder,
        } for backend in backends]

    def authenticate(self, secret_key, mfa_type):
        if self._is_iam_user():
            # For IAM users, verify the session still carries an active IAM MFA
            # marker within the allowed TTL. No local code entry is required.
            if self._iam_mfa_session_valid():
                return True, ''
            return False, _(
                'IAM MFA session has expired. Please log out and log in again '
                'to re-authenticate with your second factor.'
            )
        mfa_backend = self.user.get_mfa_backend_by_type(mfa_type)
        mfa_backend.set_request(self.request)
        ok, msg = mfa_backend.check_code(secret_key)
        return ok, msg
