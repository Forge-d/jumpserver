import time

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from users.models import User

from .base import BaseConfirm
from ..const import ConfirmType

# Sentinel returned by authenticate() when the IAM session has expired and the
# frontend must redirect the user to IAM for a fresh 2FA challenge.
IAM_STEPUP_REQUIRED = 'iam_stepup_required'

# URL of the IAM step-up view.
IAM_STEPUP_PATH = '/core/auth/iam/stepup/'


class ConfirmMFA(BaseConfirm):
    name = ConfirmType.MFA.value
    display_name = ConfirmType.MFA.name

    # ── IAM helpers ──────────────────────────────────────────────────────────

    def _is_iam_user(self) -> bool:
        return getattr(self.user, 'source', '') == 'grydd-iam'

    def _iam_mfa_session_valid(self) -> bool:
        """True if the session has an un-expired IAM MFA marker."""
        if self.request.session.get('auth_mfa_type') != 'iam':
            return False
        mfa_time = self.request.session.get('auth_mfa_time', 0)
        ttl = getattr(settings, 'SECURITY_MFA_VERIFY_TTL', 3600)
        return (time.time() - mfa_time) < ttl

    # ── BaseConfirm interface ─────────────────────────────────────────────────

    def check(self) -> bool:
        # IAM users always satisfy the presence check — their 2FA was performed
        # at the IAM provider.  Expiry is handled in authenticate().
        if self._is_iam_user():
            return True
        return bool(self.user.active_mfa_backends and self.user.mfa_enabled)

    @property
    def content(self):
        # Return empty content for IAM users — no code input is needed.
        # The confirm POST endpoint handles the step-up redirect when the
        # session has expired; within the TTL the POST passes automatically.
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
            if self._iam_mfa_session_valid():
                # Session still carries a live IAM MFA marker — pass immediately.
                return True, ''
            # Session has expired.  Signal the viewset to initiate IAM step-up.
            return False, IAM_STEPUP_REQUIRED

        # ── Regular users: existing OTP / SMS / Email flow ────────────────────
        mfa_backend = self.user.get_mfa_backend_by_type(mfa_type)
        mfa_backend.set_request(self.request)
        ok, msg = mfa_backend.check_code(secret_key)
        return ok, msg
