import time
from importlib import import_module
from threading import Thread

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import AnonymousUser
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response

from common.sessions.cache import user_session_manager
from common.utils import get_logger

__all__ = ['UserSessionApi']

logger = get_logger(__name__)


def _delayed_iam_logout(session_key: str, id_token_hint: str) -> None:
    """
    After a browser disconnect (DELETE /user-session/), wait a few seconds to
    see if the user reconnects (i.e. it was just a page refresh).  If the
    session counter is still zero after the grace period, the user genuinely
    logged out: delete the Django session and end the IAM SSO session so the
    provider cannot silently re-authenticate them.
    """
    GRACE = 6  # seconds — same as UserSessionManager.delay_delete_session

    def _run():
        time.sleep(GRACE)

        if user_session_manager.check_active(session_key):
            # Someone reconnected — this was a refresh, not a logout.
            return

        # Delete the Django session directly (no request object available here).
        try:
            engine = import_module(settings.SESSION_ENGINE)
            engine.SessionStore(session_key).delete()
        except Exception as exc:
            logger.warning("IAM logout: session delete failed: %s", exc)

        # Terminate the IAM SSO session server-to-server.
        try:
            from grydd_platform.models import IAMConfig
            iam_config = IAMConfig.get_active()
            if iam_config:
                from authentication.backends.grydd_iam import trigger_iam_backchannel_logout
                trigger_iam_backchannel_logout(id_token_hint, iam_config)
        except Exception as exc:
            logger.warning("IAM backchannel logout failed: %s", exc)

    Thread(target=_run, daemon=True).start()


class UserSessionManager:

    def __init__(self, request):
        self.request = request
        self.session = request.session

    def connect(self):
        user_session_manager.add_or_increment(self.session.session_key)

    def disconnect(self):
        user_session_manager.decrement(self.session.session_key)
        if self.should_delete_session():
            thread = Thread(target=self.delay_delete_session)
            thread.start()

    def should_delete_session(self):
        return (self.session.modified or settings.SESSION_SAVE_EVERY_REQUEST) and \
            not self.session.is_empty() and \
            self.session.get_expire_at_browser_close() and \
            not user_session_manager.check_active(self.session.session_key)

    def delay_delete_session(self):
        timeout = 6
        check_interval = 0.5

        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(check_interval)
            if user_session_manager.check_active(self.session.session_key):
                return

        logout(self.request)


class UserSessionApi(generics.RetrieveDestroyAPIView):
    permission_classes = ()

    def retrieve(self, request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser):
            return Response(status=status.HTTP_403_FORBIDDEN)

        UserSessionManager(request).connect()
        return Response(status=status.HTTP_200_OK, data={'ok': True})

    def destroy(self, request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser):
            return Response(status=status.HTTP_403_FORBIDDEN)

        UserSessionManager(request).disconnect()

        # For IAM users, schedule a delayed check: if the session is still
        # inactive after the grace period (i.e. the user didn't just refresh),
        # delete the Django session and terminate the IAM SSO session so the
        # provider cannot silently re-authenticate them.
        if getattr(request.user, 'source', '') == 'grydd-iam':
            _delayed_iam_logout(
                session_key=request.session.session_key,
                id_token_hint=request.session.get('oidc_id_token_hint', ''),
            )

        return Response(status=status.HTTP_200_OK, data={'ok': True})
