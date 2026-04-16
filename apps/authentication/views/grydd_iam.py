import logging
import time
from urllib.parse import urlencode

from django.contrib.auth import login as auth_login
from django.http import HttpResponseRedirect, JsonResponse
from django.views import View

from authentication.backends.grydd_iam import (
    generate_code_verifier,
    generate_code_challenge,
    generate_state,
    exchange_code_for_tokens,
    validate_id_token,
    check_iam_mfa_from_claims,
)

logger = logging.getLogger('jumpserver.authentication.iam')


def get_redirect_uri(request):
    return request.build_absolute_uri('/core/auth/iam/callback/')


def _build_iam_auth_url(request, iam_config, *, extra_params=None):
    """
    Build the IAM authorization URL with PKCE + MFA ACR and store OIDC
    session state.  Returns (auth_url, state).

    extra_params is merged into the query-string after defaults are set,
    allowing callers to add prompt=login or override acr_values.
    """
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier, iam_config.pkce_method)
    state = generate_state()

    request.session['oidc_code_verifier'] = code_verifier
    request.session['oidc_state'] = state
    request.session['oidc_config_id'] = str(iam_config.id)
    request.session.modified = True

    acr_values = iam_config.require_mfa_acr or 'urn:iam:acr:2fa:any'

    params = {
        'response_type': 'code',
        'client_id': iam_config.client_id,
        'redirect_uri': get_redirect_uri(request),
        'scope': iam_config.scopes,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': iam_config.pkce_method,
        'acr_values': acr_values,
    }
    if extra_params:
        params.update(extra_params)

    auth_url = f"{iam_config.authorization_endpoint}?{urlencode(params)}"
    return auth_url, state


def _set_iam_mfa_session(request, user, iam_mfa_verified, claims):
    """
    Write all MFA and confirm session keys required by JumpServer's two
    independent auth gates:

    1. Login MFA gate  — MFAMiddleware / on_user_auth_login_success signal
       Keys: auth_mfa, auth_mfa_username, auth_mfa_time, auth_mfa_required,
             auth_mfa_type

    2. Action-level confirm gate — UserConfirmation permission class
       Keys: CONFIRM_LEVEL, CONFIRM_TYPE, CONFIRM_TIME

    Both gates use SECURITY_MFA_VERIFY_TTL as their TTL, so stamping them
    together keeps the expiry in sync.
    """
    from authentication.const import ConfirmType
    now = int(time.time())

    # Gate 1 — login MFA
    request.session['auth_mfa'] = 1
    request.session['auth_mfa_username'] = user.username
    request.session['auth_mfa_time'] = now
    request.session['auth_mfa_required'] = 0
    request.session['auth_mfa_type'] = 'iam'

    # Gate 2 — action-level confirm (MFA = highest level = 3)
    mfa_confirm_level = ConfirmType.values.index(ConfirmType.MFA) + 1
    request.session['CONFIRM_LEVEL'] = mfa_confirm_level
    request.session['CONFIRM_TYPE'] = ConfirmType.MFA
    request.session['CONFIRM_TIME'] = now

    logger.info(
        "IAM MFA session set: user=%s iam_mfa_verified=%s acr=%r amr=%r "
        "confirm_level=%s",
        user.username, iam_mfa_verified,
        claims.get('acr'), claims.get('amr'),
        mfa_confirm_level,
    )


# ── Views ──────────────────────────────────────────────────────────────────────

class IAMLoginView(View):
    """
    Initiates the IAM OIDC Authorization Code + PKCE login flow.
    Always requests urn:iam:acr:2fa:any (or the configured require_mfa_acr)
    so that IAM enforces a second factor before issuing the code.
    """

    def get(self, request):
        from grydd_platform.models import IAMConfig

        iam_config = IAMConfig.get_active()
        if not iam_config:
            return JsonResponse(
                {'error': 'IAM is not configured. '
                          'Add a config via the admin API.'},
                status=503,
            )
        if not iam_config.authorization_endpoint:
            return JsonResponse(
                {'error': 'IAM endpoints not synced. '
                          'Call /api/v1/grydd_platform/iam/sync/'},
                status=503,
            )

        next_url = request.GET.get('next', '/ui/')
        if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
            next_url = '/ui/'
        request.session['oidc_next'] = next_url

        auth_url, _ = _build_iam_auth_url(request, iam_config)
        logger.info(
            "Initiating IAM login: client_id=%s acr_values=%r",
            iam_config.client_id,
            iam_config.require_mfa_acr or 'urn:iam:acr:2fa:any',
        )
        return HttpResponseRedirect(auth_url)


class IAMStepUpView(View):
    """
    Action-level MFA re-verification via IAM (step-up authentication).

    Called when JumpServer's UserConfirmation permission gate expires
    mid-session and the user needs to re-prove their second factor without
    performing a full re-login.

    Flow:
      1. This view saves ?next=<url> and redirects to IAM with prompt=login
         so IAM forces fresh credentials even if the IAM session is still
         alive.
      2. IAMCallbackView detects the oidc_stepup_next session key, verifies
         the 2FA claims, refreshes both MFA session gates, and redirects back
         to the saved URL — no auth_login() is called because the user is
         already authenticated in JumpServer.
    """

    def get(self, request):
        if request.user.is_anonymous:
            return HttpResponseRedirect('/core/auth/login/')

        from grydd_platform.models import IAMConfig
        iam_config = IAMConfig.get_active()
        if not iam_config or not iam_config.authorization_endpoint:
            return JsonResponse({'error': 'IAM not configured or synced'}, status=503)

        next_url = request.GET.get('next', '/ui/')
        if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
            next_url = '/ui/'

        # Use a distinct session key so the callback knows this is a step-up,
        # not a fresh login.
        request.session['oidc_stepup_next'] = next_url

        # prompt=login forces IAM to re-authenticate the user even if an IAM
        # SSO session is still active, giving us a genuine fresh 2FA challenge.
        auth_url, _ = _build_iam_auth_url(
            request, iam_config,
            extra_params={'prompt': 'login'},
        )
        logger.info(
            "Initiating IAM step-up: user=%s next=%r acr_values=%r",
            request.user.username, next_url,
            iam_config.require_mfa_acr or 'urn:iam:acr:2fa:any',
        )
        return HttpResponseRedirect(auth_url)


class IAMCallbackView(View):
    """
    Handles the IAM authorization callback for both:

    * Login  — user was anonymous; full auth_login() is called.
    * Step-up — user was already authenticated; only the MFA/confirm session
                keys are refreshed (auth_login() is NOT called again).

    The presence of oidc_stepup_next in the session distinguishes step-up
    from a normal login.
    """

    def get(self, request):
        returned_state = request.GET.get('state')
        stored_state = request.session.get('oidc_state')

        if not returned_state or returned_state != stored_state:
            logger.warning("OIDC state mismatch — possible CSRF")
            return JsonResponse({'error': 'Invalid state parameter'}, status=400)

        error = request.GET.get('error')
        if error:
            error_desc = request.GET.get('error_description', '')
            logger.warning("IAM error: %s — %s", error, error_desc)
            return JsonResponse({'error': error, 'detail': error_desc}, status=401)

        code = request.GET.get('code')
        if not code:
            return JsonResponse({'error': 'Missing authorization code'}, status=400)

        code_verifier = request.session.get('oidc_code_verifier')
        config_id = request.session.get('oidc_config_id')

        # Determine mode: step-up (user already logged in) vs normal login
        stepup_next = request.session.pop('oidc_stepup_next', None)
        is_stepup = stepup_next is not None

        if is_stepup:
            next_url = stepup_next
        else:
            next_url = request.session.pop('oidc_next', '/ui/')
            if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
                next_url = '/ui/'

        if not code_verifier or not config_id:
            return JsonResponse({'error': 'Missing OIDC session state'}, status=400)

        from grydd_platform.models import IAMConfig
        try:
            iam_config = IAMConfig.objects.get(id=config_id, is_active=True)
        except IAMConfig.DoesNotExist:
            return JsonResponse({'error': 'IAM config not found'}, status=500)

        try:
            tokens = exchange_code_for_tokens(
                code=code,
                code_verifier=code_verifier,
                redirect_uri=get_redirect_uri(request),
                iam_config=iam_config,
            )
        except Exception as e:
            logger.error("Token exchange failed: %s", e)
            return JsonResponse({'error': 'Token exchange failed'}, status=401)

        id_token = tokens.get('id_token')
        access_token = tokens.get('access_token')
        logger.info(
            "IAM token exchange: id_token=%s access_token=%s",
            id_token, access_token,
        )
        if not id_token:
            return JsonResponse({'error': 'No id_token in response'}, status=401)

        try:
            claims = validate_id_token(id_token, iam_config)
        except Exception as e:
            logger.error("Token validation failed: %s", e)
            return JsonResponse({'error': 'Token validation failed'}, status=401)

        # ── MFA enforcement (applies to both login and step-up) ───────────────
        iam_mfa_verified = check_iam_mfa_from_claims(claims, iam_config)
        if not iam_mfa_verified:
            requested_acr = iam_config.require_mfa_acr or 'urn:iam:acr:2fa:any'
            logger.warning(
                "IAM MFA not satisfied: acr_values=%r requested but token "
                "returned acr=%r amr=%r for step_up=%s — rejecting",
                requested_acr, claims.get('acr'), claims.get('amr'), is_stepup,
            )
            return JsonResponse(
                {'error': 'MFA required by IAM policy was not completed'},
                status=401,
            )

        for key in ['oidc_code_verifier', 'oidc_state', 'oidc_config_id']:
            request.session.pop(key, None)
        request.session['oidc_id_token_hint'] = id_token
        request.session['oidc_access_token'] = access_token

        # ── Step-up path: refresh session gates, skip re-login ───────────────
        if is_stepup:
            if request.user.is_anonymous:
                logger.warning("Step-up callback reached with anonymous user — aborting")
                return JsonResponse({'error': 'Session expired, please log in again'}, status=401)

            _set_iam_mfa_session(request, request.user, iam_mfa_verified, claims)
            logger.info("IAM step-up complete: user=%s next=%r", request.user.username, next_url)
            return HttpResponseRedirect(next_url)

        # ── Login path: authenticate user and establish Django session ────────
        from django.contrib.auth import authenticate
        user = authenticate(request, iam_claims=claims, iam_config=iam_config)

        if user is None:
            return JsonResponse({'error': 'Authentication failed'}, status=401)
        if not user.is_active:
            return JsonResponse({'error': 'User account is disabled'}, status=403)

        # Set both MFA gates BEFORE auth_login() so the post-login signal
        # sees auth_mfa=1 and does not schedule a JumpServer MFA challenge.
        _set_iam_mfa_session(request, user, iam_mfa_verified, claims)

        auth_login(
            request, user,
            backend='authentication.backends.grydd_iam.IAMOIDCBackend',
        )
        logger.info("Successful IAM login: user=%s", user.username)
        return HttpResponseRedirect(next_url)


class IAMLogoutView(View):
    def get(self, request):
        from grydd_platform.models import IAMConfig

        id_token_hint = request.session.get('oidc_id_token_hint')
        request.session.flush()

        # After logout the user is anonymous.  Redirect to the login page,
        # NOT to '/' — IndexView requires IsValidUser and would loop forever
        # when LOGIN_URL is set to a path that also requires auth.
        login_url = request.build_absolute_uri('/core/auth/login/')

        iam_config = IAMConfig.get_active()
        if iam_config and iam_config.end_session_endpoint:
            params = {
                'post_logout_redirect_uri': login_url,
            }
            if id_token_hint:
                params['id_token_hint'] = id_token_hint
            logout_url = f"{iam_config.end_session_endpoint}?{urlencode(params)}"
            return HttpResponseRedirect(logout_url)

        return HttpResponseRedirect('/core/auth/login/')
