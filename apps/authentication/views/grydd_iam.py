import logging
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
)

logger = logging.getLogger(__name__)


def get_redirect_uri(request):
    return request.build_absolute_uri('/core/auth/iam/callback/')


class IAMLoginView(View):
    def get(self, request):
        from grydd_platform.models import IAMConfig

        iam_config = IAMConfig.get_active()
        if not iam_config:
            return JsonResponse(
                {'error': 'IAM is not configured. '
                          'Add a config via the admin API.'},
                status=503
            )

        if not iam_config.authorization_endpoint:
            return JsonResponse(
                {'error': 'IAM endpoints not synced. '
                          'Call /api/v1/grydd_platform/iam/sync/'},
                status=503
            )

        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier, iam_config.pkce_method)
        state = generate_state()

        next_url = request.GET.get('next', '/ui/')
        if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
            next_url = '/ui/'

        request.session['oidc_code_verifier'] = code_verifier
        request.session['oidc_state'] = state
        request.session['oidc_config_id'] = str(iam_config.id)
        request.session['oidc_next'] = next_url
        request.session.modified = True

        params = {
            'response_type': 'code',
            'client_id': iam_config.client_id,
            'redirect_uri': get_redirect_uri(request),
            'scope': iam_config.scopes,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': iam_config.pkce_method,
        }

        auth_url = f"{iam_config.authorization_endpoint}?{urlencode(params)}"
        logger.info("Initiating IAM login client_id=%s", iam_config.client_id)
        return HttpResponseRedirect(auth_url)


class IAMCallbackView(View):
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
        if not id_token:
            return JsonResponse({'error': 'No id_token in response'}, status=401)

        try:
            claims = validate_id_token(id_token, iam_config)
        except Exception as e:
            logger.error("Token validation failed: %s", e)
            return JsonResponse({'error': 'Token validation failed'}, status=401)

        from django.contrib.auth import authenticate
        user = authenticate(request, iam_claims=claims, iam_config=iam_config)

        if user is None:
            return JsonResponse({'error': 'Authentication failed'}, status=401)

        if not user.is_active:
            return JsonResponse({'error': 'User account is disabled'}, status=403)

        for key in ['oidc_code_verifier', 'oidc_state', 'oidc_config_id']:
            request.session.pop(key, None)

        request.session['oidc_id_token_hint'] = id_token
        request.session['oidc_access_token'] = tokens.get('access_token')

        auth_login(
            request, user,
            backend='authentication.backends.grydd_iam.IAMOIDCBackend'
        )

        logger.info("Successful IAM login: user=%s", user.username)
        return HttpResponseRedirect(next_url)


class IAMLogoutView(View):
    def get(self, request):
        from grydd_platform.models import IAMConfig

        id_token_hint = request.session.get('oidc_id_token_hint')
        request.session.flush()

        iam_config = IAMConfig.get_active()
        if iam_config and iam_config.end_session_endpoint:
            params = {
                'post_logout_redirect_uri': request.build_absolute_uri('/'),
            }
            if id_token_hint:
                params['id_token_hint'] = id_token_hint
            logout_url = f"{iam_config.end_session_endpoint}?{urlencode(params)}"
            return HttpResponseRedirect(logout_url)

        return HttpResponseRedirect('/')