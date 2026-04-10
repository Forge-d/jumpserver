from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from .models import IAMConfig
from .serializers import IAMConfigSerializer


class IAMConfigView(APIView):
    """
    GET  /api/v1/grydd_platform/iam/  — get current config
    POST /api/v1/grydd_platform/iam/  — create config
    PUT  /api/v1/grydd_platform/iam/  — update config
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        config = IAMConfig.get_active()
        if not config:
            return Response({'detail': 'No IAM config found'}, status=404)
        serializer = IAMConfigSerializer(config)
        return Response(serializer.data)

    def post(self, request):
        serializer = IAMConfigSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(IAMConfigSerializer(config).data,
                        status=status.HTTP_201_CREATED)

    def put(self, request):
        config = IAMConfig.get_active()
        if not config:
            return Response({'detail': 'No config to update'}, status=404)
        serializer = IAMConfigSerializer(
            config, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(IAMConfigSerializer(config).data)


class IAMConfigSyncView(APIView):
    """
    POST /api/v1/grydd_platform/iam/sync/
    Fetches OIDC endpoints from IAM discovery document.
    """
    permission_classes = [IsAdminUser]

    def post(self, request):
        import requests as req
        config = IAMConfig.get_active()
        if not config:
            return Response({'detail': 'No IAM config found'}, status=404)
        try:
            resp = req.get(config.discovery_url, timeout=10)
            resp.raise_for_status()
            doc = resp.json()
            config.authorization_endpoint = doc['authorization_endpoint']
            config.token_endpoint = doc['token_endpoint']
            config.userinfo_endpoint = doc['userinfo_endpoint']
            config.jwks_uri = doc['jwks_uri']
            config.end_session_endpoint = doc.get('end_session_endpoint', '')
            config.save()
            return Response({
                'status': 'ok',
                'issuer': doc.get('issuer'),
                'authorization_endpoint': config.authorization_endpoint,
            })
        except Exception as e:
            return Response({'status': 'error', 'detail': str(e)}, status=502)