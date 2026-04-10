from rest_framework import serializers
from .models import IAMConfig


class IAMConfigSerializer(serializers.ModelSerializer):
    client_secret = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="Client secret for confidential clients. Leave blank for public clients (PKCE only)."
    )
    # Read-only computed fields
    issuer = serializers.SerializerMethodField(read_only=True)
    discovery_url = serializers.CharField(read_only=True)

    class Meta:
        model = IAMConfig
        exclude = ['created_at', 'updated_at']
        extra_kwargs = {
            'authorization_endpoint': {'read_only': True},
            'token_endpoint': {'read_only': True},
            'userinfo_endpoint': {'read_only': True},
            'jwks_uri': {'read_only': True},
            'end_session_endpoint': {'read_only': True},
        }

    def get_issuer(self, obj):
        return obj.issuer

    def validate_server_url(self, value):
        """Ensure server URL doesn't have trailing slash issues."""
        return value.rstrip('/')

    def validate_pkce_method(self, value):
        if value not in ('S256', 'plain'):
            raise serializers.ValidationError(
                "pkce_method must be 'S256' or 'plain'. S256 is strongly recommended."
            )
        return value

    def validate(self, attrs):
        """
        Ensure only one active config exists when creating.
        """
        if self.instance is None:  # creating new
            if IAMConfig.objects.filter(is_active=True).exists():
                raise serializers.ValidationError(
                    "An active IAM config already exists. "
                    "Use PUT to update it, or deactivate the existing one first."
                )
        return attrs