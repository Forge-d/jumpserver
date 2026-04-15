import uuid
from django.db import models
from django.contrib.auth import get_user_model

class IAMConfig(models.Model):
    """
    Single IAM configuration for this JumpServer instance.
    Only one active record should exist at a time.
    """
    server_url = models.URLField(
        help_text="Base IAM URL e.g. https://iam.the-grydd.com"
    )
    tenant = models.CharField(max_length=128)
    client_id = models.CharField(max_length=256)
    client_secret = models.CharField(max_length=512, blank=True)
 
    # OIDC endpoints — auto-populated via sync
    discovery_url = models.URLField(blank=True)
    authorization_endpoint = models.URLField(blank=True)
    token_endpoint = models.URLField(blank=True)
    userinfo_endpoint = models.URLField(blank=True)
    jwks_uri = models.URLField(blank=True)
    end_session_endpoint = models.URLField(blank=True)
 
    scopes = models.CharField(max_length=256, default="openid email profile")
    claim_username = models.CharField(max_length=64, default="preferred_username")
    claim_email = models.CharField(max_length=64, default="email")
    claim_name = models.CharField(max_length=64, default="name")
 
    pkce_enabled = models.BooleanField(default=True)
    pkce_method = models.CharField(max_length=8, default="S256")
    is_active = models.BooleanField(default=True)

    # ── Role mapping ─────────────────────────────────────────────────────────
    role_mapping = models.JSONField(
        default=dict, blank=True,
        help_text="Override DEFAULT_ROLE_MAPPING. Maps IAM group names to JumpServer role names."
    )

    # ── MFA / ACR integration ─────────────────────────────────────────────────
    require_mfa_acr = models.CharField(
        max_length=255, blank=True, default='',
        help_text=(
            "ACR value sent as acr_values in the IAM authorization URL to request MFA. "
            "Use 'urn:iam:acr:2fa:any' to require any two-factor auth. Leave blank to not request."
        )
    )
    mfa_acr_values = models.JSONField(
        default=list, blank=True,
        help_text=(
            "Extra ACR values (beyond the built-in urn:iam:acr:2fa:* prefix) that confirm MFA. "
            "Checked against the acr claim in the returned ID token."
        )
    )
 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
 
    class Meta:
        app_label = 'grydd_platform'
 
    def save(self, *args, **kwargs):
        if not self.discovery_url and self.server_url and self.tenant:
            self.discovery_url = (
                f"{self.server_url.rstrip('/')}/tenants/{self.tenant}"
                f"/.well-known/openid-configuration"
            )
        super().save(*args, **kwargs)
 
    @property
    def issuer(self):
        return f"{self.server_url.rstrip('/')}/tenants/{self.tenant}"
 
    @classmethod
    def get_active(cls):
        """Get the single active IAM config."""
        return cls.objects.filter(is_active=True).first()