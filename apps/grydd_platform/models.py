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