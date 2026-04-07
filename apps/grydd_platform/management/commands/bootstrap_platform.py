"""
Bootstrap IAM configuration from config.yml on startup.
Idempotent — safe to run multiple times.

Required config.yml settings:
    PLATFORM_KEYCLOAK_SERVER_URL  - e.g. https://iam.the-grydd.com
    PLATFORM_MASTER_TENANT         - IAM tenant id
    PLATFORM_MASTER_CLIENT_ID     - IAM client ID
    PLATFORM_MASTER_CLIENT_SECRET - Client secret (blank for public clients)
"""
import logging
import requests

from django.core.management.base import BaseCommand
from django.db import transaction

from jumpserver.const import CONFIG

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Bootstrap IAM config from config.yml (idempotent)"

    def handle(self, *args, **options):
        self.stdout.write("Bootstrapping IAM configuration...")
        try:
            self._bootstrap()
            self.stdout.write(
                self.style.SUCCESS("IAM bootstrap complete.")
            )
        except Exception as e:
            logger.error(f"Bootstrap failed: {e}", exc_info=True)
            self.stdout.write(
                self.style.ERROR(f"Bootstrap failed: {e}")
            )
            raise

    @transaction.atomic
    def _bootstrap(self):
        from grydd_platform.models import IAMConfig

        server_url = CONFIG.get('PLATFORM_KEYCLOAK_SERVER_URL', '')
        tenant = CONFIG.get('PLATFORM_MASTER_TENANT', '')
        client_id = CONFIG.get('PLATFORM_MASTER_CLIENT_ID', '')
        client_secret = CONFIG.get('PLATFORM_MASTER_CLIENT_SECRET', '')

        if not all([server_url, tenant, client_id]):
            self.stdout.write(
                self.style.WARNING(
                    "  Skipping IAM bootstrap — "
                    "PLATFORM_KEYCLOAK_SERVER_URL, PLATFORM_MASTER_TENANT "
                    "and PLATFORM_MASTER_CLIENT_ID must all be set in config.yml"
                )
            )
            return

        # Create or update the single active IAM config
        config, created = IAMConfig.objects.update_or_create(
            tenant=tenant,
            defaults={
                'server_url': server_url.rstrip('/'),
                'client_id': client_id,
                'client_secret': client_secret,
                'scopes': 'openid email profile',
                'pkce_enabled': True,
                'pkce_method': 'S256',
                'claim_username': 'preferred_username',
                'claim_email': 'email',
                'claim_name': 'name',
                'is_active': True,
            }
        )

        action = "Created" if created else "Updated"
        self.stdout.write(f"  {action} IAM config for tenant '{tenant}'")
        self.stdout.write(f"  Discovery URL: {config.discovery_url}")

        # Auto-sync endpoints from IAM discovery document
        self._sync_endpoints(config)

    def _sync_endpoints(self, config):
        """Fetch OIDC endpoints from IAM discovery document."""
        if not config.discovery_url:
            self.stdout.write(
                self.style.WARNING("  No discovery URL — skipping endpoint sync")
            )
            return

        try:
            self.stdout.write(
                f"  Syncing endpoints from {config.discovery_url} ..."
            )
            resp = requests.get(config.discovery_url, timeout=10)
            resp.raise_for_status()
            doc = resp.json()

            config.authorization_endpoint = doc.get('authorization_endpoint', '')
            config.token_endpoint = doc.get('token_endpoint', '')
            config.userinfo_endpoint = doc.get('userinfo_endpoint', '')
            config.jwks_uri = doc.get('jwks_uri', '')
            config.end_session_endpoint = doc.get('end_session_endpoint', '')
            config.save()

            self.stdout.write(
                self.style.SUCCESS(
                    f"  Endpoints synced. Issuer: {doc.get('issuer')}"
                )
            )
        except requests.exceptions.ConnectionError:
            self.stdout.write(
                self.style.WARNING(
                    f"  Could not reach IAM at {config.discovery_url} — "
                    f"endpoints not synced. Run sync manually when IAM is available:\n"
                    f"  curl -X POST http://localhost/api/v1/grydd_platform/iam/sync/"
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f"  Endpoint sync failed: {e} — continuing anyway")
            )