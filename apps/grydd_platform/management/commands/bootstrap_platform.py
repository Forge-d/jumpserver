"""
Bootstrap IAM configuration from config.yml on startup.
Idempotent — safe to run multiple times.

Required config.yml settings:
    PLATFORM_KEYCLOAK_SERVER_URL  - e.g. https://iam.the-grydd.com
    PLATFORM_MASTER_TENANT         - IAM tenant id
    PLATFORM_MASTER_CLIENT_ID     - IAM client ID
    PLATFORM_MASTER_CLIENT_SECRET - Client secret (blank for public clients)
    PLATFORM_ADMIN_USERNAME       - Username/email of the admin user to seed
    PLATFORM_ADMIN_EMAIL          - Email of the admin user to seed
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
        admin_username = CONFIG.get('PLATFORM_ADMIN_USERNAME', '')
        admin_email = CONFIG.get('PLATFORM_ADMIN_EMAIL', '')

        if not all([server_url, tenant, client_id]):
            self.stdout.write(
                self.style.WARNING(
                    "Skipping IAM bootstrap — "
                    "PLATFORM_IAM_SERVER_URL, PLATFORM_MASTER_TENANT "
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

        # Sync endpoints from IAM discovery document
        self._sync_endpoints(config)

        # Seed admin user if configured
        if admin_username or admin_email:
            self._ensure_admin_user(
                admin_username or admin_email,
                admin_email or admin_username
            )

        self._bootstrap_svc_account()

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

    def _ensure_admin_user(self, username, email):
        """
        Find or create the admin user and assign SystemAdmin role.
        Idempotent — safe to run multiple times.
        """
        from users.models import User
        from rbac.models import Role, RoleBinding

        # Find by email first, then username
        user = User.objects.filter(email=email).first()
        if not user:
            user = User.objects.filter(username=username).first()

        if not user:
            self.stdout.write(f"  Creating admin user: {username}")
            user = User(
                username=username,
                email=email,
                name=username,
                is_active=True,
                source='grydd-iam',
            )
            user.set_unusable_password()
            user.save()
        else:
            self.stdout.write(f"  Found existing user: {user.username}")

        # Get SystemAdmin role
        system_admin_role = Role.objects.filter(
            name='SystemAdmin', scope='system'
        ).first()

        if not system_admin_role:
            self.stdout.write(
                self.style.WARNING(
                    "  SystemAdmin role not found — "
                    "run migrate first to create builtin roles"
                )
            )
            return

        # Assign SystemAdmin if not already assigned
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT COUNT(*) FROM rbac_rolebinding '
                'WHERE user_id = %s AND role_id = %s',
                [str(user.id), str(system_admin_role.id)]
            )
            already_admin = cursor.fetchone()[0] > 0

        if not already_admin:
            RoleBinding.objects.create(
                user=user,
                role=system_admin_role,
                org=None,
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"  Assigned SystemAdmin role to {user.username}"
                )
            )
        else:
            self.stdout.write(
                f"  {user.username} already has SystemAdmin role"
            )

    def _bootstrap_svc_account(self):
        from django.core import management as mgmt
        self.stdout.write("Bootstrapping M2M service account...")
        try:
            mgmt.call_command('bootstrap_svc_account', stdout=self.stdout)
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f"  Service account bootstrap failed: {e}")
            )