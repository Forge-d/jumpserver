"""
Bootstrap M2M service account for cloud asset discovery.
Idempotent — safe to run on every server startup.

Optional config.yml settings:
    SVC_ACCOUNT_USERNAME   (default: "svc-cloud-discovery")
    SVC_ACCOUNT_EMAIL      (default: "svc-cloud-discovery@internal.local")
    SVC_ACCOUNT_NAME       (default: "Cloud Asset Discovery Service")
"""
import logging

from django.core.management.base import BaseCommand
from django.db import transaction

from jumpserver.const import CONFIG

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Bootstrap M2M service account for HMAC auth (idempotent)"

    def add_arguments(self, parser):
        parser.add_argument(
            '--rotate-key',
            action='store_true',
            default=False,
            help='Delete existing access keys and issue a new one',
        )

    def handle(self, *args, **options):
        self.stdout.write("Bootstrapping M2M service account...")
        try:
            self._bootstrap(rotate_key=options['rotate_key'])
            self.stdout.write(
                self.style.SUCCESS("M2M service account bootstrap complete.")
            )
        except Exception as e:
            logger.error(f"Service account bootstrap failed: {e}", exc_info=True)
            self.stdout.write(
                self.style.ERROR(f"Service account bootstrap failed: {e}")
            )

    @transaction.atomic
    def _bootstrap(self, rotate_key=False):
        username = CONFIG.get('SVC_ACCOUNT_USERNAME', 'svc-cloud-discovery')
        email = CONFIG.get('SVC_ACCOUNT_EMAIL', 'svc-cloud-discovery@internal.local')
        name = CONFIG.get('SVC_ACCOUNT_NAME', 'Cloud Asset Discovery Service')

        user = self._ensure_user(username, email, name)
        if user is None:
            return
        self._ensure_role(user)
        self._ensure_access_key(user, rotate_key=rotate_key)

    def _ensure_user(self, username, email, name):
        try:
            from users.models import User
        except ImportError as e:
            self.stdout.write(
                self.style.WARNING(f"  Could not import User model: {e}")
            )
            return None

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'name': name,
                'is_active': True,
                'is_service_account': True,
                'source': 'local',
                'mfa_level': 0,
                'comment': (
                    'M2M service account for cloud asset discovery. '
                    'Do not use for human login.'
                ),
            }
        )

        if created:
            user.set_unusable_password()
            user.save()
            self.stdout.write(f"  Created service account: {username}")
        else:
            self.stdout.write(f"  Found existing service account: {username}")

        return user

    def _ensure_role(self, user):
        try:
            from rbac.models import Role, RoleBinding, Permission
        except ImportError as e:
            self.stdout.write(
                self.style.WARNING(f"  Could not import RBAC models: {e}")
            )
            return

        role, role_created = Role.objects.get_or_create(
            name='CloudDiscoveryRole',
            scope='system',
            defaults={
                'builtin': False,
                'comment': 'Minimal role for cloud asset discovery M2M service account',
            }
        )

        if role_created:
            self.stdout.write("  Created role: CloudDiscoveryRole")
        else:
            self.stdout.write("  Found existing role: CloudDiscoveryRole")

        perms = Permission.objects.filter(
            codename__in=['view_asset', 'add_asset', 'change_asset', 'view_node', 'add_node']
        )
        if perms.exists():
            role.permissions.add(*perms)
            self.stdout.write(f"  Assigned {perms.count()} permissions to role")
        else:
            self.stdout.write(
                self.style.WARNING(
                    "  No matching permissions found — run migrate first to populate permissions"
                )
            )

        # Use objects_raw to bypass RoleBindingManager's current_org queryset filter
        binding, binding_created = RoleBinding.objects_raw.get_or_create(
            user=user,
            role=role,
            org=None,
        )
        if binding_created:
            self.stdout.write(
                self.style.SUCCESS(
                    f"  Bound CloudDiscoveryRole to {user.username}"
                )
            )
        else:
            self.stdout.write(
                f"  Role binding already exists for {user.username}"
            )

    def _ensure_access_key(self, user, rotate_key=False):
        try:
            from authentication.models import AccessKey
        except ImportError as e:
            self.stdout.write(
                self.style.WARNING(f"  Could not import AccessKey model: {e}")
            )
            return

        existing = AccessKey.objects.filter(user=user)

        if existing.exists() and not rotate_key:
            self.stdout.write(
                self.style.WARNING(
                    f"Service account '{user.username}' already provisioned. "
                    f"Use --rotate-key flag to generate a new access key."
                )
            )
            return

        if rotate_key and existing.exists():
            existing.delete()
            self.stdout.write("  Deleted existing access key(s) for rotation")

        access_key = AccessKey.objects.create(user=user)
        self._print_credentials(user.username, access_key)

    def _print_credentials(self, username, access_key):
        key_id = access_key.get_id()
        secret = access_key.get_secret()
        w = 54  # inner box width
        self.stdout.write('\n' + '╔' + '═' * w + '╗')
        self.stdout.write('║' + '        M2M SERVICE ACCOUNT CREDENTIALS               ' + '║')
        self.stdout.write('║' + '  Copy these into your secret manager NOW.            ' + '║')
        self.stdout.write('║' + '  SECRET cannot be retrieved again after this run.    ' + '║')
        self.stdout.write('╠' + '═' * w + '╣')
        self.stdout.write(f'║  Username : {username:<41}║')
        self.stdout.write(f'║  KEY_ID   : {key_id:<41}║')
        self.stdout.write(f'║  SECRET   : {secret:<41}║')
        self.stdout.write('╚' + '═' * w + '╝\n')
