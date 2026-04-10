import logging
import requests
from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync OIDC endpoints from IAM discovery document"

    def handle(self, *args, **options):
        from grydd_platform.models import IAMConfig

        config = IAMConfig.get_active()
        if not config:
            self.stdout.write(
                self.style.WARNING("No active IAM config found. "
                                   "Run bootstrap_platform first.")
            )
            return

        self._sync(config)

    def _sync(self, config):
        if not config.discovery_url:
            self.stdout.write(
                self.style.ERROR(
                    "No discovery URL set. "
                    "Ensure server_url and realm are configured."
                )
            )
            return

        try:
            self.stdout.write(f"Syncing from {config.discovery_url} ...")
            resp = requests.get(config.discovery_url, timeout=10)
            resp.raise_for_status()
            doc = resp.json()

            config.authorization_endpoint = doc.get(
                'authorization_endpoint', config.authorization_endpoint
            )
            config.token_endpoint = doc.get(
                'token_endpoint', config.token_endpoint
            )
            config.userinfo_endpoint = doc.get(
                'userinfo_endpoint', config.userinfo_endpoint
            )
            config.jwks_uri = doc.get(
                'jwks_uri', config.jwks_uri
            )
            config.end_session_endpoint = doc.get(
                'end_session_endpoint', config.end_session_endpoint
            )
            config.save()

            self.stdout.write(
                self.style.SUCCESS(
                    f"Endpoints synced successfully. "
                    f"Issuer: {doc.get('issuer')}"
                )
            )
        except requests.exceptions.ConnectionError:
            self.stdout.write(
                self.style.ERROR(
                    f"Could not reach IAM at {config.discovery_url}. "
                    f"Check that IAM is running and the URL is correct."
                )
            )
        except requests.exceptions.HTTPError as e:
            self.stdout.write(
                self.style.ERROR(f"HTTP error fetching discovery document: {e}")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Sync failed: {e}")
            )