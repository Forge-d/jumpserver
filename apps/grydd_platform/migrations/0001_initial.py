from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='IAMConfig',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('server_url', models.URLField(help_text='Base IAM URL e.g. https://iam.the-grydd.com')),
                ('tenant', models.CharField(max_length=128)),
                ('client_id', models.CharField(max_length=256)),
                ('client_secret', models.CharField(blank=True, max_length=512)),
                ('discovery_url', models.URLField(blank=True)),
                ('authorization_endpoint', models.URLField(blank=True)),
                ('token_endpoint', models.URLField(blank=True)),
                ('userinfo_endpoint', models.URLField(blank=True)),
                ('jwks_uri', models.URLField(blank=True)),
                ('end_session_endpoint', models.URLField(blank=True)),
                ('scopes', models.CharField(default='openid email profile', max_length=256)),
                ('claim_username', models.CharField(default='preferred_username', max_length=64)),
                ('claim_email', models.CharField(default='email', max_length=64)),
                ('claim_name', models.CharField(default='name', max_length=64)),
                ('pkce_enabled', models.BooleanField(default=True)),
                ('pkce_method', models.CharField(default='S256', max_length=8)),
                ('is_active', models.BooleanField(default=True)),
                ('role_mapping', models.JSONField(
                    blank=True,
                    default=dict,
                    help_text='Override DEFAULT_ROLE_MAPPING. Maps IAM group names to JumpServer role names.',
                )),
                ('require_mfa_acr', models.CharField(
                    blank=True,
                    default='',
                    help_text=(
                        "ACR value sent as acr_values in the IAM authorization URL to request MFA. "
                        "Use 'urn:iam:acr:2fa:any' to require any two-factor auth. Leave blank to not request."
                    ),
                    max_length=255,
                )),
                ('mfa_acr_values', models.JSONField(
                    blank=True,
                    default=list,
                    help_text=(
                        "Extra ACR values (beyond the built-in urn:iam:acr:2fa:* prefix) that confirm MFA. "
                        "Checked against the acr claim in the returned ID token."
                    ),
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'app_label': 'grydd_platform',
            },
        ),
    ]
