# Run in PowerShell as Administrator
wsl --install
# Restart Windows when prompted
# Default installs Ubuntu

# In Windows PowerShell or CMD Check WSL 
wsl -l -v 

# In Windows PowerShell or CMD switch to ubuntu
wsl -d Ubuntu

# Move project to Ubuntu's Linux filesystem
cp -r /mnt/c/workspace/FORGE-D/pam-workspace/jumpserver ~/jumpserver

# Work from there
cd ~/jumpserver

# Remove old venv created on Windows filesystem
rm -rf .venv

# Set UV_LINK_MODE to avoid hardlink warning
export UV_LINK_MODE=copy

# Run in WSL
sudo apt update

sudo apt install -y python3 python3-venv build-essential \
    libldap2-dev libsasl2-dev libssl-dev libpq-dev pkg-config \
    python3-dev libmagic1 gettext

python3 --version

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# Install the MySQL development libraries first:
sudo apt install -y default-libmysqlclient-dev

# Install dependencies
uv sync --no-group xpack

# Start PostgreSQL, Redis, and satellite components
docker compose -f docker-compose.dev.yml up -d db redis

# Wait for DB to be healthy
docker compose -f docker-compose.dev.yml ps

# Run supporting services 
docker compose -f docker-compose.dev.yml up -d db redis koko lion chen web core

# Activate venv
source .venv/bin/activate

# Sync again (optional | onetime only)
uv sync --no-group xpack --python 3.11

# Create migrations for grydd_platform (first time setup and on model change)
uv run python apps/manage.py makemigrations grydd_platform 
 
# Apply migrations (first time setup and on model change)
uv run python apps/manage.py migrate grydd_platform

# Then start
uv run python jms start web


-------------------------------------------- POST App Setup for Debugging -----------------------------------------------------------------------

#  Keep files on Windows, use rsync to sync changes
# Run this every time you make changes on Windows
rsync -av --exclude='.venv' --exclude='__pycache__' \
  /mnt/c/workspace/FORGE-D/pam-workspace/jumpserver/ \
  ~/jumpserver/

# To override the default mapping via shell:
    uv run python apps/manage.py shell -c "
    from grydd_platform.models import IAMConfig
    config = IAMConfig.get_active()
    config.role_mapping = {
        'my-custom-admin-group': 'SystemAdmin',
        'my-auditor-group': 'SystemAuditor',
    }
    config.save()
    print('Updated:', config.role_mapping)
    "

# To revert to default (clear DB mapping so code default is used):
    uv run python apps/manage.py shell -c "
    from grydd_platform.models import IAMConfig
    config = IAMConfig.get_active()
    config.role_mapping = {}  # empty = use DEFAULT_ROLE_MAPPING
    config.save()
    print('Cleared — will use DEFAULT_ROLE_MAPPING')
    "

-------------------------------------------- M2M Service Account (bootstrap_svc_account) -----------------------------------------------------------------------

# Run directly — prints credential box on first run, WARNING on second run
uv run python apps/manage.py bootstrap_svc_account

# Rotate the access key — deletes existing key(s) and issues a new one
uv run python apps/manage.py bootstrap_svc_account --rotate-key

# Verify it runs as part of the full platform bootstrap (no errors expected)
uv run python apps/manage.py bootstrap_platform

# Verify in DB via shell
uv run python apps/manage.py shell -c "
from users.models import User
from authentication.models import AccessKey
from rbac.models import RoleBinding

user = User.objects.get(username='svc-cloud-discovery')
print('User:', user.username, '| is_service_account:', user.is_service_account)

keys = AccessKey.objects.filter(user=user)
print('Access keys:', keys.count())

bindings = RoleBinding.objects_raw.filter(user=user)
for b in bindings:
    print('Role binding:', b.role.name, '| scope:', b.scope)
"