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

# Activate venv
source .venv/bin/activate

# Sync again (optional | onetime only)
uv sync --no-group xpack --python 3.11

# Then start
uv run python jms start web