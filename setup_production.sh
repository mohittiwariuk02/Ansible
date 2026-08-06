#!/usr/bin/env bash
# ==============================================================================
# Ansible SSH Manager — Production Setup & Deployment Script
# Target OS: RHEL / Rocky Linux / Ubuntu 22.04+
# ==============================================================================

set -e

echo "=================================================================="
echo "🚀 Starting Ansible SSH Manager Production Deployment Setup..."
echo "=================================================================="

# 1. Environment & Path Check
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

echo "📂 Base Working Directory: $BASE_DIR"

# 2. Virtual Environment Setup
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment in venv/..."
    python3 -m venv venv
fi

echo "⚡ Upgrading Pip and Installing Dependencies..."
./venv/bin/pip install --upgrade pip --quiet
./venv/bin/pip install -r requirements.txt --quiet

echo "✅ Python dependencies installed successfully."

# 3. Create Required Runtime Directories
mkdir -p logs scratch backend/__pycache__

# 4. Database Setup & Initialization
echo "🗄️ Initializing MySQL Database Schema..."
./venv/bin/python -c "
from backend.app import init_db
init_db()
print('✅ Database schema and initial seed data initialized successfully.')
"

# 5. Inventory & Ansible Config Verification
if [ ! -f "inventory.ini" ]; then
    echo "⚠️ Warning: inventory.ini not found. Creating default template..."
    cat <<EOF > inventory.ini
[web_servers]
# serv1 ansible_host=172.0.16.84

[all:vars]
ansible_user=ansible
ansible_become=true
ansible_become_method=sudo
EOF
fi

# 6. Verify Permissions on Playbooks & Key Files
chmod 644 inventory.ini ansible.cfg fetch_keys.yml manage_keys.yml

echo "=================================================================="
echo "🎉 Setup Complete! To start the production Gunicorn server, run:"
echo ""
echo "   ./venv/bin/gunicorn --workers 4 --bind 0.0.0.0:5000 backend.app:app"
echo ""
echo "Or use systemd service configuration in docs/deployment.md."
echo "=================================================================="
