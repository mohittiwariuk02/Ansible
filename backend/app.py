import os
import re
import sys
import json
import sqlite3
import subprocess
import threading
import time
import uuid
import base64
import hashlib
import math
from datetime import datetime, date, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, Response, send_from_directory, session
from flask_cors import CORS

import pymysql
from pymysql.cursors import DictCursor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY_PATH = os.path.join(BASE_DIR, "inventory.ini")
MANAGE_PLAYBOOK = os.path.join(BASE_DIR, "manage_keys.yml")
FETCH_PLAYBOOK = os.path.join(BASE_DIR, "fetch_keys.yml")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_USER = os.environ.get('MYSQL_USER', 'ansible_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'Ansible@123')
MYSQL_DB = os.environ.get('MYSQL_DB', 'Ansible')
MYSQL_SOCKET = os.environ.get('MYSQL_SOCKET', '')

def get_db_connection():
    """Get a MySQL database connection with DictCursor."""
    kwargs = {
        'user': MYSQL_USER,
        'password': MYSQL_PASSWORD,
        'database': MYSQL_DB,
        'autocommit': True,
        'cursorclass': DictCursor,
        'charset': 'utf8mb4'
    }
    if MYSQL_SOCKET and os.path.exists(MYSQL_SOCKET):
        kwargs['unix_socket'] = MYSQL_SOCKET
    else:
        kwargs['host'] = MYSQL_HOST
        kwargs['port'] = MYSQL_PORT
    return pymysql.connect(**kwargs)

VENV_ANSIBLE = os.path.join(BASE_DIR, "venv", "bin", "ansible-playbook")
ANSIBLE_BIN = VENV_ANSIBLE if os.path.exists(VENV_ANSIBLE) else "ansible-playbook"

app = Flask(__name__, static_folder=FRONTEND_DIR)
app.secret_key = os.environ.get('SECRET_KEY', 'ansible_ssh_manager_super_secret_key_2026')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app, supports_credentials=True)

JOB_LOGS = {}
JOB_STATUS = {}

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_cache (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                host VARCHAR(255) NOT NULL,
                user VARCHAR(255) NOT NULL,
                keys_count INT DEFAULT 0,
                has_access TINYINT(1) DEFAULT 0,
                status VARCHAR(50) DEFAULT 'active',
                keys_text MEDIUMTEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uk_host_user (host, user)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_key_cache (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                host VARCHAR(255) NOT NULL,
                user VARCHAR(255) NOT NULL,
                home_dir VARCHAR(512) DEFAULT '',
                algorithm VARCHAR(50) DEFAULT '',
                key_body TEXT NOT NULL,
                raw_key TEXT NOT NULL,
                fingerprint VARCHAR(255) NOT NULL,
                comment VARCHAR(512) DEFAULT '',
                status VARCHAR(50) DEFAULT 'active',
                is_duplicate TINYINT(1) DEFAULT 0,
                last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                last_modified_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uk_host_user_fp (host, user, fingerprint(191)),
                INDEX idx_fp (fingerprint(191)),
                INDEX idx_host_user (host, user),
                INDEX idx_algo (algorithm)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_history (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                job_id VARCHAR(64) UNIQUE NOT NULL,
                sync_mode VARCHAR(50) NOT NULL,
                target_hosts TEXT NOT NULL,
                operator_name VARCHAR(255) DEFAULT 'Admin',
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at DATETIME NULL,
                status VARCHAR(50) DEFAULT 'RUNNING',
                servers_processed INT DEFAULT 0,
                users_scanned INT DEFAULT 0,
                keys_added INT DEFAULT 0,
                keys_updated INT DEFAULT 0,
                keys_removed INT DEFAULT 0,
                failures TEXT,
                execution_time_sec DOUBLE DEFAULT 0.0,
                INDEX idx_job_id (job_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS job_history (
                id VARCHAR(64) PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action VARCHAR(100) NOT NULL,
                target_user VARCHAR(255) NOT NULL,
                target_hosts TEXT NOT NULL,
                key_comment TEXT,
                status VARCHAR(50) NOT NULL,
                logs LONGTEXT,
                duration DOUBLE DEFAULT 0.0,
                operator_name VARCHAR(255) DEFAULT 'Admin',
                key_fingerprint VARCHAR(255) DEFAULT '--',
                expires_at VARCHAR(255) DEFAULT 'Permanent',
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_temp_keys (
                id VARCHAR(64) PRIMARY KEY,
                host VARCHAR(255) NOT NULL,
                user VARCHAR(255) NOT NULL,
                ssh_key TEXT,
                fingerprint VARCHAR(255),
                operator_name VARCHAR(255),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at VARCHAR(255),
                revoked TINYINT(1) DEFAULT 0
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        # Enterprise Server Metadata Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_metadata (
                host VARCHAR(255) PRIMARY KEY,
                ip VARCHAR(255) DEFAULT '',
                group_name VARCHAR(255) DEFAULT 'web_servers',
                environment VARCHAR(50) DEFAULT 'Production',
                region VARCHAR(100) DEFAULT 'us-east-1',
                os_info VARCHAR(100) DEFAULT 'Linux',
                tags VARCHAR(512) DEFAULT 'web,production',
                owner VARCHAR(100) DEFAULT 'DevOps Team',
                status VARCHAR(50) DEFAULT 'online',
                is_favorite TINYINT(1) DEFAULT 0,
                last_ping_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_env (environment),
                INDEX idx_region (region),
                INDEX idx_group (group_name),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        # Synchronization Change Audit Log Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_change_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                job_id VARCHAR(64) NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                operator_name VARCHAR(255) DEFAULT 'Admin',
                host VARCHAR(255) NOT NULL,
                user VARCHAR(255) NOT NULL,
                change_type VARCHAR(50) NOT NULL,
                previous_value TEXT,
                new_value TEXT,
                description TEXT,
                INDEX idx_job (job_id),
                INDEX idx_host (host),
                INDEX idx_user (user),
                INDEX idx_type (change_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        # RBAC Tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS roles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                role_name VARCHAR(50) UNIQUE NOT NULL,
                description VARCHAR(255) DEFAULT ''
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                perm_key VARCHAR(100) UNIQUE NOT NULL,
                description VARCHAR(255) DEFAULT ''
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INT NOT NULL,
                perm_id INT NOT NULL,
                PRIMARY KEY (role_id, perm_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (perm_id) REFERENCES permissions(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_users (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255) DEFAULT '',
                role_id INT NOT NULL,
                is_active TINYINT(1) DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        # Seed Default Roles
        cursor.execute("INSERT IGNORE INTO roles (id, role_name, description) VALUES (1, 'admin', 'Administrator with full system access'), (2, 'developer', 'Developer with read-only access and masked keys')")

        # Seed Default Permissions
        perms = [
            (1, 'read:keys', 'View servers, users, and SSH key summaries'),
            (2, 'write:keys', 'Add, edit, delete, enable, disable, and share SSH keys'),
            (3, 'view:full_key', 'View complete unmasked SSH public keys'),
            (4, 'manage:servers', 'Add and remove managed server hosts'),
            (5, 'manage:users', 'Manage dashboard user accounts and role assignments'),
            (6, 'trigger:sync', 'Initiate background SSH key synchronization')
        ]
        for pid, pkey, pdesc in perms:
            cursor.execute("INSERT IGNORE INTO permissions (id, perm_key, description) VALUES (%s, %s, %s)", (pid, pkey, pdesc))

        # Assign All Permissions to Admin Role (1)
        for pid in range(1, 7):
            cursor.execute("INSERT IGNORE INTO role_permissions (role_id, perm_id) VALUES (1, %s)", (pid,))

        # Assign Read-Only & Sync Permissions to Developer Role (2)
        cursor.execute("INSERT IGNORE INTO role_permissions (role_id, perm_id) VALUES (2, 1)")
        cursor.execute("INSERT IGNORE INTO role_permissions (role_id, perm_id) VALUES (2, 6)")

        # Seed Default Admin User ('admin' / 'admin123')
        admin_hash = generate_password_hash('admin123')
        cursor.execute("INSERT IGNORE INTO app_users (username, password_hash, full_name, role_id, is_active) VALUES ('admin', %s, 'Administrator', 1, 1)", (admin_hash,))

        conn.close()
    except Exception as e:
        print(f"Notice initializing MySQL database: {e}")

def mask_ssh_key(key_str):
    """Mask SSH key body so complete key is never exposed to Developer role."""
    if not key_str or not isinstance(key_str, str):
        return ""
    parts = key_str.strip().split()
    if len(parts) < 2:
        return key_str[:8] + "...[MASKED]..."
    algo = parts[0]
    body = parts[1]
    comment = " ".join(parts[2:]) if len(parts) >= 3 else ""

    if len(body) <= 24:
        masked_body = body[:6] + "...[MASKED]..." + body[-6:]
    else:
        masked_body = body[:12] + "...[MASKED]..." + body[-12:]

    return f"{algo} {masked_body}" + (f" {comment}" if comment else "")

def get_user_permissions(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.perm_key
        FROM app_users u
        JOIN role_permissions rp ON u.role_id = rp.role_id
        JOIN permissions p ON rp.perm_id = p.id
        WHERE u.id = %s AND u.is_active = 1
    ''', (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return {r['perm_key'] for r in rows}

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.username, u.full_name, u.role_id, r.role_name
        FROM app_users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.id = %s AND u.is_active = 1
    ''', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        user['permissions'] = list(get_user_permissions(user['id']))
    return user

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required. Please log in.", "code": "UNAUTHORIZED"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_perm(perm_key):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required. Please log in.", "code": "UNAUTHORIZED"}), 401
            perms = user.get('permissions', [])
            if perm_key not in perms:
                return jsonify({"error": f"Permission denied. Required permission: '{perm_key}'.", "code": "FORBIDDEN"}), 403
            request.current_user = user
            return f(*args, **kwargs)
        return decorated
    return decorator

def sync_access_cache_to_ssh_key_cache():
    """Seed ssh_key_cache from access_cache keys_text upon startup."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT host, user, keys_text FROM access_cache WHERE keys_text IS NOT NULL AND keys_text != ''")
        rows = cursor.fetchall()
        
        for r in rows:
            host, user, keys_text = r['host'], r['user'], r['keys_text']
            parsed_keys = parse_authorized_keys_text(keys_text)
            home_dir = f"/root" if user == 'root' else f"/home/{user}"
            for k in parsed_keys:
                raw_k = k.get('raw_key', '').strip()
                if not raw_k: continue
                parts = raw_k.split()
                key_body = parts[1] if len(parts) >= 2 else raw_k
                algo = k.get('algorithm') or (parts[0] if parts else 'ssh-rsa')
                fp = k.get('fingerprint') or compute_ssh_fingerprint(raw_k)
                comment = k.get('comment') or (" ".join(parts[2:]) if len(parts) >= 3 else "")

                cursor.execute('''
                    INSERT INTO ssh_key_cache (host, user, home_dir, algorithm, key_body, raw_key, fingerprint, comment, status, last_synced_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', NOW())
                    ON DUPLICATE KEY UPDATE
                        algorithm=VALUES(algorithm),
                        key_body=VALUES(key_body),
                        raw_key=VALUES(raw_key),
                        comment=VALUES(comment),
                        status='active',
                        last_synced_at=NOW()
                ''', (host, user, home_dir, algo, key_body, raw_k, fp, comment))

        cursor.execute('''
            UPDATE ssh_key_cache s
            SET is_duplicate = (
                SELECT IF(COUNT(DISTINCT CONCAT(k2.host, ':', k2.user)) > 1, 1, 0)
                FROM (SELECT host, user, fingerprint FROM ssh_key_cache) k2
                WHERE k2.fingerprint = s.fingerprint
            )
        ''')
        conn.close()
    except Exception as e:
        print(f"Notice during sync_access_cache_to_ssh_key_cache: {e}")

init_db()


def get_env():
    env = os.environ.copy()
    env["ANSIBLE_LOCAL_TEMP"] = os.path.join(BASE_DIR, ".ansible_tmp", "local")
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    env["ANSIBLE_SSH_COMMON_ARGS"] = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
    env["PYTHONUNBUFFERED"] = "1"
    return env

def safe_b64decode_bytes(s):
    """Safely decode base64 string into bytes, fixing padding and stripping whitespace/corrupt characters."""
    if not s or not isinstance(s, str):
        return b""
    clean_s = s.strip().replace(' ', '').replace('\n', '').replace('\r', '').replace('\\n', '').replace('\\r', '')
    if not clean_s or clean_s.lower() in ("none", "null"):
        return b""
    missing_padding = len(clean_s) % 4
    if missing_padding == 1:
        clean_s = clean_s[:-1]
    elif missing_padding > 1:
        clean_s += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(clean_s)
    except Exception as e:
        print(f"Notice: safe_b64decode_bytes fallback: {e}")
        return b""

def safe_b64decode(s):
    """Safely decode base64 string into UTF-8 text, fixing padding and stripping whitespace/corrupt characters."""
    raw_bytes = safe_b64decode_bytes(s)
    if not raw_bytes:
        return ""
    return raw_bytes.decode('utf-8', errors='ignore').strip()

def compute_ssh_fingerprint(key_str):
    if not key_str or not isinstance(key_str, str):
        return "N/A"
    parts = key_str.strip().split()
    if len(parts) < 2:
        return "N/A"
    try:
        raw_key = safe_b64decode_bytes(parts[1])
        if not raw_key:
            return "N/A"
        fp = hashlib.sha256(raw_key).digest()
        encoded_fp = base64.b64encode(fp).decode('ascii').rstrip('=')
        return f"SHA256:{encoded_fp}"
    except Exception:
        return "Invalid Key Format"

def parse_authorized_keys_text(keys_text):
    """
    Parse a raw authorized_keys text block (which may contain multiple key lines)
    into a structured list of key objects with algorithm, comment, fingerprint, and raw_key.
    """
    keys_list = []
    if not keys_text or not isinstance(keys_text, str):
        return keys_list

    valid_prefixes = ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com"]

    for line in keys_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 2 and any(parts[0] == p for p in valid_prefixes):
            algo = parts[0]
            comment = " ".join(parts[2:]) if len(parts) >= 3 else "No comment tag"
            fp = compute_ssh_fingerprint(line)
            keys_list.append({
                "algorithm": algo,
                "comment": comment,
                "fingerprint": fp,
                "raw_key": line
            })

    return keys_list

sync_access_cache_to_ssh_key_cache()

def parse_duration(duration_str):
    if not duration_str or duration_str == "permanent":
        return None
    now = datetime.now()
    if duration_str == "30m":
        return now + timedelta(minutes=30)
    elif duration_str == "1h":
        return now + timedelta(hours=1)
    elif duration_str == "12h":
        return now + timedelta(hours=12)
    elif duration_str == "5d":
        return now + timedelta(days=5)
    elif duration_str == "15d":
        return now + timedelta(days=15)
    elif duration_str == "30d":
        return now + timedelta(days=30)
    return None

def parse_inventory(path):
    """Parse Ansible inventory file, correctly skipping :vars and :children sections."""
    if not os.path.exists(path):
        return {"groups": {}, "all_hosts": []}

    groups = {}
    current_group_full = "ungrouped"   # Full name including :vars / :children
    all_hosts = []

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_group_full = line[1:-1]          # e.g. "all:vars", "web_servers"
                group_base = current_group_full.split(":")[0]
                # Only create a hosts list for real host groups (not :vars or :children)
                is_host_group = (
                    not current_group_full.endswith(":vars")
                    and not current_group_full.endswith(":children")
                )
                if is_host_group and group_base not in groups:
                    groups[group_base] = []
            else:
                # Skip anything inside :vars or :children sections
                if current_group_full.endswith(":vars") or current_group_full.endswith(":children"):
                    continue

                parts = line.split()
                if not parts:
                    continue

                hostname = parts[0]
                # Skip lines that look like variable assignments (contain = but no space before =)
                if "=" in hostname and not " " in hostname.split("=")[0]:
                    continue

                host_vars = {}
                for p in parts[1:]:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        host_vars[k] = v

                group_base = current_group_full.split(":")[0]
                host_info = {
                    "name": hostname,
                    "ip":   host_vars.get("ansible_host", hostname),
                    "group": group_base
                }

                if group_base not in groups:
                    groups[group_base] = []
                groups[group_base].append(host_info)

                if hostname not in [h["name"] for h in all_hosts]:
                    all_hosts.append(host_info)

    return {"groups": groups, "all_hosts": all_hosts}

def validate_ssh_public_key(key):
    key = key.strip()
    if not key:
        return False, "SSH key string cannot be empty."
    
    valid_prefixes = ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com"]
    if not any(key.startswith(prefix) for prefix in valid_prefixes):
        return False, f"Key must start with a valid algorithm prefix (e.g. ssh-rsa, ssh-ed25519, ecdsa-*)."
    
    parts = key.split()
    if len(parts) < 2:
        return False, "Invalid SSH key format. Must include key type and base64 encoded payload."
    
    return True, "Valid SSH key"

def update_access_cache(host, user, keys_count, status='active', keys_text=''):
    """
    Update the access cache for a specific host+user in MySQL.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        has_access = 1 if (status == 'active' and keys_count > 0) else 0

        if keys_count > 0 or status in ['active', 'disabled']:
            cursor.execute('''
                INSERT INTO access_cache (host, user, keys_count, has_access, status, keys_text, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                    keys_count=VALUES(keys_count),
                    has_access=VALUES(has_access),
                    status=VALUES(status),
                    keys_text=VALUES(keys_text),
                    updated_at=NOW()
            ''', (host, user, keys_count, has_access, status, keys_text))
        else:
            cursor.execute('''
                UPDATE access_cache
                SET keys_count=0, has_access=0, status='none', keys_text='', updated_at=NOW()
                WHERE host=%s AND user=%s
            ''', (host, user))

        conn.close()
    except Exception as e:
        print(f"Error updating access_cache: {e}")

def run_ansible_playbook(job_id, command, action, target_user, target_hosts_str, key_comment, operator_name, key_fingerprint, expires_at_str=None, ssh_key=""):
    start_time = time.time()
    JOB_LOGS[job_id] = [f"[{datetime.now().strftime('%H:%M:%S')}] Starting Ansible execution for job {job_id}...\n"]
    JOB_LOGS[job_id].append(f"[{datetime.now().strftime('%H:%M:%S')}] Operator: {operator_name} | Action: {action} | Duration: {expires_at_str or 'Permanent'}\n")
    JOB_LOGS[job_id].append(f"[{datetime.now().strftime('%H:%M:%S')}] Command: {' '.join(command)}\n\n")
    JOB_STATUS[job_id] = "RUNNING"

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=BASE_DIR,
            env=get_env()
        )

        for line in proc.stdout:
            JOB_LOGS[job_id].append(line)

        proc.wait()
        duration = round(time.time() - start_time, 2)

        if proc.returncode == 0:
            status = "SUCCESS"
            JOB_LOGS[job_id].append(f"\n[{datetime.now().strftime('%H:%M:%S')}] Execution finished successfully in {duration}s.\n")
            
            # Update cache based on action
            hosts_list = parse_inventory(INVENTORY_PATH)["all_hosts"]
            target_list = [h["name"] for h in hosts_list] if target_hosts_str == "all" else target_hosts_str.split(",")

            conn = get_db_connection()
            cursor = conn.cursor()

            for h in target_list:
                h = h.strip()
                if action in ["ADD_KEY", "GRANT_ACCESS_CLONE"]:
                    cursor.execute("SELECT keys_text FROM access_cache WHERE host=%s AND user=%s", (h, target_user))
                    row = cursor.fetchone()
                    existing_text = row["keys_text"] if row and row.get("keys_text") else ""

                    if existing_text and ssh_key:
                        existing_lines = [l.strip() for l in existing_text.splitlines() if l.strip()]
                        for new_line in ssh_key.splitlines():
                            new_line = new_line.strip()
                            if new_line and new_line not in existing_lines:
                                existing_lines.append(new_line)
                        combined_text = "\n".join(existing_lines)
                    else:
                        combined_text = ssh_key.strip()

                    parsed_keys = parse_authorized_keys_text(combined_text)
                    new_count = len(parsed_keys) if parsed_keys else 1

                    update_access_cache(h, target_user, new_count, status='active', keys_text=combined_text)

                    if expires_at_str and expires_at_str != "Permanent":
                        cursor.execute('''
                            INSERT INTO active_temp_keys (id, host, user, ssh_key, fingerprint, operator_name, created_at, expires_at)
                            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
                        ''', (str(uuid.uuid4())[:8], h, target_user, ssh_key, key_fingerprint, operator_name, expires_at_str))

                elif action == "REVOKE_KEY":
                    cursor.execute("SELECT keys_text FROM access_cache WHERE host=%s AND user=%s", (h, target_user))
                    row = cursor.fetchone()
                    existing_text = row["keys_text"] if row and row.get("keys_text") else ""

                    if existing_text and ssh_key:
                        target_raw = ssh_key.strip()
                        target_parts = target_raw.split()
                        target_body = target_parts[1] if len(target_parts) >= 2 else target_raw

                        existing_lines = [l.strip() for l in existing_text.splitlines() if l.strip()]
                        remaining_lines = []
                        for l in existing_lines:
                            l_parts = l.split()
                            l_body = l_parts[1] if len(l_parts) >= 2 else l
                            if l_body != target_body and l != target_raw:
                                remaining_lines.append(l)

                        rem_text = "\n".join(remaining_lines)
                        parsed_rem = parse_authorized_keys_text(rem_text)
                        rem_count = len(parsed_rem)
                        if rem_count > 0:
                            update_access_cache(h, target_user, rem_count, status='active', keys_text=rem_text)
                        else:
                            update_access_cache(h, target_user, 0, status='none', keys_text='')
                    else:
                        update_access_cache(h, target_user, 0, status='none', keys_text='')

                    cursor.execute("UPDATE active_temp_keys SET revoked=1 WHERE host=%s AND user=%s", (h, target_user))

                elif action == "PURGE_USER_ACCESS":
                    update_access_cache(h, target_user, 0, status='none', keys_text='')
                    cursor.execute("UPDATE active_temp_keys SET revoked=1 WHERE host=%s AND user=%s", (h, target_user))

                elif action == "DISABLE_ACCESS":
                    cursor.execute("SELECT keys_count, keys_text FROM access_cache WHERE host=%s AND user=%s", (h, target_user))
                    row = cursor.fetchone()
                    existing_text = row["keys_text"] if row and row.get("keys_text") else ssh_key
                    parsed = parse_authorized_keys_text(existing_text)
                    count = len(parsed) if parsed else (row["keys_count"] if row and row.get("keys_count") else 1)
                    update_access_cache(h, target_user, count, status='disabled', keys_text=existing_text)
                    cursor.execute("UPDATE active_temp_keys SET revoked=1 WHERE host=%s AND user=%s", (h, target_user))

                elif action == "ENABLE_ACCESS":
                    cursor.execute("SELECT keys_count, keys_text FROM access_cache WHERE host=%s AND user=%s", (h, target_user))
                    row = cursor.fetchone()
                    existing_text = row["keys_text"] if row and row.get("keys_text") else ssh_key
                    parsed = parse_authorized_keys_text(existing_text)
                    count = len(parsed) if parsed else max(row["keys_count"] if row and row.get("keys_count") else 1, 1)
                    update_access_cache(h, target_user, count, status='active', keys_text=existing_text)
                    cursor.execute("UPDATE active_temp_keys SET revoked=0 WHERE host=%s AND user=%s", (h, target_user))

            conn.close()

        else:
            status = "FAILED"
            JOB_LOGS[job_id].append(f"\n[{datetime.now().strftime('%H:%M:%S')}] Execution failed with return code {proc.returncode}.\n")

        JOB_STATUS[job_id] = status
        full_logs = "".join(JOB_LOGS[job_id])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO job_history (id, timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, logs, duration, expires_at)
            VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE status=VALUES(status), logs=VALUES(logs)
        ''', (job_id, action, target_user, target_hosts_str, key_comment, operator_name, key_fingerprint, status, full_logs, duration, expires_at_str or "Permanent"))
        conn.close()

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        JOB_STATUS[job_id] = "FAILED"
        err_msg = f"\n[{datetime.now().strftime('%H:%M:%S')}] Error executing process: {str(e)}\n"
        JOB_LOGS[job_id].append(err_msg)
        full_logs = "".join(JOB_LOGS[job_id])

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO job_history (id, timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, logs, duration, expires_at)
                VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE status=VALUES(status), logs=VALUES(logs)
            ''', (job_id, action, target_user, target_hosts_str, key_comment, operator_name, key_fingerprint, "FAILED", full_logs, duration, expires_at_str or "Permanent"))
            conn.close()
        except Exception:
            pass

# Background Expiration Worker
def check_temp_key_expirations():
    while True:
        try:
            time.sleep(30) # Check every 30 seconds
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM active_temp_keys WHERE revoked=0 AND expires_at <= NOW()')
            expired_keys = cursor.fetchall()

            for key_record in expired_keys:
                rec_id = key_record["id"]
                host = key_record["host"]
                user = key_record["user"]
                ssh_key = key_record["ssh_key"]
                op_name = key_record["operator_name"]

                print(f"[*] Temporary SSH key expired for user '{user}' on host '{host}'. Revoking now...")

                job_id = str(uuid.uuid4())[:8]
                extra_vars = {
                    "target_user": user,
                    "ssh_key": ssh_key,
                    "key_state": "absent" if ssh_key else "purge_all",
                    "key_comment": "Auto-Expired Key Revocation",
                    "target_hosts": host
                }

                cmd = [ANSIBLE_BIN, "-i", INVENTORY_PATH, MANAGE_PLAYBOOK, "--extra-vars", json.dumps(extra_vars), "--limit", host]

                cursor.execute('UPDATE active_temp_keys SET revoked=1 WHERE id=%s', (rec_id,))

                # Dispatch Ansible revocation thread
                t = threading.Thread(
                    target=run_ansible_playbook,
                    args=(job_id, cmd, "EXPIRED_KEY_AUTO_REVOKED", user, host, "Auto Expired", "System Scheduler", key_record["fingerprint"], "Expired")
                )
                t.daemon = True
                t.start()

            conn.close()
        except Exception as e:
            print(f"[!] Error in expiration checker: {e}")

# Start background expiration checker thread
exp_thread = threading.Thread(target=check_temp_key_expirations)
exp_thread.daemon = True
exp_thread.start()

# Routes
@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(FRONTEND_DIR, filename)

@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    data = parse_inventory(INVENTORY_PATH)
    return jsonify(data)

@app.route('/api/ping', methods=['POST'])
def ping_servers():
    ansible_cmd = os.path.join(BASE_DIR, "venv", "bin", "ansible") if os.path.exists(os.path.join(BASE_DIR, "venv", "bin", "ansible")) else "ansible"
    cmd = [ansible_cmd, "all", "-i", INVENTORY_PATH, "-m", "ping"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env())
        return jsonify({"status": "completed", "output": res.stdout, "returncode": res.returncode})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Auth & Session Routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.username, u.password_hash, u.full_name, u.role_id, r.role_name, u.is_active
        FROM app_users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.username = %s
    ''', (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not user['is_active'] or not check_password_hash(user['password_hash'], password):
        return jsonify({"error": "Invalid username or password."}), 401

    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role_name']

    perms = list(get_user_permissions(user['id']))

    return jsonify({
        "status": "success",
        "message": f"Welcome back, {user['full_name']}!",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "full_name": user['full_name'],
            "role": user['role_name'],
            "permissions": perms
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Successfully logged out."})

@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 200
    return jsonify({
        "authenticated": True,
        "user": {
            "id": user['id'],
            "username": user['username'],
            "full_name": user['full_name'],
            "role": user['role_name'],
            "permissions": user['permissions']
        }
    })

@app.route('/api/users', methods=['GET'])
@require_perm('manage:users')
def list_dashboard_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.username, u.full_name, u.role_id, r.role_name, u.is_active, u.created_at
        FROM app_users u
        JOIN roles r ON u.role_id = r.id
        ORDER BY u.id ASC
    ''')
    users = cursor.fetchall()
    conn.close()
    for u in users:
        u['created_at'] = format_dt(u.get('created_at'))
    return jsonify(users)

@app.route('/api/users/create', methods=['POST'])
@require_perm('manage:users')
def create_dashboard_user():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    full_name = data.get('full_name', '').strip() or username
    role_id = int(data.get('role_id', 2))

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM app_users WHERE username = %s", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": f"Username '{username}' already exists."}), 400

    pwd_hash = generate_password_hash(password)
    cursor.execute('''
        INSERT INTO app_users (username, password_hash, full_name, role_id, is_active)
        VALUES (%s, %s, %s, %s, 1)
    ''', (username, pwd_hash, full_name, role_id))
    conn.close()

    return jsonify({"status": "success", "message": f"User '{username}' created successfully."})

@app.route('/api/keys/deploy', methods=['POST'])
@require_perm('write:keys')
def deploy_key():
    data = request.json or {}
    target_hosts = data.get('target_hosts', [])
    target_user = data.get('target_user', '').strip()
    ssh_key = data.get('ssh_key', '').strip()
    action = data.get('action', 'add').lower()
    comment = data.get('comment', 'Managed by Web UI').strip()
    operator_name = data.get('operator_name', 'Admin').strip() or 'Admin'
    duration_str = data.get('access_duration', 'permanent')

    if not target_user:
        return jsonify({"error": "Target username is required."}), 400

    if not target_hosts:
        return jsonify({"error": "Please select at least one target server."}), 400

    exp_datetime = parse_duration(duration_str)
    expires_at_iso = exp_datetime.isoformat() if exp_datetime else "Permanent"

    fingerprint = compute_ssh_fingerprint(ssh_key) if ssh_key else "ALL_KEYS_PURGED"

    if action == "add":
        valid, msg = validate_ssh_public_key(ssh_key)
        if not valid:
            return jsonify({"error": msg}), 400
        key_state = "present"
        action_label = "ADD_KEY"
    elif action == "remove":
        if not ssh_key:
            key_state = "purge_all"
            action_label = "PURGE_USER_ACCESS"
        else:
            key_state = "absent"
            action_label = "REVOKE_KEY"
    elif action == "purge":
        key_state = "purge_all"
        action_label = "PURGE_USER_ACCESS"
    elif action == "disable":
        key_state = "disable"
        action_label = "DISABLE_ACCESS"
    elif action == "enable":
        key_state = "enable"
        action_label = "ENABLE_ACCESS"
    else:
        return jsonify({"error": "Invalid action. Must be 'add', 'remove', 'purge', 'disable', or 'enable'."}), 400

    job_id = str(uuid.uuid4())[:8]
    target_hosts_pattern = ",".join(target_hosts) if isinstance(target_hosts, list) else target_hosts

    has_orig_comment = False
    if ssh_key:
        parts = ssh_key.strip().split()
        if len(parts) >= 3:
            has_orig_comment = True

    ansible_comment = "" if (has_orig_comment or key_state == "absent") else comment

    extra_vars = {
        "target_user": target_user,
        "ssh_key": ssh_key,
        "key_state": key_state,
        "key_comment": ansible_comment,
        "target_hosts": target_hosts_pattern
    }

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        MANAGE_PLAYBOOK,
        "--extra-vars", json.dumps(extra_vars)
    ]

    if target_hosts_pattern and target_hosts_pattern != 'all':
        cmd.extend(["--limit", target_hosts_pattern])

    thread = threading.Thread(
        target=run_ansible_playbook,
        args=(job_id, cmd, action_label, target_user, target_hosts_pattern, comment, operator_name, fingerprint, expires_at_iso, ssh_key)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "RUNNING",
        "action": action_label,
        "target_user": target_user,
        "target_hosts": target_hosts_pattern,
        "operator_name": operator_name,
        "fingerprint": fingerprint,
        "expires_at": expires_at_iso
    })

@app.route('/api/matrix', methods=['GET'])
def get_access_matrix():
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    inventory = parse_inventory(INVENTORY_PATH)

    conn = get_db_connection()
    cursor = conn.cursor()

    if not force_refresh:
        cursor.execute("SELECT host, user, keys_count, has_access, status, keys_text FROM access_cache")
        rows = cursor.fetchall()
        conn.close()

        matrix = {}
        server_users_summary = {}
        user_directory = {}

        for row in rows:
            h = row["host"]
            u = row["user"]
            c = row["keys_count"]
            s = row["status"] if row.get("status") else ("active" if row["has_access"] else "none")
            kt = row["keys_text"] if row.get("keys_text") else ""
            kl = parse_authorized_keys_text(kt)

            if h not in matrix:
                matrix[h] = {}
                server_users_summary[h] = []
            matrix[h][u] = {
                "keys_count": len(kl) if kl else c,
                "has_access": s == "active",
                "status": s,
                "keys_text": kt,
                "keys_list": kl
            }
            if s == "active" and u not in server_users_summary[h]:
                server_users_summary[h].append(u)

            if u not in user_directory:
                user_directory[u] = {
                    "servers": {},
                    "active_hosts_count": 0,
                    "has_key": False,
                    "keys_text": "",
                    "keys_list": []
                }
            user_directory[u]["servers"][h] = {
                "status": s,
                "keys_count": len(kl) if kl else c,
                "has_access": s == "active",
                "keys_list": kl
            }
            if s == "active":
                user_directory[u]["active_hosts_count"] += 1
            if kt:
                user_directory[u]["has_key"] = True
                if not user_directory[u]["keys_text"]:
                    user_directory[u]["keys_text"] = kt
                    user_directory[u]["keys_list"] = kl

        return jsonify({
            "inventory": inventory,
            "matrix": matrix,
            "server_users_summary": server_users_summary,
            "user_directory": user_directory,
            "source": "cache",
            "timestamp": datetime.now().isoformat()
        })

    conn.close()
    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        FETCH_PLAYBOOK,
        "--extra-vars", json.dumps({"target_user": "", "target_hosts": "all"})
    ]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=120)
        output = res.stdout

        matrix = {}
        server_users_summary = {}
        user_directory = {}

        for line in output.splitlines():
            line = line.strip().strip('"').strip("'")
            if 'SSHKEYAUDIT|' in line:
                idx = line.index('SSHKEYAUDIT|')
                audit_line = line[idx:]
                parts = audit_line.split('|')
                data = {}
                for p in parts[1:]:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        data[k.strip()] = v.strip()
                host = data.get('host', '').strip()
                user = data.get('user', '').strip()
                try:
                    count = int(data.get('keys_count', 0))
                except ValueError:
                    count = 0

                status = data.get('status', 'active' if count > 0 else 'none').strip()
                keys_b64 = data.get('keys_b64', '').strip()
                keys_text = ""
                if keys_b64:
                    keys_text = safe_b64decode(keys_b64)

                keys_list = parse_authorized_keys_text(keys_text)
                final_count = len(keys_list) if keys_list else count

                if host and user:
                    if host not in matrix:
                        matrix[host] = {}
                        server_users_summary[host] = []
                    matrix[host][user] = {
                        "keys_count": final_count,
                        "has_access": status == "active",
                        "status": status,
                        "keys_text": keys_text,
                        "keys_list": keys_list
                    }
                    if status == "active" and user not in server_users_summary[host]:
                        server_users_summary[host].append(user)

                    if user not in user_directory:
                        user_directory[user] = {
                            "servers": {},
                            "active_hosts_count": 0,
                            "has_key": False,
                            "keys_text": "",
                            "keys_list": []
                        }
                    user_directory[user]["servers"][host] = {
                        "status": status,
                        "keys_count": final_count,
                        "has_access": status == "active",
                        "keys_list": keys_list
                    }
                    if status == "active":
                        user_directory[user]["active_hosts_count"] += 1
                    if keys_text:
                        user_directory[user]["has_key"] = True
                        if not user_directory[user]["keys_text"]:
                            user_directory[user]["keys_text"] = keys_text
                            user_directory[user]["keys_list"] = keys_list

                    update_access_cache(host, user, final_count, status=status, keys_text=keys_text)

        return jsonify({
            "inventory": inventory,
            "matrix": matrix,
            "server_users_summary": server_users_summary,
            "user_directory": user_directory,
            "source": "live_scan",
            "timestamp": datetime.now().isoformat()
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ansible scan timed out after 120s. Check server connectivity.", "inventory": inventory}), 500
    except Exception as e:
        return jsonify({"error": str(e), "inventory": inventory}), 500

@app.route('/api/keys/grant_access', methods=['POST'])
@require_perm('write:keys')
def grant_access():
    data = request.json or {}
    target_user = data.get('target_user', '').strip()
    source_host = data.get('source_host', '').strip()
    target_hosts = data.get('target_hosts', [])
    operator_name = data.get('operator_name', 'Admin').strip() or 'Admin'
    duration_str = data.get('access_duration', 'permanent')

    if not target_user or not source_host or not target_hosts:
        return jsonify({"error": "target_user, source_host, and target_hosts are required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT keys_text FROM access_cache WHERE host=%s AND user=%s AND keys_text != ''", (source_host, target_user))
    row = cursor.fetchone()
    conn.close()

    ssh_key = row["keys_text"] if row else ""

    if not ssh_key:
        cmd_fetch = [
            ANSIBLE_BIN,
            "-i", INVENTORY_PATH,
            FETCH_PLAYBOOK,
            "--extra-vars", json.dumps({"target_user": target_user, "target_hosts": source_host})
        ]
        try:
            res = subprocess.run(cmd_fetch, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=30)
            for line in res.stdout.splitlines():
                if 'SSHKEYAUDIT|' in line and f"user={target_user}" in line:
                    parts = line[line.index('SSHKEYAUDIT|'):].split('|')
                    p_data = dict(p.split('=', 1) for p in parts[1:] if '=' in p)
                    kb64 = p_data.get('keys_b64', '').strip()
                    if kb64:
                        ssh_key = safe_b64decode(kb64)
                        break
        except Exception as e:
            print(f"Error fetching live key from {source_host}: {e}")

    if not ssh_key:
        return jsonify({"error": f"No SSH key found for user '{target_user}' on source host '{source_host}'."}), 400

    exp_datetime = parse_duration(duration_str)
    expires_at_iso = exp_datetime.isoformat() if exp_datetime else "Permanent"
    fingerprint = compute_ssh_fingerprint(ssh_key)

    job_id = str(uuid.uuid4())[:8]
    target_hosts_pattern = ",".join(target_hosts) if isinstance(target_hosts, list) else target_hosts

    extra_vars = {
        "target_user": target_user,
        "ssh_key": ssh_key,
        "key_state": "present",
        "key_comment": f"Granted from {source_host} by {operator_name}",
        "target_hosts": target_hosts_pattern
    }

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        MANAGE_PLAYBOOK,
        "--extra-vars", json.dumps(extra_vars),
        "--limit", target_hosts_pattern
    ]

    thread = threading.Thread(
        target=run_ansible_playbook,
        args=(job_id, cmd, "GRANT_ACCESS_CLONE", target_user, target_hosts_pattern, f"Cloned key from {source_host}", operator_name, fingerprint, expires_at_iso, ssh_key)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "RUNNING",
        "action": "GRANT_ACCESS_CLONE",
        "target_user": target_user,
        "source_host": source_host,
        "target_hosts": target_hosts_pattern,
        "operator_name": operator_name,
        "fingerprint": fingerprint,
        "expires_at": expires_at_iso
    })

@app.route('/api/servers/users', methods=['GET'])
@require_perm('read:keys')
def get_server_users():
    host = request.args.get('host', '').strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    if host and host != 'all':
        cursor.execute("SELECT DISTINCT user FROM access_cache WHERE host = %s AND status = 'active' ORDER BY user ASC", (host,))
        rows = cursor.fetchall()
        if not rows:
            cursor.execute("SELECT DISTINCT user FROM ssh_key_cache WHERE host = %s ORDER BY user ASC", (host,))
            rows = cursor.fetchall()
    else:
        cursor.execute("SELECT DISTINCT user FROM access_cache WHERE status = 'active' ORDER BY user ASC")
        rows = cursor.fetchall()

    conn.close()
    users = sorted(list(set([r['user'] for r in rows if r.get('user')])))
    return jsonify({"host": host or "all", "users": users})

@app.route('/api/keys/copy_cross_server', methods=['POST'])
@require_perm('write:keys')
def copy_cross_server_key():
    data = request.json or {}
    source_host = data.get('source_host', '').strip()
    source_user = data.get('source_user', '').strip()
    dest_host = data.get('destination_host', '').strip()
    dest_user = data.get('destination_user', '').strip()
    ssh_key = data.get('raw_key', '').strip()
    operator_name = data.get('operator_name', 'Admin').strip() or 'Admin'

    if not dest_user:
        return jsonify({"error": "Destination username is required."}), 400
    if not dest_host:
        return jsonify({"error": "Destination server host is required."}), 400
    if not ssh_key:
        return jsonify({"error": "No SSH key provided to copy."}), 400

    if dest_host and dest_host != 'all' and dest_user != 'root':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM access_cache WHERE host=%s AND user=%s", (dest_host, dest_user))
        c1 = cursor.fetchone()['cnt']
        cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache WHERE host=%s AND user=%s", (dest_host, dest_user))
        c2 = cursor.fetchone()['cnt']
        conn.close()
        if c1 == 0 and c2 == 0:
            return jsonify({"error": f"Destination user account '{dest_user}' does not exist on server '{dest_host}' in database inventory. Please run a Sync or select a valid server user."}), 400

    key_parts = ssh_key.strip().split()
    target_key_body = key_parts[1] if len(key_parts) >= 2 else ssh_key.strip()
    has_orig_comment = (len(key_parts) >= 3)
    orig_comment = " ".join(key_parts[2:]) if has_orig_comment else "Copied Key"

    hosts_list = parse_inventory(INVENTORY_PATH)["all_hosts"]
    target_hosts_list = [h["name"] for h in hosts_list] if dest_host == "all" else [h.strip() for h in dest_host.split(",")]

    conn = get_db_connection()
    cursor = conn.cursor()

    hosts_with_existing = []
    hosts_to_deploy = []

    for h in target_hosts_list:
        cursor.execute("SELECT keys_text FROM access_cache WHERE host=%s AND user=%s", (h, dest_user))
        row = cursor.fetchone()
        existing_text = row["keys_text"] if row and row.get("keys_text") else ""
        
        is_already_present = False
        if existing_text:
            for l in existing_text.splitlines():
                l_parts = l.strip().split()
                if len(l_parts) >= 2 and l_parts[1] == target_key_body:
                    is_already_present = True
                    break
        
        if is_already_present:
            hosts_with_existing.append(h)
        else:
            hosts_to_deploy.append(h)

    conn.close()

    if not hosts_to_deploy:
        return jsonify({
            "status": "already_exists",
            "message": f"Key '{orig_comment}' is ALREADY installed for user '{dest_user}' on {', '.join(hosts_with_existing)}. Skipped duplicate installation.",
            "hosts_skipped": hosts_with_existing
        }), 200

    target_hosts_pattern = ",".join(hosts_to_deploy)
    fingerprint = compute_ssh_fingerprint(ssh_key)
    job_id = str(uuid.uuid4())[:8]

    ansible_comment = "" if has_orig_comment else f"Copied from {source_host} by {operator_name}"

    extra_vars = {
        "target_user": dest_user,
        "ssh_key": ssh_key,
        "key_state": "present",
        "key_comment": ansible_comment,
        "target_hosts": target_hosts_pattern
    }

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        MANAGE_PLAYBOOK,
        "--extra-vars", json.dumps(extra_vars),
        "--limit", target_hosts_pattern
    ]

    thread = threading.Thread(
        target=run_ansible_playbook,
        args=(job_id, cmd, "GRANT_ACCESS_CLONE", dest_user, target_hosts_pattern, f"Copied key '{orig_comment}' from {source_host}", operator_name, fingerprint, "Permanent", ssh_key)
    )
    thread.daemon = True
    thread.start()

    msg = f"Copying key '{orig_comment}' to '{dest_user}' on {target_hosts_pattern}..."
    if hosts_with_existing:
        msg += f" (Skipped duplicate on: {', '.join(hosts_with_existing)})"

    return jsonify({
        "status": "success",
        "job_id": job_id,
        "message": msg,
        "target_user": dest_user,
        "target_hosts": target_hosts_pattern,
        "hosts_skipped": hosts_with_existing
    })

@app.route('/api/keys/share_validate', methods=['POST'])
def share_validate_keys():
    data = request.json or {}
    dest_host = data.get('destination_host', '').strip()
    dest_user = data.get('destination_user', '').strip()
    keys_list = data.get('keys', [])

    if not dest_user:
        return jsonify({"error": "destination_user parameter is required."}), 400
    if not dest_host:
        return jsonify({"error": "destination_host parameter is required."}), 400
    if not keys_list:
        return jsonify({"error": "No keys selected for validation."}), 400

    hosts_list = parse_inventory(INVENTORY_PATH)["all_hosts"]
    target_hosts = [h["name"] for h in hosts_list] if dest_host == "all" else [h.strip() for h in dest_host.split(",")]

    conn = get_db_connection()
    cursor = conn.cursor()

    validation_results = []
    eligible_count = 0
    duplicate_count = 0

    for item in keys_list:
        raw_k = item.get('raw_key', '').strip()
        if not raw_k:
            continue

        parts = raw_k.split()
        target_body = parts[1] if len(parts) >= 2 else raw_k
        comment = item.get('comment') or (" ".join(parts[2:]) if len(parts) >= 3 else "SSH Key")
        fingerprint = item.get('fingerprint') or compute_ssh_fingerprint(raw_k)
        algo = item.get('algorithm') or (parts[0] if parts else 'ssh-rsa')

        existing_hosts = []
        for h in target_hosts:
            cursor.execute("SELECT keys_text FROM access_cache WHERE host=%s AND user=%s", (h, dest_user))
            row = cursor.fetchone()
            kt = row["keys_text"] if row and row.get("keys_text") else ""
            if kt:
                for l in kt.splitlines():
                    l_parts = l.strip().split()
                    if len(l_parts) >= 2 and l_parts[1] == target_body:
                        existing_hosts.append(h)
                        break

        if len(existing_hosts) == len(target_hosts):
            status = "already_exists"
            duplicate_count += 1
            status_msg = f"Key already installed on {', '.join(existing_hosts)} for user '{dest_user}'."
        elif existing_hosts:
            status = "partial_new"
            eligible_count += 1
            status_msg = f"Already on {', '.join(existing_hosts)}. Will deploy to remaining hosts."
        else:
            status = "new"
            eligible_count += 1
            status_msg = f"Ready to share to {', '.join(target_hosts)} for user '{dest_user}'."

        validation_results.append({
            "raw_key": raw_k,
            "algorithm": algo,
            "comment": comment,
            "fingerprint": fingerprint,
            "status": status,
            "status_message": status_msg,
            "existing_hosts": existing_hosts,
            "deploy_hosts": [h for h in target_hosts if h not in existing_hosts]
        })

    conn.close()

    return jsonify({
        "destination_host": dest_host,
        "destination_user": dest_user,
        "eligible_count": eligible_count,
        "duplicate_count": duplicate_count,
        "validation_results": validation_results
    })

@app.route('/api/keys/share_execute', methods=['POST'])
@require_perm('write:keys')
def share_execute_keys():
    data = request.json or {}
    source_host = data.get('source_host', '').strip()
    source_user = data.get('source_user', '').strip()
    dest_host = data.get('destination_host', '').strip()
    dest_user = data.get('destination_user', '').strip()
    keys_to_share = data.get('eligible_keys', [])
    operator_name = data.get('operator_name', 'Admin').strip() or 'Admin'

    if not dest_user:
        return jsonify({"error": "Destination user is required."}), 400
    if not dest_host:
        return jsonify({"error": "Destination host is required."}), 400
    if not keys_to_share:
        return jsonify({"error": "No eligible keys to share."}), 400

    hosts_list = parse_inventory(INVENTORY_PATH)["all_hosts"]
    target_hosts_pattern = ",".join([h["name"] for h in hosts_list]) if dest_host == "all" else dest_host

    combined_ssh_keys = "\n".join([k.strip() for k in keys_to_share if k.strip()])
    first_key = keys_to_share[0]
    fingerprint = compute_ssh_fingerprint(first_key)
    job_id = str(uuid.uuid4())[:8]

    extra_vars = {
        "target_user": dest_user,
        "ssh_key": combined_ssh_keys,
        "key_state": "present",
        "key_comment": "",
        "target_hosts": target_hosts_pattern
    }

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        MANAGE_PLAYBOOK,
        "--extra-vars", json.dumps(extra_vars),
        "--limit", target_hosts_pattern
    ]

    comment_summary = f"Shared {len(keys_to_share)} key(s) from {source_user}@{source_host}"

    thread = threading.Thread(
        target=run_ansible_playbook,
        args=(job_id, cmd, "GRANT_ACCESS_CLONE", dest_user, target_hosts_pattern, comment_summary, operator_name, fingerprint, "Permanent", combined_ssh_keys)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "status": "success",
        "job_id": job_id,
        "message": f"Sharing {len(keys_to_share)} key(s) to '{dest_user}' on {target_hosts_pattern}...",
        "target_user": dest_user,
        "target_hosts": target_hosts_pattern
    })

def format_dt(val):
    """Format datetime objects or strings into clean YYYY-MM-DD HH:MM:SS format."""
    if not val:
        return "Never"
    if isinstance(val, (datetime, date)):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    val_str = str(val).strip()
    if val_str.startswith("%Y") or not val_str or val_str.lower() in ("none", "null"):
        return "Just now"
    return val_str

def add_servers_to_inventory(servers_data, default_group="web_servers"):
    if not os.path.exists(INVENTORY_PATH):
        with open(INVENTORY_PATH, "w") as f:
            f.write(f"[{default_group}]\n")

    with open(INVENTORY_PATH, "r") as f:
        content = f.read()

    lines = content.splitlines()
    existing_parsed = parse_inventory(INVENTORY_PATH)
    existing_names = {h["name"] for h in existing_parsed["all_hosts"]}

    new_added = []
    grouped = {}

    for item in servers_data:
        if isinstance(item, dict):
            name = item.get("name", "").strip()
            ip = item.get("ip", "").strip()
            group = item.get("group", "").strip() or default_group
            if not name or name in existing_names:
                continue
            line_str = f"{name} ansible_host={ip}" if ip else name
        elif isinstance(item, str):
            line_clean = item.strip()
            if not line_clean or line_clean.startswith('#') or line_clean.startswith('['):
                continue
            parts = line_clean.split()
            name = parts[0]
            if name in existing_names:
                continue
            line_str = line_clean
            group = default_group
        else:
            continue

        existing_names.add(name)
        new_added.append(name)
        if group not in grouped:
            grouped[group] = []
        grouped[group].append(line_str)

    if not new_added:
        return new_added

    new_content_lines = []
    written_groups = set()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            grp = stripped[1:-1].split(":")[0]
            written_groups.add(grp)
            new_content_lines.append(line)
            if grp in grouped:
                for new_line in grouped[grp]:
                    new_content_lines.append(new_line)
                del grouped[grp]
        else:
            new_content_lines.append(line)

    for grp, grp_lines in grouped.items():
        new_content_lines.append(f"\n[{grp}]")
        new_content_lines.extend(grp_lines)

    with open(INVENTORY_PATH, "w") as f:
        f.write("\n".join(new_content_lines) + "\n")

    return new_added

def remove_server_from_inventory(host_name):
    if not os.path.exists(INVENTORY_PATH):
        return False
    with open(INVENTORY_PATH, "r") as f:
        lines = f.readlines()
    
    new_lines = []
    removed = False
    for line in lines:
        parts = line.strip().split()
        if parts and parts[0] == host_name:
            removed = True
            continue
        new_lines.append(line)

    if removed:
        with open(INVENTORY_PATH, "w") as f:
            f.writelines(new_lines)
    return removed

@app.route('/api/servers/add', methods=['POST'])
@require_perm('manage:servers')
def add_servers():
    data = request.json or {}
    servers = data.get('servers', [])
    bulk_text = data.get('bulk_text', '').strip()
    group = data.get('group', 'web_servers').strip() or 'web_servers'

    servers_to_add = []
    if bulk_text:
        for line in bulk_text.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('['):
                servers_to_add.append(line)
    elif servers:
        for s in servers:
            if isinstance(s, dict) and s.get('name'):
                servers_to_add.append(s)
            elif isinstance(s, str) and s.strip():
                servers_to_add.append(s.strip())

    if not servers_to_add:
        return jsonify({"error": "No valid server data provided."}), 400

    added_hosts = add_servers_to_inventory(servers_to_add, default_group=group)

    if not added_hosts:
        return jsonify({"status": "warning", "message": "Server(s) already exist in inventory.ini or no new host was added.", "inventory": parse_inventory(INVENTORY_PATH)}), 200

    for h in added_hosts:
        update_access_cache(h, 'root', 0, status='none', keys_text='')

    return jsonify({
        "status": "success",
        "message": f"Successfully added {len(added_hosts)} server(s) ({', '.join(added_hosts)}) to inventory.ini!",
        "added_hosts": added_hosts,
        "inventory": parse_inventory(INVENTORY_PATH)
    })

def sync_inventory_to_server_metadata():
    try:
        inv = parse_inventory(INVENTORY_PATH)
        conn = get_db_connection()
        cursor = conn.cursor()
        for host_info in inv["all_hosts"]:
            name = host_info["name"]
            ip = host_info["ip"]
            grp = host_info["group"]
            cursor.execute('''
                INSERT INTO server_metadata (host, ip, group_name, environment, region, os_info, tags, owner, status, is_favorite, last_ping_at, last_synced_at)
                VALUES (%s, %s, %s, 'Production', 'us-east-1', 'Linux', 'web,production', 'DevOps Team', 'online', 0, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    ip = VALUES(ip),
                    group_name = VALUES(group_name)
            ''', (name, ip, grp))
        conn.close()
    except Exception as e:
        print(f"Notice sync_inventory_to_server_metadata: {e}")

@app.route('/api/servers/explorer', methods=['GET'])
@require_perm('read:keys')
def get_server_explorer():
    sync_inventory_to_server_metadata()
    
    q = request.args.get('q', '').strip()
    env = request.args.get('env', '').strip()
    region = request.args.get('region', '').strip()
    group = request.args.get('group', '').strip()
    status_filter = request.args.get('status', '').strip()
    favorites_only = request.args.get('favorites', 'false').lower() == 'true'

    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if q:
        q_wild = f"%{q}%"
        where_clauses.append("(host LIKE %s OR ip LIKE %s OR group_name LIKE %s OR owner LIKE %s OR tags LIKE %s)")
        params.extend([q_wild, q_wild, q_wild, q_wild, q_wild])

    if env and env.lower() != 'all':
        where_clauses.append("environment = %s")
        params.append(env)

    if region and region.lower() != 'all':
        where_clauses.append("region = %s")
        params.append(region)

    if group and group.lower() != 'all':
        where_clauses.append("group_name = %s")
        params.append(group)

    if status_filter and status_filter.lower() != 'all':
        where_clauses.append("status = %s")
        params.append(status_filter)

    if favorites_only:
        where_clauses.append("is_favorite = 1")

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cursor.execute(f"SELECT * FROM server_metadata{where_sql} ORDER BY is_favorite DESC, host ASC", params)
    servers = cursor.fetchall()

    for s in servers:
        s['last_ping_at'] = format_dt(s.get('last_ping_at'))
        s['last_synced_at'] = format_dt(s.get('last_synced_at'))

    cursor.execute("SELECT COUNT(*) as total, SUM(IF(status='online', 1, 0)) as online_cnt, SUM(IF(environment='Production', 1, 0)) as prod_cnt, SUM(IF(environment='Staging', 1, 0)) as staging_cnt, SUM(IF(environment='Development', 1, 0)) as dev_cnt, SUM(IF(environment='QA', 1, 0)) as qa_cnt FROM server_metadata")
    stats = cursor.fetchone() or {}

    conn.close()

    return jsonify({
        "servers": servers,
        "total_servers": stats.get('total', 0) or 0,
        "online_servers": stats.get('online_cnt', 0) or 0,
        "stats": {
            "production": stats.get('prod_cnt', 0) or 0,
            "staging": stats.get('staging_cnt', 0) or 0,
            "development": stats.get('dev_cnt', 0) or 0,
            "qa": stats.get('qa_cnt', 0) or 0
        }
    })

@app.route('/api/servers/metadata', methods=['POST'])
@require_perm('manage:servers')
def update_server_metadata():
    data = request.json or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({"error": "host parameter is required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    if 'is_favorite' in data:
        fav = 1 if data['is_favorite'] else 0
        cursor.execute("UPDATE server_metadata SET is_favorite = %s WHERE host = %s", (fav, host))

    if 'environment' in data:
        cursor.execute("UPDATE server_metadata SET environment = %s WHERE host = %s", (data['environment'], host))

    if 'region' in data:
        cursor.execute("UPDATE server_metadata SET region = %s WHERE host = %s", (data['region'], host))

    if 'owner' in data:
        cursor.execute("UPDATE server_metadata SET owner = %s WHERE host = %s", (data['owner'], host))

    if 'tags' in data:
        cursor.execute("UPDATE server_metadata SET tags = %s WHERE host = %s", (data['tags'], host))

    conn.close()
    return jsonify({"status": "success", "message": f"Updated metadata for server '{host}'."})

@app.route('/api/servers/ping_batch', methods=['POST'])
@require_perm('read:keys')
def ping_batch():
    data = request.json or {}
    hosts = data.get('hosts', [])
    if not hosts:
        inv = parse_inventory(INVENTORY_PATH)
        hosts = [h['name'] for h in inv['all_hosts']]

    ansible_cmd = os.path.join(BASE_DIR, "venv", "bin", "ansible") if os.path.exists(os.path.join(BASE_DIR, "venv", "bin", "ansible")) else "ansible"
    limit_pattern = ",".join(hosts)
    cmd = [ansible_cmd, limit_pattern, "-i", INVENTORY_PATH, "-m", "ping"]

    conn = get_db_connection()
    cursor = conn.cursor()

    results = {}
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=30)
        output = res.stdout

        for h in hosts:
            if f"{h} | SUCCESS" in output:
                status = "online"
            elif f"{h} | UNREACHABLE" in output or f"{h} | FAILED" in output:
                status = "offline"
            else:
                status = "online"
            results[h] = status
            cursor.execute("UPDATE server_metadata SET status = %s, last_ping_at = NOW() WHERE host = %s", (status, h))
        conn.close()
        return jsonify({"status": "completed", "results": results, "raw_output": output})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/servers/remove', methods=['POST'])
@require_perm('manage:servers')
def remove_server():
    data = request.json or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({"error": "host parameter is required."}), 400

    removed = remove_server_from_inventory(host)
    if removed:
        return jsonify({"status": "success", "message": f"Server '{host}' removed from inventory.ini.", "inventory": parse_inventory(INVENTORY_PATH)})
    else:
        return jsonify({"error": f"Server '{host}' not found in inventory.ini."}), 404

@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, duration, expires_at FROM job_history ORDER BY timestamp DESC LIMIT 100")
    jobs = cursor.fetchall()
    conn.close()
    for j in jobs:
        j['timestamp'] = format_dt(j.get('timestamp'))
    return jsonify(jobs)

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job_details(job_id):
    if job_id in JOB_LOGS:
        return jsonify({
            "id": job_id,
            "status": JOB_STATUS.get(job_id, "RUNNING"),
            "logs": "".join(JOB_LOGS[job_id])
        })

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, logs, duration, expires_at FROM job_history WHERE id = %s", (job_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        row['timestamp'] = format_dt(row.get('timestamp'))
        return jsonify(row)
    else:
        return jsonify({"error": "Job not found"}), 404

@app.route('/api/search/global', methods=['GET'])
def global_search():
    start_time = time.time()
    query = request.args.get('q', '').strip()
    host_filter = request.args.get('host', '').strip()
    user_filter = request.args.get('user', '').strip()
    algo_filter = request.args.get('algo', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
        
    try:
        per_page = min(100, max(5, int(request.args.get('per_page', 15))))
    except ValueError:
        per_page = 15

    sort_by = request.args.get('sort_by', 'user').strip()
    sort_dir = request.args.get('sort_dir', 'ASC').upper()
    if sort_dir not in ('ASC', 'DESC'):
        sort_dir = 'ASC'
    valid_sort_cols = {'user': 'user', 'host': 'host', 'algorithm': 'algorithm', 'fingerprint': 'fingerprint', 'last_synced_at': 'last_synced_at'}
    col_name = valid_sort_cols.get(sort_by, 'user')

    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if query:
        q_clean = query
        q_alt = query.replace(' ', '+')
        q1 = f"%{q_clean}%"
        q2 = f"%{q_alt}%"
        where_clauses.append("(user LIKE %s OR host LIKE %s OR fingerprint LIKE %s OR algorithm LIKE %s OR comment LIKE %s OR raw_key LIKE %s OR key_body LIKE %s OR raw_key LIKE %s OR key_body LIKE %s)")
        params.extend([q1, q1, q1, q1, q1, q1, q1, q2, q2])

    if host_filter and host_filter != 'all':
        where_clauses.append("host = %s")
        params.append(host_filter)

    if user_filter and user_filter != 'all':
        where_clauses.append("user = %s")
        params.append(user_filter)

    if algo_filter and algo_filter != 'all':
        where_clauses.append("LOWER(algorithm) LIKE %s")
        params.append(f"%{algo_filter.lower()}%")

    if status_filter and status_filter != 'all':
        if status_filter == 'duplicate':
            where_clauses.append("is_duplicate = 1")
        elif status_filter == 'active':
            where_clauses.append("status = 'active'")

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cursor.execute(f"SELECT COUNT(*) as cnt FROM ssh_key_cache{where_sql}", params)
    row_count = cursor.fetchone()
    total_matches = row_count['cnt'] if row_count else 0

    offset = (page - 1) * per_page
    cursor.execute(f"SELECT id, host, user, home_dir, algorithm, raw_key, fingerprint, comment, status, is_duplicate, last_synced_at FROM ssh_key_cache{where_sql} ORDER BY {col_name} {sort_dir} LIMIT %s OFFSET %s", params + [per_page, offset])
    rows = cursor.fetchall()

    user = get_current_user()
    user_perms = user.get('permissions', []) if user else []
    can_view_full = 'view:full_key' in user_perms

    results = []
    for r in rows:
        raw_k = r["raw_key"] if can_view_full else mask_ssh_key(r["raw_key"])
        results.append({
            "id": r["id"],
            "host": r["host"],
            "user": r["user"],
            "home_dir": r["home_dir"] or (f"/root" if r["user"] == 'root' else f"/home/{r['user']}"),
            "algorithm": r["algorithm"],
            "raw_key": raw_k,
            "fingerprint": r["fingerprint"],
            "comment": r["comment"],
            "status": "duplicate" if r["is_duplicate"] else r["status"],
            "is_duplicate": bool(r["is_duplicate"]),
            "last_synced_at": format_dt(r.get("last_synced_at")),
            "can_copy_full": can_view_full
        })

    cursor.execute("SELECT COUNT(DISTINCT host) as cnt FROM ssh_key_cache")
    total_hosts = cursor.fetchone()['cnt']
    cursor.execute("SELECT COUNT(DISTINCT user) as cnt FROM ssh_key_cache")
    total_users = cursor.fetchone()['cnt']
    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache")
    total_keys = cursor.fetchone()['cnt']
    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache WHERE is_duplicate = 1")
    total_duplicates = cursor.fetchone()['cnt']

    conn.close()

    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    pages_count = max(1, math.ceil(total_matches / per_page))

    return jsonify({
        "query": query,
        "page": page,
        "per_page": per_page,
        "total_matches": total_matches,
        "total_pages": pages_count,
        "elapsed_ms": elapsed_ms,
        "stats": {
            "total_hosts": total_hosts,
            "total_users": total_users,
            "total_keys": total_keys,
            "total_duplicates": total_duplicates
        },
        "results": results
    })

@app.route('/api/sync/status', methods=['GET'])
def sync_status():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT MAX(ended_at) as max_ended FROM sync_history WHERE status = 'SUCCESS'")
    row_sync = cursor.fetchone()
    last_global_sync = format_dt(row_sync['max_ended']) if row_sync else "Never"

    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache")
    total_keys = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(DISTINCT host) as cnt FROM ssh_key_cache")
    total_hosts = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(DISTINCT user) as cnt FROM ssh_key_cache")
    total_users = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache WHERE is_duplicate = 1")
    duplicate_keys = cursor.fetchone()['cnt']

    cursor.execute("SELECT id, job_id, sync_mode, target_hosts, operator_name, started_at, ended_at, status, servers_processed, users_scanned, keys_added, failures, execution_time_sec FROM sync_history ORDER BY id DESC LIMIT 10")
    history_rows = cursor.fetchall()
    conn.close()

    for h in history_rows:
        h['started_at'] = format_dt(h.get('started_at'))
        h['ended_at'] = format_dt(h.get('ended_at'))

    return jsonify({
        "last_global_sync": last_global_sync,
        "total_keys": total_keys,
        "total_hosts": total_hosts,
        "total_users": total_users,
        "duplicate_keys": duplicate_keys,
        "database_version": "MySQL Enterprise 8.0 (InnoDB)",
        "search_index_status": "ONLINE",
        "recent_history": history_rows
    })

@app.route('/api/sync/start', methods=['POST'])
@require_perm('trigger:sync')
def sync_start():
    data = request.json or {}
    sync_mode = data.get('sync_mode', 'full').strip()
    target_hosts = data.get('target_hosts', ['all'])
    operator_name = data.get('operator_name', 'Admin').strip() or 'Admin'

    target_hosts_pattern = ",".join(target_hosts) if isinstance(target_hosts, list) else target_hosts
    job_id = str(uuid.uuid4())[:8]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sync_history (job_id, sync_mode, target_hosts, operator_name, started_at, status)
        VALUES (%s, %s, %s, %s, NOW(), 'RUNNING')
    ''', (job_id, sync_mode, target_hosts_pattern, operator_name))
    conn.close()

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        FETCH_PLAYBOOK,
        "--extra-vars", json.dumps({"target_user": "all", "target_hosts": target_hosts_pattern})
    ]
    if target_hosts_pattern != 'all':
        cmd.extend(["--limit", target_hosts_pattern])

    thread = threading.Thread(
        target=run_sync_job_background,
        args=(job_id, cmd, sync_mode, target_hosts_pattern, operator_name)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "RUNNING",
        "sync_mode": sync_mode,
        "target_hosts": target_hosts_pattern,
        "message": f"Background synchronization started for {target_hosts_pattern}."
    })

def parse_ansible_play_recap(output_text):
    if not output_text:
        return {
            'total_hosts': 0, 'ok_hosts': 0, 'changed_hosts': 0,
            'unreachable_hosts': 0, 'failed_hosts': 0, 'skipped_hosts': 0,
            'final_status': 'FAILED', 'recap_summary': 'No execution logs'
        }

    recap_started = False
    recap_lines = []
    
    for line in output_text.splitlines():
        if 'PLAY RECAP' in line:
            recap_started = True
            continue
        if recap_started:
            if line.strip().startswith('PLAY [') or line.strip().startswith('TASK ['):
                recap_started = False
                continue
            if line.strip():
                recap_lines.append(line.strip())

    hosts_stat = {}
    recap_regex = re.compile(
        r'^(?P<host>[^\s:]+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)(?:\s+skipped=(?P<skipped>\d+))?'
    )

    for line in recap_lines:
        match = recap_regex.search(line)
        if match:
            h = match.group('host').strip()
            ok_cnt = int(match.group('ok'))
            chg_cnt = int(match.group('changed'))
            unreach_cnt = int(match.group('unreachable'))
            fail_cnt = int(match.group('failed'))
            skip_cnt = int(match.group('skipped') or 0)
            
            hosts_stat[h] = {
                'ok': ok_cnt,
                'changed': chg_cnt,
                'unreachable': unreach_cnt,
                'failed': fail_cnt,
                'skipped': skip_cnt
            }

    if not hosts_stat:
        if "UNREACHABLE!" in output_text or "FAILED!" in output_text or "fatal:" in output_text:
            return {
                'total_hosts': 0, 'ok_hosts': 0, 'changed_hosts': 0,
                'unreachable_hosts': 1, 'failed_hosts': 1, 'skipped_hosts': 0,
                'final_status': 'FAILED', 'recap_summary': 'Ansible execution failed before PLAY RECAP'
            }

    total_hosts = len(hosts_stat)
    ok_hosts = sum(1 for h, s in hosts_stat.items() if s['ok'] > 0 and s['unreachable'] == 0 and s['failed'] == 0)
    changed_hosts = sum(1 for h, s in hosts_stat.items() if s['changed'] > 0)
    unreachable_hosts = sum(1 for h, s in hosts_stat.items() if s['unreachable'] > 0)
    failed_hosts = sum(1 for h, s in hosts_stat.items() if s['failed'] > 0)
    skipped_hosts = sum(1 for h, s in hosts_stat.items() if s['skipped'] > 0)

    if total_hosts > 0 and unreachable_hosts == 0 and failed_hosts == 0:
        final_status = 'SUCCESS'
    elif ok_hosts > 0 and (unreachable_hosts > 0 or failed_hosts > 0):
        final_status = 'PARTIAL_SUCCESS'
    else:
        final_status = 'FAILED'

    summary_parts = []
    if unreachable_hosts > 0:
        unreach_hosts_names = [h for h, s in hosts_stat.items() if s['unreachable'] > 0]
        summary_parts.append(f"{unreachable_hosts} host(s) UNREACHABLE ({', '.join(unreach_hosts_names)})")
    if failed_hosts > 0:
        fail_hosts_names = [h for h, s in hosts_stat.items() if s['failed'] > 0]
        summary_parts.append(f"{failed_hosts} host(s) FAILED ({', '.join(fail_hosts_names)})")
    if ok_hosts > 0:
        summary_parts.append(f"{ok_hosts} host(s) SUCCESS")

    recap_summary = ", ".join(summary_parts) if summary_parts else ("All hosts completed successfully" if final_status == 'SUCCESS' else "Execution failed")

    return {
        'total_hosts': total_hosts,
        'ok_hosts': ok_hosts,
        'changed_hosts': changed_hosts,
        'unreachable_hosts': unreachable_hosts,
        'failed_hosts': failed_hosts,
        'skipped_hosts': skipped_hosts,
        'final_status': final_status,
        'recap_summary': recap_summary
    }

def run_sync_job_background(job_id, cmd, sync_mode, target_hosts_pattern, operator_name):
    start_t = time.time()
    JOB_STATUS[job_id] = "RUNNING"
    JOB_LOGS[job_id] = f"[{datetime.now().strftime('%H:%M:%S')}] Initiating background synchronization for {target_hosts_pattern}...\n"
    
    pre_snapshot_users = {}
    try:
        conn_pre = get_db_connection()
        cursor_pre = conn_pre.cursor()
        cursor_pre.execute("SELECT host, user, fingerprint, comment FROM ssh_key_cache")
        for r in cursor_pre.fetchall():
            key_id = (r['host'], r['user'])
            if key_id not in pre_snapshot_users:
                pre_snapshot_users[key_id] = set()
            pre_snapshot_users[key_id].add((r['fingerprint'], r['comment'] or ''))
        conn_pre.close()
    except Exception as pre_err:
        print(f"Notice pre-sync snapshot: {pre_err}")

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=180)
        output = res.stdout
        JOB_LOGS[job_id] = output
        
        users_scanned = set()
        keys_added = 0

        for line in output.splitlines():
            line = line.strip().strip('"').strip("'")
            if 'SSHKEYAUDIT|' in line:
                idx = line.index('SSHKEYAUDIT|')
                audit_line = line[idx:]
                parts = audit_line.split('|')
                p_data = dict(p.split('=', 1) for p in parts[1:] if '=' in p)
                
                h = p_data.get('host', '').strip()
                u = p_data.get('user', '').strip()
                c = int(p_data.get('keys_count', 0)) if p_data.get('keys_count', '').isdigit() else 0
                status = p_data.get('status', 'active' if c > 0 else 'none').strip()
                keys_b64 = p_data.get('keys_b64', '').strip()
                keys_text = safe_b64decode(keys_b64)

                if h and u:
                    users_scanned.add(u)
                    update_access_cache(h, u, c, status=status, keys_text=keys_text)
                    
                    parsed = parse_authorized_keys_text(keys_text)
                    home_dir = "/root" if u == 'root' else f"/home/{u}"
                    
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    for k in parsed:
                        rk = k.get('raw_key', '').strip()
                        if not rk: continue
                        kparts = rk.split()
                        kbody = kparts[1] if len(kparts) >= 2 else rk
                        algo = k.get('algorithm') or (kparts[0] if kparts else 'ssh-rsa')
                        fp = k.get('fingerprint') or compute_ssh_fingerprint(rk)
                        cmt = k.get('comment') or (" ".join(kparts[2:]) if len(kparts) >= 3 else "")

                        cursor.execute('''
                            INSERT INTO ssh_key_cache (host, user, home_dir, algorithm, key_body, raw_key, fingerprint, comment, status, last_synced_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', NOW())
                            ON DUPLICATE KEY UPDATE
                                algorithm=VALUES(algorithm),
                                key_body=VALUES(key_body),
                                raw_key=VALUES(raw_key),
                                comment=VALUES(comment),
                                status='active',
                                last_synced_at=NOW()
                        ''', (h, u, home_dir, algo, kbody, rk, fp, cmt))
                        keys_added += 1

                    conn.close()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE ssh_key_cache s
            SET is_duplicate = (
                SELECT IF(COUNT(DISTINCT CONCAT(k2.host, ':', k2.user)) > 1, 1, 0)
                FROM (SELECT host, user, fingerprint FROM ssh_key_cache) k2
                WHERE k2.fingerprint = s.fingerprint
            )
        ''')

        exec_time = round(time.time() - start_t, 2)
        
        log_file = os.path.join(LOGS_DIR, f"{job_id}.log")
        with open(log_file, "w") as f:
            f.write(output)

        recap_info = parse_ansible_play_recap(output)
        final_status = recap_info['final_status']
        recap_summary = recap_info['recap_summary']

        JOB_STATUS[job_id] = final_status

        cursor.execute('''
            UPDATE sync_history SET
                status = %s,
                ended_at = NOW(),
                servers_processed = %s,
                users_scanned = %s,
                keys_added = %s,
                failures = %s,
                execution_time_sec = %s
            WHERE job_id = %s
        ''', (final_status, recap_info['total_hosts'], len(users_scanned), keys_added, recap_summary if final_status != 'SUCCESS' else '', exec_time, job_id))
        
        cursor.execute('''
            INSERT INTO job_history (id, status, action, target_user, target_hosts, logs, operator_name, key_comment)
            VALUES (%s, %s, 'SYNC_KEY_CACHE', 'all', %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE status=VALUES(status)
        ''', (job_id, final_status, target_hosts_pattern, output, operator_name, f"Sync {final_status}: {recap_summary}"))

        # Post-Sync Change Tracking Diff Engine
        try:
            post_snapshot_users = {}
            cursor.execute("SELECT host, user, fingerprint, comment FROM ssh_key_cache")
            for r in cursor.fetchall():
                key_id = (r['host'], r['user'])
                if key_id not in post_snapshot_users:
                    post_snapshot_users[key_id] = set()
                post_snapshot_users[key_id].add((r['fingerprint'], r['comment'] or ''))

            # Detect New Users
            for (h, u) in post_snapshot_users.keys():
                if (h, u) not in pre_snapshot_users:
                    cursor.execute('''
                        INSERT INTO sync_change_log (job_id, operator_name, host, user, change_type, previous_value, new_value, description)
                        VALUES (%s, %s, %s, %s, 'NEW_USER', 'None', %s, %s)
                    ''', (job_id, operator_name, h, u, f"User {u}", f"Discovered new Linux user account '{u}' on server '{h}'"))

            # Detect Removed Users
            for (h, u) in pre_snapshot_users.keys():
                if (h, u) not in post_snapshot_users:
                    cursor.execute('''
                        INSERT INTO sync_change_log (job_id, operator_name, host, user, change_type, previous_value, new_value, description)
                        VALUES (%s, %s, %s, %s, 'USER_REMOVED', %s, 'None', %s)
                    ''', (job_id, operator_name, h, u, f"User {u}", f"User account '{u}' removed from server '{h}'"))

            # Detect Key Additions
            for (h, u), post_keys in post_snapshot_users.items():
                pre_keys = pre_snapshot_users.get((h, u), set())
                added_keys = post_keys - pre_keys
                for fp, cmt in added_keys:
                    cursor.execute('''
                        INSERT INTO sync_change_log (job_id, operator_name, host, user, change_type, previous_value, new_value, description)
                        VALUES (%s, %s, %s, %s, 'KEY_ADDED', 'None', %s, %s)
                    ''', (job_id, operator_name, h, u, f"Key ({cmt or fp})", f"Authorized new SSH key ('{cmt or fp}') for user '{u}' on '{h}'"))

            # Detect Unreachable Hosts
            if 'UNREACHABLE' in recap_summary:
                for line in output.splitlines():
                    if 'UNREACHABLE!' in line:
                        parts = line.split(']')
                        unreach_h = parts[0].split('[')[-1].strip() if len(parts) >= 2 else 'Unknown'
                        cursor.execute('''
                            INSERT INTO sync_change_log (job_id, operator_name, host, user, change_type, previous_value, new_value, description)
                            VALUES (%s, %s, %s, 'system', 'SERVER_UNREACHABLE', 'ONLINE', 'UNREACHABLE', %s)
                        ''', (job_id, operator_name, unreach_h, f"Server '{unreach_h}' unreachable during SSH connection check"))

        except Exception as diff_err:
            print(f"Notice generating sync change diffs: {diff_err}")

        conn.close()

    except Exception as e:
        exec_time = round(time.time() - start_t, 2)
        err_msg = str(e)
        JOB_LOGS[job_id] = f"Error during sync: {err_msg}"
        JOB_STATUS[job_id] = "FAILED"
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sync_history SET
                    status = 'FAILED',
                    ended_at = NOW(),
                    failures = %s,
                    execution_time_sec = %s
                WHERE job_id = %s
            ''', (err_msg, exec_time, job_id))
            conn.close()
        except Exception:
            pass

@app.route('/api/keys/audit', methods=['POST'])
def audit_keys():
    data = request.json or {}
    target_user = data.get('target_user', 'developer').strip()
    target_hosts = data.get('target_hosts', ['all'])
    target_hosts_pattern = ",".join(target_hosts) if isinstance(target_hosts, list) else target_hosts

    cmd = [
        ANSIBLE_BIN,
        "-i", INVENTORY_PATH,
        FETCH_PLAYBOOK,
        "--extra-vars", json.dumps({"target_user": target_user, "target_hosts": target_hosts_pattern})
    ]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=120)
        output = res.stdout
        host_map = {}
        for line in output.splitlines():
            line = line.strip().strip('"').strip("'")
            if 'SSHKEYAUDIT|' in line:
                idx = line.index('SSHKEYAUDIT|')
                audit_line = line[idx:]
                parts = audit_line.split('|')
                p_data = {}
                for p in parts[1:]:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        p_data[k.strip()] = v.strip()
                h = p_data.get('host', '').strip()
                u = p_data.get('user', '').strip()
                try:
                    c = int(p_data.get('keys_count', 0))
                except ValueError:
                    c = 0
                status = p_data.get('status', 'active' if c > 0 else 'none').strip()
                keys_b64 = p_data.get('keys_b64', '').strip()
                keys_text = safe_b64decode(keys_b64)

                if h and u:
                    host_map[h] = {"host": h, "user": u, "keys_count": c, "status": status, "keys_text": keys_text}
                    update_access_cache(h, u, c, status=status, keys_text=keys_text)
        audit_results = list(host_map.values())
        return jsonify({"target_user": target_user, "results": audit_results, "raw_output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Audit timed out after 120s."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/inspect', methods=['POST'])
def inspect_user_keys():
    data = request.json or {}
    host = data.get('host', '').strip()
    user = data.get('user', '').strip()
    live = data.get('live', False)

    if not user:
        return jsonify({"error": "user parameter is required."}), 400

    target_pattern = host if (host and host != 'all') else 'all'

    if live:
        cmd = [
            ANSIBLE_BIN,
            "-i", INVENTORY_PATH,
            FETCH_PLAYBOOK,
            "--extra-vars", json.dumps({"target_user": user, "target_hosts": target_pattern})
        ]
        if target_pattern != 'all':
            cmd.extend(["--limit", target_pattern])

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR, env=get_env(), timeout=30)
            host_map = {}
            for line in res.stdout.splitlines():
                line = line.strip().strip('"').strip("'")
                if 'SSHKEYAUDIT|' in line:
                    idx = line.index('SSHKEYAUDIT|')
                    audit_line = line[idx:]
                    parts = audit_line.split('|')
                    p_data = {}
                    for p in parts[1:]:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            p_data[k.strip()] = v.strip()
                    h = p_data.get('host', '').strip()
                    u = p_data.get('user', '').strip()
                    try:
                        c = int(p_data.get('keys_count', 0))
                    except ValueError:
                        c = 0
                    status = p_data.get('status', 'active' if c > 0 else 'none').strip()
                    keys_b64 = p_data.get('keys_b64', '').strip()
                    keys_text = safe_b64decode(keys_b64)

                    parsed_keys = parse_authorized_keys_text(keys_text)
                    final_count = len(parsed_keys) if parsed_keys else c

                    if h and u:
                        update_access_cache(h, u, final_count, status=status, keys_text=keys_text)
                        host_map[h] = {
                            "host": h,
                            "user": u,
                            "status": status,
                            "keys_count": final_count,
                            "keys_list": parsed_keys,
                            "keys_text": keys_text
                        }

            results = list(host_map.values())
            if results:
                return jsonify({"user": user, "inspect_results": results, "source": "live"})
        except Exception as e:
            print(f"[!] Error performing live inspect for user '{user}': {e}")

    # Fallback to DB cache if live scan unavailable
    conn = get_db_connection()
    cursor = conn.cursor()
    if host and host != 'all':
        cursor.execute("SELECT host, user, keys_count, status, keys_text FROM access_cache WHERE host=%s AND user=%s", (host, user))
    else:
        cursor.execute("SELECT host, user, keys_count, status, keys_text FROM access_cache WHERE user=%s", (user,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        kt = r["keys_text"] if r.get("keys_text") else ""
        parsed_keys = parse_authorized_keys_text(kt)
        results.append({
            "host": r["host"],
            "user": r["user"],
            "status": r["status"] if r.get("status") else "active",
            "keys_count": len(parsed_keys) if parsed_keys else r["keys_count"],
            "keys_list": parsed_keys,
            "keys_text": kt
        })

    curr_u = get_current_user()
    user_perms = curr_u.get('permissions', []) if curr_u else []
    can_view_full = 'view:full_key' in user_perms

    if not can_view_full:
        for r in results:
            if 'keys_list' in r:
                for k in r['keys_list']:
                    if 'raw_key' in k:
                        k['raw_key'] = mask_ssh_key(k['raw_key'])
            if 'keys_text' in r and r['keys_text']:
                r['keys_text'] = "\n".join([mask_ssh_key(line) for line in r['keys_text'].splitlines() if line.strip()])

    return jsonify({"user": user, "inspect_results": results, "source": "cache" if not live else "live", "can_copy_full": can_view_full})

@app.route('/api/sync/changes', methods=['GET'])
@require_perm('read:keys')
def get_sync_change_logs():
    job_id = request.args.get('job_id', '').strip()
    change_type = request.args.get('change_type', '').strip()
    host = request.args.get('host', '').strip()
    user = request.args.get('user', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if job_id:
        where_clauses.append("job_id = %s")
        params.append(job_id)

    if change_type and change_type.lower() != 'all':
        where_clauses.append("change_type = %s")
        params.append(change_type)

    if host and host.lower() != 'all':
        where_clauses.append("host = %s")
        params.append(host)

    if user and user.lower() != 'all':
        where_clauses.append("user = %s")
        params.append(user)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cursor.execute(f"SELECT id, job_id, timestamp, operator_name, host, user, change_type, previous_value, new_value, description FROM sync_change_log{where_sql} ORDER BY id DESC LIMIT 250", params)
    rows = cursor.fetchall()
    conn.close()

    for r in rows:
        r['timestamp'] = format_dt(r.get('timestamp'))

    return jsonify(rows)

@app.route('/api/keys/analyze_duplicates', methods=['POST', 'GET'])
@require_perm('read:keys')
def analyze_duplicate_keys():
    data = request.json if request.is_json else (request.args or {})
    query = data.get('query', '').strip()
    host_filter = data.get('host', '').strip()

    curr_u = get_current_user()
    user_perms = curr_u.get('permissions', []) if curr_u else []
    can_view_full = 'view:full_key' in user_perms

    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if query:
        q_clean = query
        q_alt = query.replace(' ', '+')
        q1 = f"%{q_clean}%"
        q2 = f"%{q_alt}%"
        where_clauses.append("(fingerprint LIKE %s OR raw_key LIKE %s OR comment LIKE %s OR user LIKE %s OR host LIKE %s OR key_body LIKE %s OR raw_key LIKE %s OR key_body LIKE %s)")
        params.extend([q1, q1, q1, q1, q1, q1, q2, q2])
    else:
        where_clauses.append("is_duplicate = 1")

    if host_filter and host_filter != 'all':
        where_clauses.append("host = %s")
        params.append(host_filter)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cursor.execute(f"SELECT fingerprint, COUNT(*) as cnt FROM ssh_key_cache{where_sql} GROUP BY fingerprint HAVING cnt > 1 ORDER BY cnt DESC", params)
    dup_fps = cursor.fetchall()

    duplicate_groups = []
    total_instances = 0

    for row in dup_fps:
        fp = row['fingerprint']
        cursor.execute("SELECT id, host, user, home_dir, algorithm, raw_key, fingerprint, comment, status, last_synced_at FROM ssh_key_cache WHERE fingerprint = %s ORDER BY host ASC, user ASC", (fp,))
        occurrences_rows = cursor.fetchall()
        
        if len(occurrences_rows) <= 1 and not query:
            continue

        total_instances += len(occurrences_rows)
        sample = occurrences_rows[0]
        
        raw_k = sample['raw_key'] if can_view_full else mask_ssh_key(sample['raw_key'])

        hosts_set = sorted(list(set(r['host'] for r in occurrences_rows)))
        users_set = sorted(list(set(r['user'] for r in occurrences_rows)))
        same_user = (len(users_set) == 1 and len(hosts_set) > 1)

        occurrences = []
        timestamps = []
        for r in occurrences_rows:
            if r.get('last_synced_at'):
                timestamps.append(r['last_synced_at'])
            occurrences.append({
                "host": r["host"],
                "user": r["user"],
                "home_dir": r["home_dir"] or (f"/root" if r["user"] == 'root' else f"/home/{r['user']}"),
                "status": r["status"],
                "last_synced_at": format_dt(r.get("last_synced_at"))
            })

        min_t = format_dt(min(timestamps)) if timestamps else "Unknown"
        max_t = format_dt(max(timestamps)) if timestamps else "Unknown"

        duplicate_groups.append({
            "fingerprint": fp,
            "algorithm": sample["algorithm"],
            "comment": sample["comment"] or "Authorized Key",
            "raw_key": raw_k,
            "total_matches": len(occurrences_rows),
            "affected_hosts": hosts_set,
            "affected_users": users_set,
            "same_user_across_hosts": same_user,
            "first_detected": min_t,
            "last_synced": max_t,
            "occurrences": occurrences,
            "can_copy_full": can_view_full
        })

    conn.close()

    return jsonify({
        "query": query,
        "total_duplicate_groups": len(duplicate_groups),
        "total_duplicate_instances": total_instances,
        "duplicate_groups": duplicate_groups
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print(f"Starting SSH Key Manager Web Service on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
