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
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, send_from_directory
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
CORS(app)

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

        conn.close()
    except Exception as e:
        print(f"Notice initializing MySQL database: {e}")

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
    env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
    env["PYTHONUNBUFFERED"] = "1"
    return env

def compute_ssh_fingerprint(key_str):
    if not key_str or not isinstance(key_str, str):
        return "N/A"
    parts = key_str.strip().split()
    if len(parts) < 2:
        return "N/A"
    try:
        raw_key = base64.b64decode(parts[1])
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

@app.route('/api/keys/deploy', methods=['POST'])
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

@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:%%i:%%s') as timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, duration, expires_at FROM job_history ORDER BY timestamp DESC LIMIT 100")
    jobs = cursor.fetchall()
    conn.close()
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
    cursor.execute("SELECT id, DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:%%i:%%s') as timestamp, action, target_user, target_hosts, key_comment, operator_name, key_fingerprint, status, logs, duration, expires_at FROM job_history WHERE id = %s", (job_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify(row)
    else:
        return jsonify({"error": "Job not found"}), 404

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
                    try:
                        keys_text = base64.b64decode(keys_b64).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        keys_text = ""

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
                        ssh_key = base64.b64decode(kb64).decode('utf-8', errors='ignore').strip()
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

@app.route('/api/keys/copy_cross_server', methods=['POST'])
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
    cursor.execute(f"SELECT id, host, user, home_dir, algorithm, raw_key, fingerprint, comment, status, is_duplicate, DATE_FORMAT(last_synced_at, '%%Y-%%m-%%d %%H:%%i:%%s') as last_synced_at FROM ssh_key_cache{where_sql} ORDER BY {col_name} {sort_dir} LIMIT %s OFFSET %s", params + [per_page, offset])
    rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "host": r["host"],
            "user": r["user"],
            "home_dir": r["home_dir"] or (f"/root" if r["user"] == 'root' else f"/home/{r['user']}"),
            "algorithm": r["algorithm"],
            "raw_key": r["raw_key"],
            "fingerprint": r["fingerprint"],
            "comment": r["comment"],
            "status": "duplicate" if r["is_duplicate"] else r["status"],
            "is_duplicate": bool(r["is_duplicate"]),
            "last_synced_at": str(r["last_synced_at"]) if r["last_synced_at"] else "Just now"
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

    cursor.execute("SELECT DATE_FORMAT(MAX(ended_at), '%%Y-%%m-%%d %%H:%%i:%%s') as max_ended FROM sync_history WHERE status = 'SUCCESS'")
    row_sync = cursor.fetchone()
    last_global_sync = str(row_sync['max_ended']) if row_sync and row_sync.get('max_ended') else "Never"

    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache")
    total_keys = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(DISTINCT host) as cnt FROM ssh_key_cache")
    total_hosts = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(DISTINCT user) as cnt FROM ssh_key_cache")
    total_users = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM ssh_key_cache WHERE is_duplicate = 1")
    duplicate_keys = cursor.fetchone()['cnt']

    cursor.execute("SELECT id, job_id, sync_mode, target_hosts, operator_name, DATE_FORMAT(started_at, '%%Y-%%m-%%d %%H:%%i:%%s') as started_at, DATE_FORMAT(ended_at, '%%Y-%%m-%%d %%H:%%i:%%s') as ended_at, status, servers_processed, users_scanned, keys_added, failures, execution_time_sec FROM sync_history ORDER BY id DESC LIMIT 10")
    history_rows = cursor.fetchall()

    conn.close()

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

def run_sync_job_background(job_id, cmd, sync_mode, target_hosts_pattern, operator_name):
    start_t = time.time()
    JOB_STATUS[job_id] = "RUNNING"
    JOB_LOGS[job_id] = f"[{datetime.now().strftime('%H:%M:%S')}] Initiating background synchronization for {target_hosts_pattern}...\n"
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
                keys_text = base64.b64decode(keys_b64).decode('utf-8', errors='ignore').strip() if keys_b64 else ""

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

        JOB_STATUS[job_id] = "SUCCESS"

        cursor.execute('''
            UPDATE sync_history SET
                status = 'SUCCESS',
                ended_at = NOW(),
                servers_processed = (SELECT COUNT(DISTINCT host) FROM ssh_key_cache),
                users_scanned = %s,
                keys_added = %s,
                execution_time_sec = %s
            WHERE job_id = %s
        ''', (len(users_scanned), keys_added, exec_time, job_id))
        
        cursor.execute('''
            INSERT INTO job_history (id, status, action, target_user, target_hosts, logs, operator_name, key_comment)
            VALUES (%s, 'SUCCESS', 'SYNC_KEY_CACHE', 'all', %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE status='SUCCESS'
        ''', (job_id, target_hosts_pattern, output, operator_name, f"Synced {keys_added} keys across {len(users_scanned)} users"))

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
                keys_text = ""
                if keys_b64:
                    try:
                        keys_text = base64.b64decode(keys_b64).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        keys_text = ""

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
                    keys_text = ""
                    if keys_b64:
                        try:
                            keys_text = base64.b64decode(keys_b64).decode('utf-8', errors='ignore').strip()
                        except Exception:
                            keys_text = ""

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

    return jsonify({"user": user, "inspect_results": results, "source": "cache"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print(f"Starting SSH Key Manager Web Service on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
