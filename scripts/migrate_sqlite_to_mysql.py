#!/usr/bin/env python3
"""
SQLite to MySQL Migration Script for SSH Manager.
Migrates all existing records from jobs.db into MySQL 'Ansible' database.
"""
import os
import sys
import sqlite3
import pymysql
from pymysql.cursors import DictCursor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_DB = os.path.join(BASE_DIR, "jobs.db")

MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_USER = os.environ.get('MYSQL_USER', 'ansible_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'Ansible@123')
MYSQL_DB = os.environ.get('MYSQL_DB', 'Ansible')
MYSQL_SOCKET = os.environ.get('MYSQL_SOCKET', '')

def get_mysql_conn():
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

def migrate():
    if not os.path.exists(SQLITE_DB):
        print(f"No SQLite database found at {SQLITE_DB}. Skipping migration.")
        return

    print(f"Starting migration from SQLite ({SQLITE_DB}) -> MySQL ({MYSQL_DB})...")

    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_conn.row_factory = sqlite3.Row
    s_cur = sqlite_conn.cursor()

    mysql_conn = get_mysql_conn()
    m_cur = mysql_conn.cursor()

    # Create MySQL Tables First
    m_cur.execute('''
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

    m_cur.execute('''
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

    m_cur.execute('''
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

    m_cur.execute('''
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

    # 1. Migrate access_cache
    s_cur.execute("SELECT * FROM access_cache")
    rows = [dict(r) for r in s_cur.fetchall()]
    print(f"Migrating {len(rows)} records from access_cache...")
    for r in rows:
        m_cur.execute('''
            INSERT INTO access_cache (host, user, keys_count, has_access, status, keys_text, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                keys_count=VALUES(keys_count),
                has_access=VALUES(has_access),
                status=VALUES(status),
                keys_text=VALUES(keys_text),
                updated_at=VALUES(updated_at)
        ''', (r['host'], r['user'], r['keys_count'], r['has_access'], r.get('status', 'active'), r.get('keys_text', ''), r.get('updated_at')))

    # 2. Migrate ssh_key_cache
    try:
        s_cur.execute("SELECT * FROM ssh_key_cache")
        key_rows = [dict(r) for r in s_cur.fetchall()]
        print(f"Migrating {len(key_rows)} records from ssh_key_cache...")
        for r in key_rows:
            m_cur.execute('''
                INSERT INTO ssh_key_cache (host, user, home_dir, algorithm, key_body, raw_key, fingerprint, comment, status, is_duplicate, last_synced_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    algorithm=VALUES(algorithm),
                    key_body=VALUES(key_body),
                    raw_key=VALUES(raw_key),
                    comment=VALUES(comment),
                    status=VALUES(status),
                    is_duplicate=VALUES(is_duplicate),
                    last_synced_at=VALUES(last_synced_at)
            ''', (r['host'], r['user'], r['home_dir'], r['algorithm'], r['key_body'], r['raw_key'], r['fingerprint'], r['comment'], r['status'], r['is_duplicate'], r['last_synced_at']))
    except Exception as e:
        print(f"Notice during ssh_key_cache migration: {e}")

    # 3. Migrate sync_history
    try:
        s_cur.execute("SELECT * FROM sync_history")
        sync_rows = [dict(r) for r in s_cur.fetchall()]
        print(f"Migrating {len(sync_rows)} records from sync_history...")
        for r in sync_rows:
            m_cur.execute('''
                INSERT INTO sync_history (job_id, sync_mode, target_hosts, operator_name, started_at, ended_at, status, servers_processed, users_scanned, keys_added, failures, execution_time_sec)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    status=VALUES(status),
                    ended_at=VALUES(ended_at),
                    execution_time_sec=VALUES(execution_time_sec)
            ''', (r['job_id'], r['sync_mode'], r['target_hosts'], r.get('operator_name', 'Admin'), r['started_at'], r.get('ended_at'), r['status'], r.get('servers_processed', 0), r.get('users_scanned', 0), r.get('keys_added', 0), r.get('failures', ''), r.get('execution_time_sec', 0.0)))
    except Exception as e:
        print(f"Notice during sync_history migration: {e}")

    # 4. Migrate job_history
    try:
        s_cur.execute("SELECT * FROM job_history")
        job_rows = [dict(r) for r in s_cur.fetchall()]
        print(f"Migrating {len(job_rows)} records from job_history...")
        for r in job_rows:
            m_cur.execute('''
                INSERT INTO job_history (id, timestamp, action, target_user, target_hosts, key_comment, status, logs, duration, operator_name, key_fingerprint, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    status=VALUES(status),
                    logs=VALUES(logs)
            ''', (r['id'], r.get('timestamp'), r.get('action'), r.get('target_user'), r.get('target_hosts'), r.get('key_comment'), r.get('status'), r.get('logs'), r.get('duration', 0.0), r.get('operator_name', 'Admin'), r.get('key_fingerprint', '--'), r.get('expires_at', 'Permanent')))
    except Exception as e:
        print(f"Notice during job_history migration: {e}")

    sqlite_conn.close()
    mysql_conn.close()
    print("Migration from SQLite to MySQL completed successfully!")

if __name__ == '__main__':
    migrate()
