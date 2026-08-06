-- ============================================================
-- Ansible SSH Manager — Production MySQL 8.0 Database Schema
-- Export Date: 6 August 2026
-- ============================================================

CREATE DATABASE IF NOT EXISTS `ansible_manager` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `ansible_manager`;

-- ------------------------------------------------------------
-- 1. Table: server_metadata
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `server_metadata` (
    `host` VARCHAR(100) NOT NULL,
    `ip` VARCHAR(45) NOT NULL,
    `group_name` VARCHAR(50) DEFAULT 'web_servers',
    `env` VARCHAR(20) DEFAULT 'Production',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`host`),
    KEY `idx_ip` (`ip`),
    KEY `idx_group` (`group_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 2. Table: access_cache
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `access_cache` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `host` VARCHAR(100) NOT NULL,
    `user` VARCHAR(100) NOT NULL,
    `keys_count` INT DEFAULT 0,
    `status` VARCHAR(20) DEFAULT 'active',
    `keys_text` TEXT,
    `last_synced_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uk_host_user` (`host`, `user`),
    KEY `idx_host` (`host`),
    KEY `idx_user` (`user`),
    KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 3. Table: ssh_key_cache
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `ssh_key_cache` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `host` VARCHAR(100) NOT NULL,
    `user` VARCHAR(100) NOT NULL,
    `fingerprint` VARCHAR(100) NOT NULL,
    `algorithm` VARCHAR(50) DEFAULT 'rsa',
    `comment` VARCHAR(255) DEFAULT '',
    `home_dir` VARCHAR(255) DEFAULT '',
    `status` VARCHAR(20) DEFAULT 'active',
    `public_key` TEXT NOT NULL,
    `last_synced_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uk_host_user_fp` (`host`, `user`, `fingerprint`),
    KEY `idx_fp` (`fingerprint`),
    KEY `idx_user_host` (`user`, `host`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 4. Table: job_history
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `job_history` (
    `job_id` VARCHAR(50) PRIMARY KEY,
    `mode` VARCHAR(50) NOT NULL,
    `target_hosts` TEXT NOT NULL,
    `target_user` VARCHAR(100) DEFAULT '',
    `operator` VARCHAR(100) DEFAULT 'system',
    `status` VARCHAR(20) DEFAULT 'RUNNING',
    `start_time` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `end_time` DATETIME DEFAULT NULL,
    `duration_seconds` FLOAT DEFAULT 0.0,
    `scanned_users_count` INT DEFAULT 0,
    `added_keys_count` INT DEFAULT 0,
    `removed_keys_count` INT DEFAULT 0,
    `error_message` TEXT DEFAULT NULL,
    `raw_log_path` VARCHAR(255) DEFAULT '',
    KEY `idx_start_time` (`start_time`),
    KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 5. Table: active_temp_keys
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `active_temp_keys` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `job_id` VARCHAR(50) NOT NULL,
    `target_hosts` TEXT NOT NULL,
    `target_user` VARCHAR(100) NOT NULL,
    `public_key` TEXT NOT NULL,
    `fingerprint` VARCHAR(100) DEFAULT '',
    `granted_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    `duration_minutes` INT NOT NULL,
    `revoked` TINYINT(1) DEFAULT 0,
    `revoked_at` DATETIME DEFAULT NULL,
    KEY `idx_expires_revoked` (`expires_at`, `revoked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 6. Table: sync_change_log
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `sync_change_log` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `job_id` VARCHAR(50) NOT NULL,
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `operator` VARCHAR(100) DEFAULT 'system',
    `host` VARCHAR(100) NOT NULL,
    `user` VARCHAR(100) NOT NULL,
    `event_type` VARCHAR(50) NOT NULL,
    `details` TEXT,
    KEY `idx_timestamp` (`timestamp`),
    KEY `idx_event` (`event_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- 7. RBAC Tables: roles, permissions, role_permissions, app_users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `roles` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(50) UNIQUE NOT NULL,
    `description` VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `permissions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(50) UNIQUE NOT NULL,
    `description` VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `role_permissions` (
    `role_id` INT NOT NULL,
    `perm_id` INT NOT NULL,
    PRIMARY KEY (`role_id`, `perm_id`),
    FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`perm_id`) REFERENCES `permissions`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `app_users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `full_name` VARCHAR(100),
    `email` VARCHAR(100),
    `role_id` INT NOT NULL,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_login_at` DATETIME DEFAULT NULL,
    FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- Initial RBAC Seed Data
-- ------------------------------------------------------------
INSERT INTO `roles` (`id`, `name`, `description`) VALUES
(1, 'Admin', 'Full System Administrator Access'),
(2, 'Developer', 'Read-Only & Search Access')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `permissions` (`id`, `name`, `description`) VALUES
(1, 'view:matrix', 'View Access Matrix & Search'),
(2, 'deploy:key', 'Deploy / Remove / Disable SSH Keys'),
(3, 'manage:servers', 'Add / Edit Managed Servers'),
(4, 'manage:users', 'Manage Dashboard User Accounts & Roles'),
(5, 'share:keys', 'Share SSH Keys Between Servers'),
(6, 'trigger:sync', 'Trigger Infrastructure Synchronization')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

-- Grant All Permissions to Admin Role (1)
INSERT INTO `role_permissions` (`role_id`, `perm_id`) VALUES
(1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6)
ON DUPLICATE KEY UPDATE `perm_id` = VALUES(`perm_id`);

-- Grant Read & View Permissions to Developer Role (2) - Restricted from trigger:sync
INSERT INTO `role_permissions` (`role_id`, `perm_id`) VALUES
(2, 1), (2, 5)
ON DUPLICATE KEY UPDATE `perm_id` = VALUES(`perm_id`);

-- Seed Default Admin User: admin / admin123 (PBKDF2-SHA256 Hash)
INSERT INTO `app_users` (`username`, `password_hash`, `full_name`, `email`, `role_id`, `is_active`) VALUES
('admin', 'pbkdf2:sha256:600000$tT1d5kM0Yw9q0pLz$49c5e53e4cf6b8f36c507c331a31b46a782b53c7adbbefc051a89c9c8bc84294', 'System Administrator', 'admin@example.com', 1, 1),
('dev', 'pbkdf2:sha256:600000$tT1d5kM0Yw9q0pLz$49c5e53e4cf6b8f36c507c331a31b46a782b53c7adbbefc051a89c9c8bc84294', 'Developer User', 'dev@example.com', 2, 1)
ON DUPLICATE KEY UPDATE `is_active` = VALUES(`is_active`);
