-- ============================================================
-- ThreatGate — Shared MySQL Schema Contract
-- Owned jointly by Track A, B, and C. Do not rename columns
-- without telling the other two owners — everything downstream
-- (proxy logging, socket payloads, dashboard queries) depends
-- on these exact names.
-- ============================================================

CREATE DATABASE IF NOT EXISTS threatgate
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE threatgate;

-- ------------------------------------------------------------
-- orgs — a tenant boundary. Every user, rule, and log belongs
-- to exactly one org. Track C scopes dashboard queries by org_id
-- pulled from the JWT so one customer never sees another's data.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS orgs (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- users — auth + role. role is an ENUM on purpose (not a free
-- text field) so the middleware role check is a cheap equality,
-- not a string-matching guessing game.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  org_id        INT NOT NULL,
  email         VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,   -- bcrypt hash, ~60 chars
  role          ENUM('admin', 'viewer') NOT NULL DEFAULT 'viewer',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_users_org FOREIGN KEY (org_id) REFERENCES orgs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- rules — the "rules-as-data" engine Track A reads from instead
-- of hardcoded regex. pattern is the regex; weight is how much
-- risk score it adds when it matches; category groups rules for
-- the dashboard's attack-type chart.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  org_id      INT NOT NULL,
  category    ENUM('sqli', 'xss', 'path_traversal', 'other') NOT NULL,
  pattern     TEXT NOT NULL,
  weight      INT NOT NULL DEFAULT 10,
  is_active   BOOLEAN NOT NULL DEFAULT TRUE,
  description VARCHAR(255),
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_rules_org FOREIGN KEY (org_id) REFERENCES orgs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- attack_logs — one row per request decision (allowed OR
-- blocked — Track B logs every decision, not just blocks, so
-- the dashboard can show traffic volume, not just incidents).
-- This is the table Socket.io emits from on INSERT.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_logs (
  id           BIGINT AUTO_INCREMENT PRIMARY KEY,
  org_id       INT NOT NULL,
  ip_address   VARCHAR(45) NOT NULL,       -- IPv4 or IPv6
  method       VARCHAR(10) NOT NULL,
  path         VARCHAR(2048) NOT NULL,
  category     ENUM('sqli', 'xss', 'path_traversal', 'brute_force', 'none') NOT NULL,
  risk_score   INT NOT NULL DEFAULT 0,
  action       ENUM('allowed', 'blocked') NOT NULL,
  matched_rule_id INT NULL,
  user_agent   VARCHAR(512),
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_logs_org FOREIGN KEY (org_id) REFERENCES orgs(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_logs_rule FOREIGN KEY (matched_rule_id) REFERENCES rules(id)
    ON DELETE SET NULL,
  INDEX idx_logs_org_created (org_id, created_at),
  INDEX idx_logs_ip (ip_address)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- blocked_ips — Track B's brute-force/rate-limit output. expires_at
-- is what makes a block temporary; a NULL expires_at means a
-- permanent, manually-applied block from the admin dashboard.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_ips (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  org_id      INT NOT NULL,
  ip_address  VARCHAR(45) NOT NULL,
  reason      VARCHAR(255),
  blocked_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME NULL,
  CONSTRAINT fk_blocked_org FOREIGN KEY (org_id) REFERENCES orgs(id)
    ON DELETE CASCADE,
  UNIQUE KEY uniq_org_ip (org_id, ip_address)
) ENGINE=InnoDB;
