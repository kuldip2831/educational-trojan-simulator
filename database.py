from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error

from config import Config, db_config


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('student', 'instructor') NOT NULL DEFAULT 'student',
        totp_secret VARCHAR(64) NOT NULL,
        two_factor_enabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS simulations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        simulation_type VARCHAR(80) NOT NULL,
        status VARCHAR(40) NOT NULL,
        snapshot_json JSON NULL,
        persistence_json JSON NULL,
        kill_switch_active BOOLEAN DEFAULT FALSE,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        completed_at DATETIME NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        action VARCHAR(120) NOT NULL,
        target VARCHAR(255) NOT NULL,
        status VARCHAR(60) NOT NULL,
        detection_result VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        event_type VARCHAR(120) NOT NULL,
        description TEXT NOT NULL,
        severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
        resource VARCHAR(255) NOT NULL,
        decision VARCHAR(40) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS learning_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        simulation VARCHAR(120) NOT NULL,
        completed BOOLEAN DEFAULT FALSE,
        threat_detected BOOLEAN DEFAULT FALSE,
        rollback_completed BOOLEAN DEFAULT FALSE,
        score INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_chain (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp VARCHAR(40) NOT NULL,
        user_label VARCHAR(255) NOT NULL,
        action VARCHAR(120) NOT NULL,
        resource VARCHAR(255) NOT NULL,
        status VARCHAR(60) NOT NULL,
        previous_hash CHAR(64) NOT NULL,
        current_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        ip_address VARCHAR(80) NOT NULL,
        success BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
]

ALTERATIONS = [
    (
        "users",
        "two_factor_enabled",
        "ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE AFTER totp_secret",
    ),
]


def init_db():
    Config.SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        server = mysql.connector.connect(**db_config(include_database=False))
        cur = server.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{Config.DB_NAME}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cur.close()
        server.close()

        conn = mysql.connector.connect(**db_config())
        cur = conn.cursor()
        for statement in SCHEMA:
            cur.execute(statement)
        for table, column, statement in ALTERATIONS:
            cur.execute(
                """
                SELECT COUNT(*) AS count
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
                """,
                (Config.DB_NAME, table, column),
            )
            exists = cur.fetchone()[0]
            if not exists:
                cur.execute(statement)
        conn.commit()
        cur.close()
        conn.close()
    except Error as exc:
        raise RuntimeError(f"MySQL initialization failed: {exc}") from exc


@contextmanager
def get_db(dictionary=True):
    conn = mysql.connector.connect(**db_config())
    cur = conn.cursor(dictionary=dictionary)
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def fetch_one(query, params=()):
    with get_db() as cur:
        cur.execute(query, params)
        return cur.fetchone()


def fetch_all(query, params=()):
    with get_db() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def execute(query, params=()):
    with get_db() as cur:
        cur.execute(query, params)
        return cur.lastrowid
