from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from uuid import uuid4
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import threading
import csv
import time
import ipaddress
from functools import wraps
import secrets
import sqlite3
import hashlib
import shutil
from datetime import timedelta
from collections import defaultdict
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# AI-NET : AI POWERED NETWORK INTRUSION DETECTION SYSTEM
# ============================================================

app = Flask(__name__)

# Project root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Day 46 — SQLite persistence foundation
DATABASE_PATH = os.path.join(BASE_DIR, "logs", "ai_net.db")

def get_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db()
    conn.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT,
        created_by TEXT, updated_at TEXT, updated_by TEXT
    );
    CREATE TABLE IF NOT EXISTS authentication_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        event TEXT NOT NULL, username TEXT, role TEXT, target TEXT,
        ip_address TEXT, details TEXT
    );
    CREATE TABLE IF NOT EXISTS soc_cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT UNIQUE NOT NULL,
        title TEXT, source_ip TEXT, priority TEXT, status TEXT, notes TEXT,
        created_at TEXT, updated_at TEXT, incident_id TEXT, created_by TEXT,
        assigned_to TEXT, sla_due_at TEXT
    );
    CREATE TABLE IF NOT EXISTS incident_response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, incident_id TEXT,
        source_ip TEXT, action TEXT, actor TEXT, details TEXT
    );
    CREATE TABLE IF NOT EXISTS security_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT UNIQUE NOT NULL,
        source_ip TEXT, level TEXT, attack_count INTEGER, total_flows INTEGER,
        attack_share REAL, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS ioc_watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT UNIQUE NOT NULL,
        ioc_type TEXT, notes TEXT, created_at TEXT, created_by TEXT
    );
    CREATE TABLE IF NOT EXISTS detection_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_hash TEXT UNIQUE NOT NULL,
        timestamp TEXT, source_ip TEXT, destination_ip TEXT, source_port TEXT,
        destination_port TEXT, protocol TEXT, flow_duration REAL, packets REAL,
        fwd_packets REAL, bwd_packets REAL, prediction TEXT, confidence REAL,
        source TEXT, ingested_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON detection_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_detection_prediction ON detection_events(prediction);
    CREATE INDEX IF NOT EXISTS idx_detection_source_ip ON detection_events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_detection_destination_ip ON detection_events(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_detection_protocol ON detection_events(protocol);
    CREATE INDEX IF NOT EXISTS idx_detection_ingested_at ON detection_events(ingested_at);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON authentication_audit(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_username ON authentication_audit(username);
    CREATE INDEX IF NOT EXISTS idx_cases_status ON soc_cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_priority ON soc_cases(priority);
    CREATE INDEX IF NOT EXISTS idx_cases_source_ip ON soc_cases(source_ip);
    CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON security_incidents(source_ip);
    CREATE INDEX IF NOT EXISTS idx_incidents_level ON security_incidents(level);
    CREATE INDEX IF NOT EXISTS idx_response_incident ON incident_response_actions(incident_id);
    CREATE INDEX IF NOT EXISTS idx_response_timestamp ON incident_response_actions(timestamp);
    CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_watchlist(ioc_type);
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            notification_key TEXT UNIQUE NOT NULL,
            incident_id TEXT, source_ip TEXT, severity TEXT,
            event_type TEXT NOT NULL, message TEXT NOT NULL,
            created_at TEXT NOT NULL, acknowledged_at TEXT,
            acknowledged_by TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_soc_notifications_created ON soc_notifications(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_soc_notifications_incident ON soc_notifications(incident_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_report_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            report_type TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            generated_by TEXT,
            posture TEXT,
            file_name TEXT,
            file_path TEXT,
            summary TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_archive_generated ON soc_report_archive(generated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_archive_type ON soc_report_archive(report_type)")
    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_publishing_policy (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        require_approval INTEGER NOT NULL DEFAULT 1,
        allow_admin_override INTEGER NOT NULL DEFAULT 1,
        require_published_for_delivery INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        updated_by TEXT
    );
    """)

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        approval_id TEXT UNIQUE NOT NULL,
        report_id TEXT NOT NULL,
        version_id TEXT,
        state TEXT NOT NULL,
        submitted_by TEXT,
        submitted_at TEXT,
        reviewed_by TEXT,
        reviewed_at TEXT,
        published_by TEXT,
        published_at TEXT,
        rejection_reason TEXT,
        approval_note TEXT,
        FOREIGN KEY(report_id) REFERENCES soc_report_archive(report_id)
    );
    CREATE INDEX IF NOT EXISTS idx_report_approvals_report
        ON soc_report_approvals(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_approvals_state
        ON soc_report_approvals(state);
    CREATE INDEX IF NOT EXISTS idx_report_approvals_updated
        ON soc_report_approvals(reviewed_at);
    """)
    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_approval_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        approval_id TEXT NOT NULL,
        report_id TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        actor TEXT,
        timestamp TEXT NOT NULL,
        note TEXT,
        FOREIGN KEY(approval_id) REFERENCES soc_report_approvals(approval_id)
    );
    CREATE INDEX IF NOT EXISTS idx_report_approval_history_approval
        ON soc_report_approval_history(approval_id);
    CREATE INDEX IF NOT EXISTS idx_report_approval_history_timestamp
        ON soc_report_approval_history(timestamp);
    """)


    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id TEXT UNIQUE NOT NULL,
        report_id TEXT NOT NULL,
        parent_report_id TEXT,
        version_number INTEGER NOT NULL,
        generated_at TEXT NOT NULL,
        generated_by TEXT,
        report_type TEXT,
        posture TEXT,
        file_name TEXT,
        sha256 TEXT,
        file_size INTEGER,
        change_summary TEXT,
        source_type TEXT,
        FOREIGN KEY(report_id) REFERENCES soc_report_archive(report_id)
    );
    CREATE INDEX IF NOT EXISTS idx_report_versions_report
        ON soc_report_versions(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_versions_parent
        ON soc_report_versions(parent_report_id);
    CREATE INDEX IF NOT EXISTS idx_report_versions_generated
        ON soc_report_versions(generated_at);
    """)

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_download_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT,
        username TEXT,
        role TEXT,
        timestamp TEXT NOT NULL,
        outcome TEXT NOT NULL,
        ip_address TEXT,
        file_name TEXT,
        sha256 TEXT,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_report_download_audit_report
        ON soc_report_download_audit(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_download_audit_timestamp
        ON soc_report_download_audit(timestamp);
    CREATE INDEX IF NOT EXISTS idx_report_download_audit_username
        ON soc_report_download_audit(username);
    """)


    # Day 48.13 — report integrity / retention metadata
    report_columns = {
        "sha256": "TEXT",
        "file_size": "INTEGER",
        "integrity_status": "TEXT",
        "retention_until": "TEXT",
        "verified_at": "TEXT"
    }
    existing_report_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(soc_report_archive)").fetchall()
    }
    for col_name, col_type in report_columns.items():
        if col_name not in existing_report_columns:
            conn.execute(
                f"ALTER TABLE soc_report_archive ADD COLUMN {col_name} {col_type}"
            )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_report_schedule (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            frequency TEXT NOT NULL DEFAULT 'DAILY',
            run_hour INTEGER NOT NULL DEFAULT 9,
            run_minute INTEGER NOT NULL DEFAULT 0,
            day_of_week INTEGER NOT NULL DEFAULT 0,
            last_run_at TEXT,
            updated_at TEXT,
            updated_by TEXT
        )
    """)
    conn.execute("""
        INSERT OR IGNORE INTO soc_report_schedule
        (id, enabled, frequency, run_hour, run_minute, day_of_week, updated_at, updated_by)
        VALUES (1, 0, 'DAILY', 9, 0, 0, ?, 'system')
    """, (datetime.now().isoformat(timespec='seconds'),))
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_schedule_enabled ON soc_report_schedule(enabled)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_notification_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            notification_id INTEGER, notification_key TEXT, incident_id TEXT,
            event TEXT NOT NULL, actor TEXT, timestamp TEXT NOT NULL, details TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notification_audit_timestamp ON soc_notification_audit(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notification_audit_notification ON soc_notification_audit(notification_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notification_audit_incident ON soc_notification_audit(incident_id)")

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        delivery_id TEXT UNIQUE NOT NULL,
        report_id TEXT NOT NULL,
        method TEXT NOT NULL,
        recipient TEXT NOT NULL,
        status TEXT NOT NULL,
        queued_at TEXT NOT NULL,
        sent_at TEXT,
        actor TEXT,
        error_message TEXT,
        notes TEXT,
        FOREIGN KEY(report_id) REFERENCES soc_report_archive(report_id)
    );
    CREATE INDEX IF NOT EXISTS idx_report_delivery_report
        ON soc_report_delivery(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_delivery_status
        ON soc_report_delivery(status);
    CREATE INDEX IF NOT EXISTS idx_report_delivery_queued
        ON soc_report_delivery(queued_at);
    """)

    conn.execute("""
        INSERT OR IGNORE INTO soc_report_publishing_policy
        (id, require_approval, allow_admin_override,
         require_published_for_delivery, updated_at, updated_by)
        VALUES (1, 1, 1, 1, ?, ?)
    """, (datetime.now().isoformat(timespec="seconds"), "system"))

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_compliance_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id TEXT UNIQUE NOT NULL,
        report_id TEXT,
        event_type TEXT NOT NULL,
        actor TEXT,
        timestamp TEXT NOT NULL,
        outcome TEXT NOT NULL,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_report_compliance_report
        ON soc_report_compliance_audit(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_compliance_event
        ON soc_report_compliance_audit(event_type);
    CREATE INDEX IF NOT EXISTS idx_report_compliance_timestamp
        ON soc_report_compliance_audit(timestamp);
    """)

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_compliance_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT,
        report_count INTEGER NOT NULL DEFAULT 0,
        published_count INTEGER NOT NULL DEFAULT 0,
        verified_count INTEGER NOT NULL DEFAULT 0,
        critical_findings INTEGER NOT NULL DEFAULT 0,
        high_findings INTEGER NOT NULL DEFAULT 0,
        medium_findings INTEGER NOT NULL DEFAULT 0,
        summary TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_report_compliance_snapshots_created
        ON soc_report_compliance_snapshots(created_at);
    """)

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_governance_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        governance_id TEXT UNIQUE NOT NULL,
        report_id TEXT,
        check_type TEXT NOT NULL,
        status TEXT NOT NULL,
        severity TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        checked_by TEXT,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_report_governance_report
        ON soc_report_governance_audit(report_id);
    CREATE INDEX IF NOT EXISTS idx_report_governance_status
        ON soc_report_governance_audit(status);
    CREATE INDEX IF NOT EXISTS idx_report_governance_checked
        ON soc_report_governance_audit(checked_at);
    """)

    conn.executescript("""

    CREATE TABLE IF NOT EXISTS soc_report_governance_certifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        certification_id TEXT UNIQUE NOT NULL,
        report_id TEXT NOT NULL,
        governance_status TEXT NOT NULL,
        state TEXT NOT NULL,
        certified_by TEXT,
        certified_at TEXT,
        certification_note TEXT,
        rejection_reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_gov_cert_report
        ON soc_report_governance_certifications(report_id);
    CREATE INDEX IF NOT EXISTS idx_gov_cert_state
        ON soc_report_governance_certifications(state);

    CREATE TABLE IF NOT EXISTS soc_report_governance_cert_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        certification_id TEXT NOT NULL,
        report_id TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        actor TEXT,
        timestamp TEXT NOT NULL,
        note TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_gov_cert_history_report
        ON soc_report_governance_cert_history(report_id);
    """)

    conn.commit()
    conn.close()

init_database()

# ============================================================
# DAY 48.1 — PERSISTENT SOC INCIDENT LIFECYCLE
# ============================================================
def ensure_incident_lifecycle_schema():
    """Add lifecycle fields to existing security_incidents safely."""
    conn = get_db()
    try:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(security_incidents)").fetchall()}
        additions = {
            "lifecycle_status": "TEXT DEFAULT 'OPEN'",
            "assigned_to": "TEXT",
            "resolution_note": "TEXT",
            "first_seen": "TEXT",
            "last_seen": "TEXT"
        }
        for column, definition in additions.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE security_incidents ADD COLUMN {column} {definition}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_lifecycle_status ON security_incidents(lifecycle_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON security_incidents(assigned_to)")
        conn.execute("UPDATE security_incidents SET lifecycle_status='OPEN' WHERE lifecycle_status IS NULL OR TRIM(lifecycle_status)=''")
        conn.commit()
    finally:
        conn.close()

ensure_incident_lifecycle_schema()


# ============================================================
# DAY 48.3 — INCIDENT SLA & ESCALATION ENGINE
# ============================================================
INCIDENT_SLA_HOURS = {
    "CRITICAL": 1,
    "HIGH": 4,
    "MEDIUM": 12,
    "LOW": 24,
}


def ensure_incident_sla_schema():
    """Add persistent SLA/escalation fields to existing incidents safely."""
    conn = get_db()
    try:
        existing = {row[1] for row in conn.execute(
            "PRAGMA table_info(security_incidents)"
        ).fetchall()}
        additions = {
            "sla_due_at": "TEXT",
            "sla_status": "TEXT DEFAULT 'ON_TRACK'",
            "escalation_level": "INTEGER DEFAULT 0",
            "escalated_at": "TEXT",
            "sla_acknowledged_at": "TEXT",
        }
        for column, definition in additions.items():
            if column not in existing:
                conn.execute(
                    f"ALTER TABLE security_incidents ADD COLUMN {column} {definition}"
                )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_sla_due "
            "ON security_incidents(sla_due_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_sla_status "
            "ON security_incidents(sla_status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_escalation "
            "ON security_incidents(escalation_level)"
        )
        conn.commit()
    finally:
        conn.close()


def _sla_hours_for_level(level):
    return INCIDENT_SLA_HOURS.get(str(level or "MEDIUM").upper(), 12)


def _parse_dt(value):
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", ""))
    except Exception:
        return None


def _sla_status(level, due_at, lifecycle_status):
    status = str(lifecycle_status or "OPEN").upper()
    if status in {"RESOLVED", "CLOSED"}:
        return "COMPLETED"
    due = _parse_dt(due_at)
    if due is None:
        return "NO_DEADLINE"
    now = datetime.now()
    remaining = (due - now).total_seconds()
    if remaining <= 0:
        return "OVERDUE"
    if remaining <= 15 * 60:
        return "AT_RISK"
    return "ON_TRACK"


def _ensure_incident_sla(conn, incident_id, level, first_seen=None):
    row = conn.execute(
        "SELECT sla_due_at FROM security_incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()
    if not row:
        return None
    if row["sla_due_at"]:
        return row["sla_due_at"]
    start = _parse_dt(first_seen) or datetime.now()
    due = start + timedelta(hours=_sla_hours_for_level(level))
    due_text = due.strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE security_incidents SET sla_due_at = ?, sla_status = ? WHERE incident_id = ?",
        (due_text, "ON_TRACK", incident_id)
    )
    return due_text


ensure_incident_sla_schema()

# ============================================================
# DAY 48.2 — INCIDENT LIFECYCLE HISTORY
# ============================================================
def init_incident_lifecycle_history():
    conn = get_db()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS incident_lifecycle_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL,
            assigned_to TEXT,
            resolution_note TEXT,
            actor TEXT,
            source_ip TEXT,
            FOREIGN KEY (incident_id) REFERENCES security_incidents(incident_id)
        );
        CREATE INDEX IF NOT EXISTS idx_lifecycle_history_incident
            ON incident_lifecycle_history(incident_id);
        CREATE INDEX IF NOT EXISTS idx_lifecycle_history_timestamp
            ON incident_lifecycle_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_lifecycle_history_actor
            ON incident_lifecycle_history(actor);
        """)
        conn.commit()
    finally:
        conn.close()

init_incident_lifecycle_history()

# Day 46.4 — Incident persistence helpers
def _db_has_rows(table_name):
    allowed = {"security_incidents", "incident_response_actions"}
    if table_name not in allowed:
        raise ValueError("Unsupported database table")
    conn = get_db()
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]) > 0
    finally:
        conn.close()

def _migrate_incident_csv_to_db():
    """One-time migration of legacy incident CSV files into SQLite."""
    conn = get_db()
    try:
        # Incident snapshots
        if not _db_has_rows("security_incidents") and os.path.exists(INCIDENT_LOG if "INCIDENT_LOG" in globals() else os.path.join(BASE_DIR, "logs", "security_incidents.csv")):
            path = INCIDENT_LOG if "INCIDENT_LOG" in globals() else os.path.join(BASE_DIR, "logs", "security_incidents.csv")
            df = pd.read_csv(path)
            df.columns = df.columns.astype(str).str.strip()
            for _, row in df.iterrows():
                conn.execute(
                    """INSERT OR IGNORE INTO security_incidents
                    (incident_id, source_ip, level, attack_count, total_flows, attack_share, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (str(row.get("Incident ID", "")), str(row.get("Source IP", "Unknown")),
                     str(row.get("Level", "MEDIUM")), int(float(row.get("DDoS Flows", 0) or 0)),
                     0, float(row.get("Attack Share (%)", 0) or 0),
                     str(row.get("Timestamp", "")), str(row.get("Timestamp", "")))
                )

        # Response actions
        response_path = INCIDENT_RESPONSE_LOG if "INCIDENT_RESPONSE_LOG" in globals() else os.path.join(BASE_DIR, "logs", "incident_response_actions.csv")
        if not _db_has_rows("incident_response_actions") and os.path.exists(response_path):
            df = pd.read_csv(response_path)
            df.columns = df.columns.astype(str).str.strip()
            for _, row in df.iterrows():
                conn.execute(
                    """INSERT INTO incident_response_actions
                    (timestamp, incident_id, source_ip, action, actor, details)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(row.get("Timestamp", "")), str(row.get("Incident ID", "")),
                     str(row.get("Source IP", "Unknown")), str(row.get("Action", "")),
                     str(row.get("Actor", "Legacy CSV")),
                     str(row.get("Details", row.get("Mode", "SIMULATION"))))
                )
        conn.commit()
    except Exception as error:
        conn.rollback()
        print("INCIDENT DATABASE MIGRATION WARNING:", str(error))
    finally:
        conn.close()

def save_incident_rows_to_db(incidents):
    conn = get_db()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for item in incidents:
            timestamp = item.get("timestamp") or now
            conn.execute(
                """INSERT INTO security_incidents
                (incident_id, source_ip, level, attack_count, total_flows, attack_share, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    source_ip=excluded.source_ip, level=excluded.level,
                    attack_count=excluded.attack_count, attack_share=excluded.attack_share,
                    updated_at=excluded.updated_at""",
                (item.get("incident_id", ""), item.get("source_ip", "Unknown"),
                 item.get("level", "MEDIUM"), int(item.get("ddos_flows", 0)), 0,
                 float(item.get("attack_share", 0)), timestamp, now)
            )
        conn.commit()
    finally:
        conn.close()

def get_incident_response_actions(limit=20):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT timestamp, incident_id, source_ip, action, actor, details "
            "FROM incident_response_actions ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

_migrate_incident_csv_to_db()

# ============================================================
# DAY 45 — AUTHENTICATION & SOC ROLES
# ============================================================
# Demo/local deployment authentication. Change this secret before
# any real deployment and never reuse the demo credentials.
# Security configuration
# Set AI_NET_SECRET_KEY in the environment for deployment.
# For local development, persist a generated secret so restarting Flask
# does not invalidate the login session.
LOCAL_SECRET_FILE = os.path.join(BASE_DIR, "logs", ".ai_net_secret")

def _load_or_create_local_secret():
    env_secret = os.environ.get("AI_NET_SECRET_KEY")
    if env_secret:
        return env_secret
    os.makedirs(os.path.dirname(LOCAL_SECRET_FILE), exist_ok=True)
    try:
        if os.path.exists(LOCAL_SECRET_FILE):
            value = Path(LOCAL_SECRET_FILE).read_text(encoding="utf-8").strip()
            if len(value) >= 32:
                return value
        value = secrets.token_hex(32)
        Path(LOCAL_SECRET_FILE).write_text(value, encoding="utf-8")
        try:
            os.chmod(LOCAL_SECRET_FILE, 0o600)
        except OSError:
            pass
        return value
    except Exception:
        # Last-resort local fallback. Production should always use AI_NET_SECRET_KEY.
        return secrets.token_hex(32)

app.config["SECRET_KEY"] = _load_or_create_local_secret()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("AI_NET_COOKIE_SECURE", "0") == "1"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

FAILED_LOGINS = defaultdict(list)
LOCKED_UNTIL = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

AUTH_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "users.json")
AUTH_AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "authentication_audit.csv")

DEFAULT_USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "analyst": {"password": "analyst123", "role": "SOC Analyst"},
    "viewer": {"password": "viewer123", "role": "Viewer"}
}


def _db_user_count():
    conn = get_db()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    finally:
        conn.close()

def _migrate_users_json_to_db():
    """One-time migration of the existing users.json into SQLite."""
    if _db_user_count() > 0:
        return

    source_users = {}
    if os.path.exists(AUTH_STORE):
        try:
            with open(AUTH_STORE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    source_users = loaded
        except Exception as error:
            print("USER JSON MIGRATION READ ERROR:", error)

    if not source_users:
        source_users = {
            username: {
                "password_hash": generate_password_hash(item["password"]),
                "role": item["role"]
            }
            for username, item in DEFAULT_USERS.items()
        }

    now = datetime.now().isoformat(timespec="seconds")
    conn = get_db()
    try:
        for username, item in source_users.items():
            conn.execute("""
                INSERT OR IGNORE INTO users
                (username, password_hash, role, created_at, created_by, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                item.get("password_hash", ""),
                item.get("role", "Viewer"),
                item.get("created_at", now),
                item.get("created_by", "migration"),
                item.get("updated_at"),
                item.get("updated_by")
            ))
        conn.commit()
        print(f"AUTH DATABASE: migrated {len(source_users)} user(s) from users.json")
    finally:
        conn.close()

def _migrate_auth_audit_csv_to_db():
    """One-time migration of the existing authentication audit CSV into SQLite."""
    conn = get_db()
    try:
        existing = int(conn.execute("SELECT COUNT(*) FROM authentication_audit").fetchone()[0])
        if existing > 0 or not os.path.exists(AUTH_AUDIT_LOG):
            return
        with open(AUTH_AUDIT_LOG, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            conn.execute("""
                INSERT INTO authentication_audit
                (timestamp, event, username, role, target, ip_address, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                row.get("Timestamp") or datetime.now().isoformat(timespec="seconds"),
                row.get("Event") or "UNKNOWN",
                row.get("Username") or "-",
                row.get("Role") or "-",
                row.get("Target") or "-",
                row.get("IP Address") or "-",
                row.get("Details") or "-"
            ))
        conn.commit()
        print(f"AUTH DATABASE: migrated {len(rows)} audit event(s) from authentication_audit.csv")
    except Exception as error:
        print("AUTH AUDIT CSV MIGRATION ERROR:", error)
    finally:
        conn.close()

def write_auth_audit(event, username="", role="", target="", details=""):
    """Write authentication/admin events to SQLite; retain CSV as a legacy mirror."""
    timestamp = datetime.now().isoformat(timespec="seconds")
    ip_address = request.remote_addr or "-"
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO authentication_audit
            (timestamp, event, username, role, target, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, event, username or "-", role or "-", target or "-", ip_address, details or "-"))
        conn.commit()
        conn.close()
    except Exception as error:
        print("AUTH DATABASE AUDIT WRITE ERROR:", error)

    # Keep the old CSV as a compatibility/export mirror during the migration phase.
    try:
        os.makedirs(os.path.dirname(AUTH_AUDIT_LOG), exist_ok=True)
        new_file = not os.path.exists(AUTH_AUDIT_LOG)
        with open(AUTH_AUDIT_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow(["Timestamp", "Event", "Username", "Role", "Target", "IP Address", "Details"])
            writer.writerow([timestamp, event, username or "-", role or "-", target or "-", ip_address, details or "-"])
    except Exception as error:
        print("AUTH AUDIT CSV WRITE ERROR:", error)


def load_users():
    """Load users from SQLite; migrate legacy JSON once if the table is empty."""
    _migrate_users_json_to_db()
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT username, password_hash, role, created_at, created_by, updated_at, updated_by
            FROM users ORDER BY username
        """).fetchall()
        return {
            row["username"]: {
                "password_hash": row["password_hash"],
                "role": row["role"],
                "created_at": row["created_at"],
                "created_by": row["created_by"],
                "updated_at": row["updated_at"],
                "updated_by": row["updated_by"]
            }
            for row in rows
        }
    finally:
        conn.close()

def save_users(users):
    """Persist the complete user dictionary to SQLite."""
    conn = get_db()
    try:
        conn.execute("BEGIN")
        existing = {row["username"]: dict(row) for row in conn.execute("SELECT * FROM users").fetchall()}
        incoming = set(users.keys())
        for username in set(existing) - incoming:
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
        for username, item in users.items():
            old = existing.get(username, {})
            conn.execute("""
                INSERT INTO users
                (username, password_hash, role, created_at, created_by, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash=excluded.password_hash,
                    role=excluded.role,
                    created_at=excluded.created_at,
                    created_by=excluded.created_by,
                    updated_at=excluded.updated_at,
                    updated_by=excluded.updated_by
            """, (
                username,
                item.get("password_hash", old.get("password_hash", "")),
                item.get("role", old.get("role", "Viewer")),
                item.get("created_at", old.get("created_at")),
                item.get("created_by", old.get("created_by")),
                item.get("updated_at", old.get("updated_at")),
                item.get("updated_by", old.get("updated_by"))
            ))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# Run one-time legacy migrations after the database and auth constants exist.
_migrate_users_json_to_db()
_migrate_auth_audit_csv_to_db()


def current_user():
    username = session.get("username")
    if not username:
        return None
    user = load_users().get(username)
    if not user:
        session.clear()
        return None
    return {"username": username, "role": user.get("role", "Viewer")}

def role_required(*roles):
    """Require one of the supplied SOC roles for an API endpoint."""
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({
                    "success": False,
                    "error": "Authentication required."
                }), 401
            if roles and user["role"] not in roles:
                return jsonify({
                    "success": False,
                    "error": "Insufficient role permissions.",
                    "required_roles": list(roles),
                    "current_role": user["role"]
                }), 403
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def viewer_read_only_guard():
    """Return a 403 response when a Viewer attempts a state-changing API action."""
    user = current_user()
    if not user:
        return jsonify({"success": False, "error": "Authentication required."}), 401
    if user["role"] == "Viewer":
        return jsonify({
            "success": False,
            "error": "Viewer role is read-only. This action requires SOC Analyst or Admin access.",
            "current_role": "Viewer",
            "required_roles": ["SOC Analyst", "Admin"]
        }), 403
    return None

@app.before_request
def protect_dashboard():
    public = {"login", "logout", "static"}
    if request.endpoint in public or request.path.startswith("/static/"):
        return None
    if current_user() is None:
        api_prefixes = (
            "/predict", "/live_capture/", "/monitor_status", "/recent_detections",
            "/security_alerts", "/detection_history", "/traffic_volume",
            "/threat_intelligence", "/attack_source_intelligence",
            "/source_investigation", "/incident_", "/soc_", "/ioc_",
            "/threat_hunt", "/mitre_attack", "/network_forensics",
            "/model_explainability", "/model_performance", "/attack_analytics",
            "/database/", "/auth/status", "/system/"
        )
        if request.path.startswith(api_prefixes) or request.method != "GET":
            return jsonify({"success": False, "error": "Authentication required."}), 401
        return redirect(url_for("login", next=request.path))
    return None

def _client_key(username):
    return f"{request.remote_addr or 'unknown'}:{username.lower()}"

def _login_locked(key):
    import time
    until = LOCKED_UNTIL.get(key, 0)
    if until > time.time():
        return True, int(until - time.time())
    LOCKED_UNTIL.pop(key, None)
    return False, 0

def _record_failed_login(key):
    import time
    now = time.time()
    FAILED_LOGINS[key] = [t for t in FAILED_LOGINS[key] if now - t < LOCKOUT_SECONDS]
    FAILED_LOGINS[key].append(now)
    if len(FAILED_LOGINS[key]) >= MAX_FAILED_ATTEMPTS:
        LOCKED_UNTIL[key] = now + LOCKOUT_SECONDS
        FAILED_LOGINS[key] = []

def _clear_login_failures(key):
    FAILED_LOGINS.pop(key, None)
    LOCKED_UNTIL.pop(key, None)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.endpoint in {"login", "logout"} or request.path.startswith("/auth/"):
        response.headers["Cache-Control"] = "no-store"
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Day 47.4 — Database consistency verification
def _legacy_count(path, prediction=None):
    if not os.path.exists(path):
        return None
    try:
        df = pd.read_csv(path)
        df.columns = df.columns.astype(str).str.strip()
        if prediction is None:
            return int(len(df))
        col = "AI-Net Prediction"
        if col not in df.columns:
            return None
        return int((df[col].astype(str).str.strip().str.upper() == prediction.upper()).sum())
    except Exception:
        return None


# ============================================================
# DAY 48.23 — FINAL PRODUCTION HARDENING & READINESS
# ============================================================

@app.after_request
def add_final_security_headers(response):
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.errorhandler(404)
def handle_not_found(error):
    if request.path.startswith("/api/") or request.path.startswith((
        "/predict", "/live_capture", "/soc_", "/incident_", "/database/",
        "/auth/", "/admin/", "/ioc_", "/threat_", "/model_", "/network_",
        "/mitre_", "/attack_", "/source_", "/notification_", "/system/"
    )):
        return jsonify({"status": "ERROR", "error": "Endpoint not found."}), 404
    return error


@app.errorhandler(413)
def handle_upload_too_large(error):
    return jsonify({
        "status": "ERROR",
        "error": "Uploaded file exceeds the configured size limit."
    }), 413


@app.errorhandler(500)
def handle_server_error(error):
    return jsonify({
        "status": "ERROR",
        "error": "Internal server error."
    }), 500


@app.route("/system/readiness", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def system_readiness():
    checks = {}

    try:
        conn = get_db()
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        required = [
            "users", "authentication_audit", "detection_events",
            "security_incidents", "incident_response_actions",
            "ioc_watchlist", "soc_cases", "soc_notifications",
            "soc_report_archive", "soc_report_versions",
            "soc_report_approvals", "soc_report_delivery",
            "soc_report_download_audit", "soc_report_compliance_audit",
            "soc_report_compliance_snapshots",
            "soc_report_governance_audit",
            "soc_report_governance_certifications",
            "soc_report_governance_cert_history"
        ]
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        checks["database_integrity"] = integrity == "ok"
        checks["required_tables"] = all(t in tables for t in required)
        checks["table_count"] = len(tables)

        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        detection_count = conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0]
        case_count = conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0]
        conn.close()

        checks["users"] = user_count
        checks["detections"] = detection_count
        checks["cases"] = case_count
    except Exception as exc:
        checks["database_integrity"] = False
        checks["required_tables"] = False
        checks["database_error"] = str(exc)

    # The application uses lowercase `model` and `scaler` variables.
    checks["model_loaded"] = model is not None
    checks["scaler_loaded"] = scaler is not None
    registered_routes = {rule.rule for rule in app.url_map.iter_rules()}
    checks["critical_routes"] = all(
        rule in registered_routes for rule in [
            "/login", "/predict", "/predict_csv",
            "/live_capture/start", "/live_capture/stop",
            "/soc_cases", "/incident_correlation",
            "/soc_executive_report", "/soc_report_compliance",
            "/soc_report_governance", "/soc_report_governance/certifications"
        ]
    )
    checks["configuration_secret"] = bool(app.config.get("SECRET_KEY"))
    checks["ready"] = all([
        checks.get("database_integrity", False),
        checks.get("required_tables", False),
        checks.get("model_loaded", False),
        checks.get("scaler_loaded", False),
        checks.get("critical_routes", False)
    ])

    return jsonify({
        "status": "READY" if checks["ready"] else "NOT_READY",
        "checks": checks,
        "production_note": (
            "Set AI_NET_SECRET_KEY and AI_NET_COOKIE_SECURE=1 before HTTPS deployment."
        )
    })


@app.route("/system/smoke_test", methods=["GET"])
@role_required("Admin", "SOC Analyst")
def system_smoke_test():
    routes = [
        "/auth/status",
        "/database/status",
        "/database/health",
        "/system/health",
        "/system/readiness",
        "/soc_report_compliance/health",
        "/soc_report_governance",
        "/soc_report_governance/certifications",
        "/soc_report_governance/certification_summary"
    ]
    available = {rule.rule for rule in app.url_map.iter_rules()}
    results = [
        {"endpoint": r, "registered": r in available}
        for r in routes
    ]
    passed = sum(x["registered"] for x in results)
    return jsonify({
        "status": "PASS" if passed == len(results) else "FAIL",
        "passed": passed,
        "total": len(results),
        "results": results,
        "tested_at": datetime.now().isoformat(timespec="seconds")
    })


@app.route("/database/consistency", methods=["GET"])
@role_required("Admin")
def database_consistency():
    conn = get_db()
    try:
        counts = {}
        for table in ["users", "authentication_audit", "soc_cases", "incident_response_actions", "security_incidents", "ioc_watchlist", "detection_events"]:
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        db_total = counts["detection_events"]
        live_path = os.path.join(BASE_DIR, "logs", "live_predictions.csv")
        csv_path = os.path.join(BASE_DIR, "logs", "csv_predictions.csv")
        return jsonify({
            "status": "OK",
            "database_detection_events": db_total,
            "legacy_live_rows": _legacy_count(live_path),
            "legacy_csv_rows": _legacy_count(csv_path),
            "tables": counts,
            "note": "SQLite is the primary persistence layer; legacy files are compatibility backups."
        })
    finally:
        conn.close()

@app.route("/database/status")
@role_required("Admin")
def database_status():
    conn = get_db()
    tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
    counts = {}
    for table in tables:
        if table == "sqlite_sequence":
            continue
        counts[table] = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    db_size = os.path.getsize(DATABASE_PATH) if os.path.exists(DATABASE_PATH) else 0
    required_tables = ["users", "authentication_audit", "soc_cases", "incident_response_actions", "security_incidents", "ioc_watchlist", "detection_events"]
    missing_tables = [name for name in required_tables if name not in tables]
    verified = (str(integrity).lower() == "ok" and not missing_tables)
    return jsonify({
        "database": DATABASE_PATH,
        "tables": tables,
        "counts": counts,
        "status": "verified" if verified else "attention_required",
        "integrity": integrity,
        "missing_tables": missing_tables,
        "database_size_bytes": db_size,
        "persistence_verified": verified,
        "detection_events": counts.get("detection_events", 0),
        "analytics_backend": "SQLite primary"
    })


# Day 47.6 — SQLite backup and recovery
BACKUP_DIR = os.path.join(BASE_DIR, "logs", "database_backups")


def create_database_backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"ai_net_{stamp}.db")
    source = sqlite3.connect(DATABASE_PATH)
    try:
        target = sqlite3.connect(backup_path)
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()
    return backup_path


def list_database_backups():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    items = []
    for name in os.listdir(BACKUP_DIR):
        if not name.startswith("ai_net_") or not name.endswith(".db"):
            continue
        path = os.path.join(BACKUP_DIR, name)
        if not os.path.isfile(path):
            continue
        items.append({
            "name": name,
            "size_bytes": os.path.getsize(path),
            "modified_at": datetime.fromtimestamp(os.path.getmtime(path)).isoformat(timespec="seconds")
        })
    items.sort(key=lambda x: x["modified_at"], reverse=True)
    return items


@app.route("/database/backups", methods=["GET"])
@role_required("Admin")
def database_backups():
    return jsonify({"status": "OK", "backup_directory": BACKUP_DIR, "backups": list_database_backups()})


@app.route("/database/backup", methods=["POST"])
@role_required("Admin")
def database_backup():
    try:
        path = create_database_backup()
        return jsonify({
            "status": "created",
            "name": os.path.basename(path),
            "size_bytes": os.path.getsize(path),
            "created_at": datetime.now().isoformat(timespec="seconds")
        })
    except Exception as exc:
        return jsonify({"error": f"Backup failed: {exc}"}), 500


@app.route("/database/restore", methods=["POST"])
@role_required("Admin")
def database_restore():
    payload = request.get_json(silent=True) or {}
    name = os.path.basename(str(payload.get("name", "")).strip())
    if not name or not name.startswith("ai_net_") or not name.endswith(".db"):
        return jsonify({"error": "Invalid backup name."}), 400
    backup_path = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(backup_path):
        return jsonify({"error": "Backup not found."}), 404

    # Validate the backup before replacing the live database.
    check = sqlite3.connect(backup_path)
    try:
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        if str(integrity).lower() != "ok":
            return jsonify({"error": f"Backup failed integrity check: {integrity}"}), 400
    finally:
        check.close()

    # Keep a safety snapshot of the current DB before restoration.
    try:
        safety_path = create_database_backup()
        source = sqlite3.connect(backup_path)
        try:
            target = sqlite3.connect(DATABASE_PATH)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        return jsonify({
            "status": "restored",
            "restored_from": name,
            "safety_backup": os.path.basename(safety_path),
            "restored_at": datetime.now().isoformat(timespec="seconds")
        })
    except Exception as exc:
        return jsonify({"error": f"Restore failed: {exc}"}), 500


@app.route("/system/health", methods=["GET"])
@role_required("Admin")
def system_health():
    """Administrative health check for model, database, and critical API routes."""
    conn = get_db()
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        db_tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        detection_count = int(
            conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0]
        )
        user_count = int(
            conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        )
    finally:
        conn.close()

    critical_routes = [
        "/", "/health", "/predict", "/predict_csv",
        "/recent_detections", "/security_alerts", "/detection_history",
        "/live_capture/start", "/live_capture/stop",
        "/live_capture/status", "/monitor_status",
        "/traffic_volume", "/threat_intelligence",
        "/attack_source_intelligence", "/source_investigation",
        "/incident_correlation", "/incident_response",
        "/incident_dashboard", "/incident_audit_log",
        "/soc_dashboard", "/attack_analytics",
        "/model_explainability", "/model_performance",
        "/threat_hunt", "/mitre_attack", "/network_forensics",
        "/ioc_management", "/soc_cases", "/case_evidence",
        "/generate_case_report"
    ]
    registered = {rule.rule for rule in app.url_map.iter_rules()}
    missing_routes = [route for route in critical_routes if route not in registered]
    required_tables = {
        "users", "authentication_audit", "soc_cases",
        "incident_response_actions", "security_incidents",
        "ioc_watchlist", "detection_events"
    }
    missing_tables = sorted(required_tables - db_tables)

    healthy = (
        model is not None
        and str(integrity).lower() == "ok"
        and not missing_tables
        and not missing_routes
    )

    return jsonify({
        "status": "healthy" if healthy else "attention_required",
        "model_loaded": model is not None,
        "model_type": type(model).__name__ if model is not None else None,
        "database_integrity": integrity,
        "database": "SQLite",
        "user_count": user_count,
        "detection_event_count": detection_count,
        "missing_tables": missing_tables,
        "missing_critical_routes": missing_routes,
        "timestamp": datetime.now().isoformat(timespec="seconds")
    })


@app.route("/database/health")
@role_required("Admin")
def database_health():
    conn = get_db()
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        index_rows = conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name").fetchall()
        indexes = [{"name": r["name"], "table": r["tbl_name"]} for r in index_rows]
        return jsonify({
            "status": "healthy" if str(integrity).lower() == "ok" else "attention_required",
            "integrity": integrity,
            "journal_mode": journal_mode,
            "index_count": len(indexes),
            "indexes": indexes,
            "query_optimization": "enabled",
            "single_source_of_truth": "SQLite"
        })
    finally:
        conn.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if current_user():
            return redirect(url_for("home"))
        return render_template("login.html")
    username = str(request.form.get("username", "")).strip().lower()
    password = str(request.form.get("password", ""))
    key = _client_key(username)

    locked, remaining = _login_locked(key)
    if locked:
        write_auth_audit("LOGIN_BLOCKED", username=username, details=f"Temporary lockout; retry in {remaining}s")
        return render_template("login.html", error=f"Too many failed attempts. Try again in about {max(1, remaining // 60 + 1)} minute(s)."), 429

    user = load_users().get(username)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        _record_failed_login(key)
        write_auth_audit("LOGIN_FAILED", username=username, details="Invalid username or password")
        return render_template("login.html", error="Invalid username or password."), 401

    _clear_login_failures(key)
    session.clear()
    session["username"] = username
    session["role"] = user.get("role", "Viewer")
    session.permanent = True
    write_auth_audit("LOGIN_SUCCESS", username=username, role=user.get("role", "Viewer"))
    next_url = request.form.get("next", "")
    if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
        next_url = url_for("home")
    return redirect(next_url)

@app.route("/logout")
def logout():
    user = current_user()
    if user:
        write_auth_audit("LOGOUT", username=user["username"], role=user["role"])
    session.clear()
    return redirect(url_for("login"))

@app.route("/auth/status")
def auth_status():
    user = current_user()
    return jsonify({"authenticated": bool(user), "user": user})

@app.context_processor
def inject_current_user():
    return {"current_user": current_user()}



# ============================================================
# DAY 45 STEP 3 — ADMIN USER MANAGEMENT
# ============================================================

ALLOWED_ROLES = {"Admin", "SOC Analyst", "Viewer"}


# NOTE: save_users() is intentionally not redefined here.
# The SQLite-backed implementation defined above is authoritative.

@app.route("/admin/users", methods=["GET", "POST"])
@role_required("Admin")
def admin_users():
    users = load_users()

    if request.method == "GET":
        safe_users = []
        for username, item in sorted(users.items()):
            safe_users.append({
                "username": username,
                "role": item.get("role", "Viewer")
            })
        return jsonify({"success": True, "users": safe_users})

    payload = request.get_json(silent=True) or request.form.to_dict()
    username = str(payload.get("username", "")).strip().lower()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "Viewer")).strip()

    if not username or len(username) < 3 or len(username) > 32:
        return jsonify({"success": False, "error": "Username must be 3–32 characters."}), 400
    if not username.replace("_", "").replace("-", "").isalnum():
        return jsonify({"success": False, "error": "Username may contain only letters, numbers, _ or -."}), 400
    if len(password) < 10:
        return jsonify({"success": False, "error": "Password must be at least 10 characters."}), 400
    if role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": "Invalid SOC role."}), 400
    if username in users:
        return jsonify({"success": False, "error": "Username already exists."}), 409

    users[username] = {
        "password_hash": generate_password_hash(password),
        "role": role,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "created_by": session.get("username", "admin")
    }
    save_users(users)
    write_auth_audit("USER_CREATED", username=session.get("username", "admin"), role="Admin", target=username, details=f"Created as {role}")

    return jsonify({
        "success": True,
        "message": f"User '{username}' created successfully.",
        "user": {"username": username, "role": role}
    }), 201


@app.route("/admin/users/<username>", methods=["PATCH", "DELETE"])
@role_required("Admin")
def admin_user_detail(username):
    username = str(username).strip().lower()
    users = load_users()

    if username not in users:
        return jsonify({"success": False, "error": "User not found."}), 404

    if request.method == "DELETE":
        if username == str(session.get("username", "")).lower():
            return jsonify({"success": False, "error": "You cannot delete your own account while logged in."}), 400

        target_role = users[username].get("role", "Viewer")
        if target_role == "Admin":
            admin_count = sum(1 for item in users.values() if item.get("role") == "Admin")
            if admin_count <= 1:
                return jsonify({"success": False, "error": "The last Admin account cannot be deleted."}), 400

        del users[username]
        save_users(users)
        write_auth_audit("USER_DELETED", username=session.get("username", "admin"), role="Admin", target=username, details=f"Deleted {target_role} account")
        return jsonify({"success": True, "message": f"User '{username}' deleted."})

    payload = request.get_json(silent=True) or request.form.to_dict()
    new_role = str(payload.get("role", users[username].get("role", "Viewer"))).strip()
    new_password = str(payload.get("password", ""))

    if new_role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": "Invalid SOC role."}), 400

    if username == str(session.get("username", "")).lower() and new_role != "Admin":
        return jsonify({"success": False, "error": "You cannot remove Admin access from your own active account."}), 400

    if users[username].get("role") == "Admin" and new_role != "Admin":
        admin_count = sum(1 for item in users.values() if item.get("role") == "Admin")
        if admin_count <= 1:
            return jsonify({"success": False, "error": "The last Admin account must remain an Admin."}), 400

    users[username]["role"] = new_role
    if new_password:
        if len(new_password) < 10:
            return jsonify({"success": False, "error": "Password must be at least 10 characters."}), 400
        users[username]["password_hash"] = generate_password_hash(new_password)
    users[username]["updated_at"] = datetime.now().isoformat(timespec="seconds")
    users[username]["updated_by"] = session.get("username", "admin")
    save_users(users)
    changes = f"Role: {new_role}" + ("; Password reset" if new_password else "")
    write_auth_audit("USER_UPDATED", username=session.get("username", "admin"), role="Admin", target=username, details=changes)

    return jsonify({
        "success": True,
        "message": f"User '{username}' updated successfully.",
        "user": {"username": username, "role": new_role}
    })

@app.route("/auth/audit")
@role_required("Admin")
def auth_audit():
    """Return recent authentication and user-management audit events."""
    try:
        _migrate_auth_audit_csv_to_db()
        conn = get_db()
        rows = conn.execute("""
            SELECT timestamp AS Timestamp, event AS Event, username AS Username,
                   role AS Role, target AS Target, ip_address AS "IP Address", details AS Details
            FROM authentication_audit
            ORDER BY id DESC LIMIT 200
        """).fetchall()
        events = [dict(row) for row in rows]
        conn.close()
        return jsonify({"success": True, "events": events, "count": len(events)})
    except Exception as error:
        return jsonify({"success": False, "error": f"Unable to read authentication audit database: {error}"}), 500

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR, "models", "random_forest_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR, "models", "scaler.pkl"
)

LOG_DIR = os.path.join(BASE_DIR, "logs")
PREDICTION_LOG = os.path.join(LOG_DIR, "predictions.json")
CSV_LOG = os.path.join(LOG_DIR, "csv_predictions.csv")
INCIDENT_LOG = os.path.join(LOG_DIR, "security_incidents.csv")
INCIDENT_RESPONSE_LOG = os.path.join(LOG_DIR, "incident_response_actions.csv")
INCIDENT_STATUS_LOG = os.path.join(LOG_DIR, "incident_status.csv")

os.makedirs(LOG_DIR, exist_ok=True)

# ============================================================
# FEATURES USED BY THE TRAINED MODEL
# ============================================================

FEATURES = [
    "Avg Bwd Segment Size",
    "Packet Length Variance",
    "Bwd Packet Length Max",
    "Max Packet Length",
    "Bwd Packet Length Std",
    "Packet Length Std",
    "Average Packet Size",
    "Subflow Fwd Packets",
    "act_data_pkt_fwd",
    "Bwd Packet Length Mean"
]

# ============================================================
# LOAD MODEL
# ============================================================

model = None
scaler = None
model_error = None
scaler_status = "Not loaded"

try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}"
        )

    model = joblib.load(MODEL_PATH)

    print("=" * 60)
    print("AI-NET MODEL LOADED SUCCESSFULLY")
    print("=" * 60)
    print("Model type:", type(model).__name__)

    if os.path.exists(SCALER_PATH):
        try:
            scaler = joblib.load(SCALER_PATH)
            print("Scaler loaded successfully.")
            print("Scaler type:", type(scaler).__name__)

            if hasattr(scaler, "feature_names_in_"):
                scaler_features = list(scaler.feature_names_in_)

                if scaler_features == FEATURES:
                    scaler_status = "Compatible"
                elif set(scaler_features) == set(FEATURES):
                    scaler_status = "Compatible after reordering"
                else:
                    scaler_status = "Incompatible"
            elif hasattr(scaler, "n_features_in_"):
                scaler_status = (
                    "Compatible"
                    if int(scaler.n_features_in_) == len(FEATURES)
                    else "Incompatible"
                )
            else:
                scaler_status = "Loaded"

        except Exception as e:
            print("WARNING: Could not load scaler:", str(e))
            scaler = None
            scaler_status = "Unavailable"
    else:
        print("No scaler.pkl found. Continuing without scaler.")
        scaler_status = "Not found"

    if hasattr(model, "n_features_in_"):
        print("MODEL FEATURE COUNT:", model.n_features_in_)

    print("EXPECTED APP FEATURES:", len(FEATURES))
    print("=" * 60)

except Exception as e:
    model_error = str(e)
    print("=" * 60)
    print("ERROR LOADING MODEL")
    print(model_error)
    print("=" * 60)


# ============================================================
# LABEL CONVERSION
# ============================================================

def convert_prediction_to_label(value):
    text = str(value).strip()

    if text.upper() == "BENIGN":
        return "BENIGN"

    if text.upper() == "DDOS":
        return "DDoS"

    try:
        numeric = float(value)

        if numeric == 0:
            return "BENIGN"

        if numeric == 1:
            return "DDoS"

    except Exception:
        pass

    return text


# ============================================================
# SAVE MANUAL PREDICTION LOG
# ============================================================

def save_prediction_log(data):
    try:
        existing_logs = []

        if os.path.exists(PREDICTION_LOG):
            try:
                with open(
                    PREDICTION_LOG,
                    "r",
                    encoding="utf-8"
                ) as f:
                    existing_logs = json.load(f)

                if not isinstance(existing_logs, list):
                    existing_logs = []

            except Exception:
                existing_logs = []

        existing_logs.append(data)

        with open(
            PREDICTION_LOG,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                existing_logs,
                f,
                indent=4
            )

    except Exception as e:
        print("Logging error:", str(e))


# ============================================================
# PREPARE MODEL INPUT
# ============================================================

def prepare_prediction_input(input_df):
    input_df = input_df.copy()

    # Ensure exact feature order
    input_df = input_df[FEATURES]

    # Convert to numeric
    for feature in FEATURES:
        input_df[feature] = pd.to_numeric(
            input_df[feature],
            errors="coerce"
        )

    # Replace infinity values
    input_df = input_df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Fill missing values
    input_df = input_df.fillna(0)

    # Try scaler only when compatible
    if scaler is not None:
        try:
            if hasattr(scaler, "feature_names_in_"):
                scaler_features = list(scaler.feature_names_in_)

                if set(scaler_features) == set(FEATURES):
                    input_for_scaler = input_df[scaler_features]
                    return scaler.transform(input_for_scaler)

            elif hasattr(scaler, "n_features_in_"):
                if int(scaler.n_features_in_) == len(FEATURES):
                    return scaler.transform(input_df)

        except Exception as e:
            print("Scaler could not be applied:", str(e))
            print("Continuing with raw features.")

    return input_df


# ============================================================
# GET PREDICTION PROBABILITIES
# ============================================================

def get_prediction_probabilities(input_data):
    benign_probability = 0.0
    ddos_probability = 0.0

    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(
            model.predict_proba(input_data)
        )[0]

        classes = getattr(model, "classes_", None)

        if classes is not None:
            for class_value, probability in zip(
                classes,
                probabilities
            ):
                label = convert_prediction_to_label(
                    class_value
                )

                if label == "BENIGN":
                    benign_probability = float(probability)

                elif label == "DDoS":
                    ddos_probability = float(probability)

        elif len(probabilities) >= 2:
            benign_probability = float(probabilities[0])
            ddos_probability = float(probabilities[1])

    else:
        prediction = model.predict(input_data)[0]
        label = convert_prediction_to_label(prediction)

        if label == "BENIGN":
            benign_probability = 1.0
        elif label == "DDoS":
            ddos_probability = 1.0

    total = benign_probability + ddos_probability

    if total > 0:
        benign_percentage = (
            benign_probability / total
        ) * 100

        ddos_percentage = (
            ddos_probability / total
        ) * 100
    else:
        benign_percentage = 0.0
        ddos_percentage = 0.0

    return benign_percentage, ddos_percentage


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    return render_template(
        "index.html",
        model_online=(model is not None),
        model_type=(
            type(model).__name__
            if model is not None
            else "Unavailable"
        ),
        feature_count=len(FEATURES),
        class_count=2,
        features=FEATURES
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    if model is None:
        return jsonify({
            "status": "offline",
            "model_loaded": False,
            "error": model_error
        }), 500

    return jsonify({
        "status": "online",
        "model_loaded": True,
        "model_type": type(model).__name__,
        "features": len(FEATURES),
        "scaler_status": scaler_status,
        "classes": ["BENIGN", "DDoS"]
    })


# ============================================================
# MANUAL PREDICTION API
# ============================================================

@app.route("/predict", methods=["POST"])
@role_required("SOC Analyst", "Admin")
def predict():
    if model is None:
        return jsonify({
            "success": False,
            "error": "Machine learning model is not loaded."
        }), 500

    try:
        data = request.get_json(silent=True)

        if data is None:
            return jsonify({
                "success": False,
                "error": "Invalid JSON request."
            }), 400

        received_features = data.get("features")

        if received_features is None:
            return jsonify({
                "success": False,
                "error": "Missing 'features' in request."
            }), 400

        # Dictionary input
        if isinstance(received_features, dict):
            values = []

            for feature in FEATURES:
                if feature not in received_features:
                    return jsonify({
                        "success": False,
                        "error": f"Missing feature: {feature}"
                    }), 400

                try:
                    value = float(
                        received_features[feature]
                    )
                except Exception:
                    return jsonify({
                        "success": False,
                        "error": f"Invalid value for feature: {feature}"
                    }), 400

                if not np.isfinite(value):
                    return jsonify({
                        "success": False,
                        "error": f"Invalid numeric value for: {feature}"
                    }), 400

                values.append(value)

        # List input
        elif isinstance(received_features, list):
            if len(received_features) != len(FEATURES):
                return jsonify({
                    "success": False,
                    "error": (
                        f"Expected {len(FEATURES)} features "
                        f"but received {len(received_features)}."
                    )
                }), 400

            values = []

            for value in received_features:
                try:
                    value = float(value)
                except Exception:
                    return jsonify({
                        "success": False,
                        "error": "All feature values must be numeric."
                    }), 400

                if not np.isfinite(value):
                    return jsonify({
                        "success": False,
                        "error": "Feature values must be finite numbers."
                    }), 400

                values.append(value)

        else:
            return jsonify({
                "success": False,
                "error": "'features' must be a list or dictionary."
            }), 400

        input_df = pd.DataFrame(
            [values],
            columns=FEATURES
        )

        if hasattr(model, "n_features_in_"):
            expected_count = int(model.n_features_in_)

            if expected_count != len(FEATURES):
                return jsonify({
                    "success": False,
                    "error": (
                        f"Feature count mismatch. Model expects "
                        f"{expected_count} features but app provides "
                        f"{len(FEATURES)}."
                    )
                }), 500

        prediction_input = prepare_prediction_input(
            input_df
        )

        raw_prediction = model.predict(
            prediction_input
        )[0]

        result = convert_prediction_to_label(
            raw_prediction
        )

        benign_percentage, ddos_percentage = (
            get_prediction_probabilities(
                prediction_input
            )
        )

        confidence = max(
            benign_percentage,
            ddos_percentage
        )

        if result == "DDoS":
            message = "DDoS ATTACK DETECTED"
        elif result == "BENIGN":
            message = "BENIGN TRAFFIC"
        else:
            message = str(result)

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "prediction": result,
            "confidence": round(confidence, 4),
            "probabilities": {
                "BENIGN": round(benign_percentage, 4),
                "DDoS": round(ddos_percentage, 4)
            },
            "features": {
                feature: value
                for feature, value in zip(
                    FEATURES,
                    values
                )
            }
        }

        save_prediction_log(log_entry)

        return jsonify({
            "success": True,
            "prediction": result,
            "result": result,
            "message": message,
            "confidence": round(confidence, 2),
            "probabilities": {
                "BENIGN": round(benign_percentage, 2),
                "DDoS": round(ddos_percentage, 2)
            },
            "features": {
                feature: value
                for feature, value in zip(
                    FEATURES,
                    values
                )
            }
        })

    except Exception as e:
        print("PREDICTION ERROR:", str(e))

        return jsonify({
            "success": False,
            "error": "Prediction failed.",
            "details": str(e)
        }), 500


# ============================================================
# CSV TRAFFIC ANALYSIS API
# ============================================================

@app.route("/predict_csv", methods=["POST"])
@role_required("SOC Analyst", "Admin")
def predict_csv():
    if model is None:
        return jsonify({
            "success": False,
            "error": "Machine learning model is not loaded.",
            "details": model_error
        }), 500

    try:
        # --------------------------------------------------------
        # Get uploaded file
        # --------------------------------------------------------

        uploaded_file = request.files.get("file")

        if uploaded_file is None:
            return jsonify({
                "success": False,
                "error": "No CSV file was uploaded."
            }), 400

        if uploaded_file.filename == "":
            return jsonify({
                "success": False,
                "error": "No CSV file was selected."
            }), 400

        if not uploaded_file.filename.lower().endswith(".csv"):
            return jsonify({
                "success": False,
                "error": "Please upload a CSV file."
            }), 400

        print("\n" + "=" * 60)
        print("AI-NET CSV ANALYSIS")
        print("=" * 60)
        print("File:", uploaded_file.filename)

        # --------------------------------------------------------
        # Read CSV
        # --------------------------------------------------------

        df = pd.read_csv(uploaded_file)

        if df.empty:
            return jsonify({
                "success": False,
                "error": "The uploaded CSV is empty."
            }), 400

        # CIC-IDS2017 CSV headers often contain leading spaces.
        df.columns = df.columns.astype(str).str.strip()

        print("Rows:", len(df))
        print("Columns:", len(df.columns))

        # --------------------------------------------------------
        # Verify required features
        # --------------------------------------------------------

        missing_features = [
            feature
            for feature in FEATURES
            if feature not in df.columns
        ]

        if missing_features:
            return jsonify({
                "success": False,
                "error": "CSV is missing required model features.",
                "missing_features": missing_features
            }), 400

        # --------------------------------------------------------
        # Prepare feature data
        # --------------------------------------------------------

        feature_df = df[FEATURES].copy()

        for feature in FEATURES:
            feature_df[feature] = pd.to_numeric(
                feature_df[feature],
                errors="coerce"
            )

        feature_df = feature_df.replace(
            [np.inf, -np.inf],
            np.nan
        )

        feature_df = feature_df.fillna(0)

        # --------------------------------------------------------
        # Check model feature count
        # --------------------------------------------------------

        if hasattr(model, "n_features_in_"):
            expected_count = int(model.n_features_in_)

            if expected_count != len(FEATURES):
                return jsonify({
                    "success": False,
                    "error": (
                        f"Feature count mismatch. Model expects "
                        f"{expected_count} features but app provides "
                        f"{len(FEATURES)}."
                    )
                }), 500

        # --------------------------------------------------------
        # Prepare model input
        # --------------------------------------------------------

        prediction_input = prepare_prediction_input(
            feature_df
        )

        # --------------------------------------------------------
        # Predict entire dataset
        # --------------------------------------------------------

        predictions = model.predict(
            prediction_input
        )

        predictions = np.asarray(
            predictions
        )

        labels = [
            convert_prediction_to_label(prediction)
            for prediction in predictions
        ]

        # --------------------------------------------------------
        # Probabilities
        # --------------------------------------------------------

        if hasattr(model, "predict_proba"):
            probability_array = np.asarray(
                model.predict_proba(
                    prediction_input
                )
            )

            classes = getattr(
                model,
                "classes_",
                None
            )

            benign_probabilities = np.zeros(
                len(df),
                dtype=float
            )

            ddos_probabilities = np.zeros(
                len(df),
                dtype=float
            )

            if classes is not None:
                for index, class_value in enumerate(classes):
                    label = convert_prediction_to_label(
                        class_value
                    )

                    if label == "BENIGN":
                        benign_probabilities = (
                            probability_array[:, index] * 100
                        )

                    elif label == "DDoS":
                        ddos_probabilities = (
                            probability_array[:, index] * 100
                        )

            confidence_array = np.maximum(
                benign_probabilities,
                ddos_probabilities
            )

        else:
            benign_probabilities = np.array([
                100.0 if label == "BENIGN" else 0.0
                for label in labels
            ])

            ddos_probabilities = np.array([
                100.0 if label == "DDoS" else 0.0
                for label in labels
            ])

            confidence_array = np.maximum(
                benign_probabilities,
                ddos_probabilities
            )

        # --------------------------------------------------------
        # Create results dataframe
        # --------------------------------------------------------

        results_df = df.copy()

        results_df["AI-Net Prediction"] = labels
        results_df["BENIGN Probability (%)"] = np.round(
            benign_probabilities,
            4
        )
        results_df["DDoS Probability (%)"] = np.round(
            ddos_probabilities,
            4
        )
        results_df["AI-Net Confidence (%)"] = np.round(
            confidence_array,
            4
        )

        # --------------------------------------------------------
        # Save results
        # --------------------------------------------------------

        results_df.to_csv(
            CSV_LOG,
            index=False
        )

        # --------------------------------------------------------
        # Summary
        # --------------------------------------------------------

        total_rows = len(results_df)

        benign_count = sum(
            label == "BENIGN"
            for label in labels
        )

        ddos_count = sum(
            label == "DDoS"
            for label in labels
        )

        benign_percentage = (
            benign_count / total_rows * 100
            if total_rows > 0
            else 0
        )

        ddos_percentage = (
            ddos_count / total_rows * 100
            if total_rows > 0
            else 0
        )

        average_confidence = (
            float(np.mean(confidence_array))
            if len(confidence_array) > 0
            else 0
        )

        attack_detected = ddos_count > 0

        print("\nCSV ANALYSIS COMPLETE")
        print("Total traffic:", total_rows)
        print("BENIGN:", benign_count)
        print("DDoS:", ddos_count)
        print(
            "Average confidence:",
            round(average_confidence, 2),
            "%"
        )
        print("=" * 60)

        # --------------------------------------------------------
        # Return JSON for dashboard
        # --------------------------------------------------------

        return jsonify({
            "success": True,
            "filename": uploaded_file.filename,
            "total_rows": total_rows,
            "total_traffic": total_rows,

            "benign_count": benign_count,
            "ddos_count": ddos_count,

            # Compatibility aliases used by the dashboard UI
            "benign_traffic": benign_count,
            "ddos_traffic": ddos_count,
            "benign": benign_count,
            "ddos": ddos_count,

            "benign_percentage": round(
                benign_percentage,
                2
            ),

            "ddos_percentage": round(
                ddos_percentage,
                2
            ),

            "average_confidence": round(
                average_confidence,
                2
            ),

            "confidence": round(
                average_confidence,
                2
            ),

            "attack_detected": attack_detected,

            "results_file": "logs/csv_predictions.csv"
        })

    except pd.errors.EmptyDataError:
        return jsonify({
            "success": False,
            "error": "The uploaded file does not contain CSV data."
        }), 400

    except Exception as e:
        print("\nCSV ANALYSIS ERROR:")
        print(str(e))

        return jsonify({
            "success": False,
            "error": "CSV analysis failed.",
            "details": str(e)
        }), 500



# ============================================================
# DAY 47.1 — DETECTION EVENT PERSISTENCE
# ============================================================
def _safe_float(value):
    try:
        if value is None or (isinstance(value, float) and np.isnan(value)):
            return None
        return float(value)
    except Exception:
        return None

def _event_hash(record, source):
    fields = [source] + [str(record.get(k, "")) for k in (
        "Timestamp", "Source IP", "Destination IP", "Source Port",
        "Destination Port", "Protocol", "Flow Duration", "Packets",
        "Fwd Packets", "Bwd Packets", "AI-Net Prediction",
        "AI-Net Confidence (%)"
    )]
    return hashlib.sha256("|".join(fields).encode("utf-8", errors="ignore")).hexdigest()

def sync_detection_logs_to_db():
    """Ingest legacy/live CSV detections into SQLite without removing the CSV logs."""
    sources = []
    if os.path.exists(LIVE_LOG):
        sources.append((LIVE_LOG, "live_packet_capture"))
    if os.path.exists(CSV_LOG):
        sources.append((CSV_LOG, "csv_analysis"))
    if not sources:
        return 0
    conn = get_db()
    inserted = 0
    try:
        for path, source in sources:
            header = pd.read_csv(path, nrows=0)
            cols = set(header.columns)
            wanted = [c for c in [
                "Timestamp", "Source IP", "Destination IP", "Source Port",
                "Destination Port", "Protocol", "Flow Duration", "Packets",
                "Fwd Packets", "Bwd Packets", "AI-Net Prediction",
                "AI-Net Confidence (%)"
            ] if c in cols]
            if "AI-Net Prediction" not in wanted:
                continue
            df = pd.read_csv(path, usecols=wanted)
            for record in df.tail(5000).to_dict(orient="records"):
                h = _event_hash(record, source)
                prediction = convert_prediction_to_label(record.get("AI-Net Prediction", ""))
                confidence = _safe_float(record.get("AI-Net Confidence (%)"))
                cur = conn.execute("""
                    INSERT OR IGNORE INTO detection_events
                    (event_hash, timestamp, source_ip, destination_ip, source_port,
                     destination_port, protocol, flow_duration, packets, fwd_packets,
                     bwd_packets, prediction, confidence, source, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (h, record.get("Timestamp"), record.get("Source IP"),
                      record.get("Destination IP"), str(record.get("Source Port", "")),
                      str(record.get("Destination Port", "")), record.get("Protocol"),
                      _safe_float(record.get("Flow Duration")), _safe_float(record.get("Packets")),
                      _safe_float(record.get("Fwd Packets")), _safe_float(record.get("Bwd Packets")),
                      prediction, confidence, source, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                inserted += cur.rowcount
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return inserted


def safe_sync_detection_logs_to_db():
    try:
        return sync_detection_logs_to_db(), None
    except Exception as error:
        print("DETECTION LOG SYNC WARNING:", str(error))
        return 0, str(error)


# ============================================================
# RECENT DETECTIONS API
# ============================================================

@app.route("/recent_detections", methods=["GET"])
def recent_detections():
    """Return recent detections from SQLite, populated from live/CSV telemetry."""
    try:
        # SQLite is the primary source. Legacy CSV synchronization is best-effort
        # and must never make this read-only endpoint return HTTP 500.
        try:
            sync_detection_logs_to_db()
        except Exception as sync_error:
            print("RECENT DETECTIONS SYNC WARNING:", str(sync_error))

        conn = get_db()
        try:
            rows = conn.execute("""
                SELECT timestamp, source_ip, destination_ip, source_port,
                       destination_port, protocol, flow_duration, prediction, confidence, source
                FROM detection_events
                ORDER BY id DESC LIMIT 10
            """).fetchall()
        finally:
            conn.close()
        detections = []
        for row in rows:
            detections.append({
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "source_port": row["source_port"],
                "destination_port": row["destination_port"],
                "protocol": row["protocol"],
                "flow_duration": row["flow_duration"],
                "prediction": row["prediction"],
                "confidence": round(float(row["confidence"] or 0), 2),
            })
        source = "sqlite_detection_events"
        return jsonify({
            "success": True,
            "source": source,
            "count": len(detections),
            "ddos_recent": sum(x["prediction"] == "DDoS" for x in detections),
            "detections": detections
        })
    except Exception as error:
        print("RECENT DETECTIONS ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load recent detections.",
            "details": str(error)
        }), 500


# ============================================================
# SECURITY ALERTS API
# ============================================================

@app.route("/security_alerts", methods=["GET"])
def security_alerts():
    """Generate security alerts from the SQLite detection store."""
    try:
        sync_warning = None
        try:
            sync_detection_logs_to_db()
        except Exception as sync_error:
            sync_warning = str(sync_error)
            print("SECURITY ALERTS SYNC WARNING:", sync_warning)

        conn = get_db()
        try:
            source = "sqlite_detection_events"
            stats = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(prediction) = 'DDOS' THEN 1 ELSE 0 END) AS ddos,
                       AVG(COALESCE(confidence, 0)) AS avg_confidence
                FROM detection_events
            """).fetchone()
            rows = conn.execute("""
                SELECT timestamp, source_ip, destination_ip, prediction, confidence
                FROM detection_events
                ORDER BY id DESC
                LIMIT 50
            """).fetchall()
        finally:
            conn.close()

        total = int(stats["total"] or 0)
        ddos = int(stats["ddos"] or 0)
        avg_confidence = float(stats["avg_confidence"] or 0)
        alerts = []
        for row in rows:
            if convert_prediction_to_label(row["prediction"]) != "DDoS":
                continue
            score = float(row["confidence"] or 0)
            level = "critical" if score >= 95 else ("high" if score >= 80 else "medium")
            alerts.append({
                "level": level,
                "title": "DDoS Attack Detected",
                "message": f"{row['source_ip'] or 'Unknown source'} → {row['destination_ip'] or 'Unknown destination'} classified as DDoS with {score:.2f}% confidence.",
                "timestamp": row["timestamp"],
                "confidence": round(score, 2)
            })

        return jsonify({
            "success": True,
            "source": source,
            "alerts": alerts[:10],
            "attack_rate": round(ddos / total * 100 if total else 0, 2),
            "average_confidence": round(avg_confidence, 2),
            "total": total,
            "ddos": ddos,
            "sync_warning": sync_warning
        })
    except Exception as error:
        print("SECURITY ALERTS ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load security alerts.",
            "details": str(error)
        }), 500


# ============================================================
# SECURITY REPORT
# ============================================================

@app.route("/generate_report", methods=["GET"])
def generate_report():
    """Generate a professional PDF security report from the latest detections."""
    try:
        from io import BytesIO
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
        from datetime import datetime

        total = benign = ddos = 0
        avg_confidence = 0.0
        attack_rate = 0.0

        if os.path.exists(LIVE_LOG):
            df = pd.read_csv(LIVE_LOG)
            df.columns = df.columns.astype(str).str.strip()

            prediction_col = next(
                (c for c in ["AI-Net Prediction", "Prediction", "prediction", "Label"]
                 if c in df.columns),
                None
            )
            confidence_col = next(
                (c for c in ["AI-Net Confidence (%)", "Confidence", "confidence"]
                 if c in df.columns),
                None
            )

            if prediction_col:
                predictions = df[prediction_col].astype(str).str.strip().str.upper()
                total = int(len(df))
                benign = int((predictions == "BENIGN").sum())
                ddos = int((predictions == "DDOS").sum())
                attack_rate = round((ddos / total) * 100, 2) if total else 0.0

            if confidence_col and total:
                numeric_conf = pd.to_numeric(df[confidence_col], errors="coerce")
                avg_confidence = round(float(numeric_conf.mean()), 2) if numeric_conf.notna().any() else 0.0

        buffer = BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=42,
            bottomMargin=42
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=22,
            leading=27,
            spaceAfter=8
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            alignment=TA_CENTER,
            fontSize=10,
            textColor=colors.grey,
            spaceAfter=22
        )
        heading_style = ParagraphStyle(
            "ReportHeading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=14,
            spaceAfter=8
        )

        story = [
            Paragraph("AI-Net Security Report", title_style),
            Paragraph(
                "AI-powered Network Intrusion Detection System",
                subtitle_style
            ),
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                subtitle_style
            ),
            Paragraph("Executive Summary", heading_style),
        ]

        summary_data = [
            ["Metric", "Result"],
            ["Total Network Flows", f"{total:,}"],
            ["BENIGN Traffic", f"{benign:,}"],
            ["DDoS Detections", f"{ddos:,}"],
            ["Attack Rate", f"{attack_rate:.2f}%"],
            ["Average Confidence", f"{avg_confidence:.2f}%"],
        ]

        summary_table = Table(summary_data, colWidths=[260, 180])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7dee9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white, colors.HexColor("#f8fafc")
            ]),
            ("PADDING", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 1), (1, -1), "RIGHT"),
        ]))

        story += [
            summary_table,
            Paragraph("Detection Engine", heading_style),
        ]

        engine_data = [
            ["Property", "Configuration"],
            ["Model", "Random Forest"],
            ["Features", "10 selected network-flow features"],
            ["Classes", "BENIGN / DDoS"],
            ["Backend", "Flask API"],
            ["Packet Capture", "Scapy + Npcap"],
        ]

        engine_table = Table(engine_data, colWidths=[180, 260])
        engine_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172554")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7dee9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white, colors.HexColor("#f8fafc")
            ]),
            ("PADDING", (0, 0), (-1, -1), 9),
        ]))

        story += [
            engine_table,
            Paragraph("Security Assessment", heading_style),
            Paragraph(
                (
                    "No DDoS activity was detected in the latest persistent "
                    "live-capture history."
                    if ddos == 0
                    else
                    f"The latest persistent history contains {ddos:,} DDoS "
                    f"detection(s), representing an attack rate of {attack_rate:.2f}%."
                ),
                styles["BodyText"]
            ),
            Spacer(1, 18),
            Paragraph(
                "AI-Net — Network Intrusion Detection and Security Analytics",
                subtitle_style
            )
        ]

        doc.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"AI-Net_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    except Exception as error:
        print("SECURITY REPORT ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# DETECTION HISTORY
# ============================================================

@app.route("/detection_history", methods=["GET"])
def detection_history():
    """Persistent detection history backed directly by SQLite."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(5, min(int(request.args.get("per_page", 20)), 100))
        search = str(request.args.get("search", "")).strip().lower()
        detection_filter = str(request.args.get("detection", "ALL")).strip().upper()
        start_date = str(request.args.get("start_date", "")).strip()
        end_date = str(request.args.get("end_date", "")).strip()

        try:
            sync_detection_logs_to_db()
        except Exception as sync_error:
            print("DETECTION HISTORY SYNC WARNING:", str(sync_error))
        where=[]
        params=[]
        if search:
            like=f"%{search}%"
            where.append("LOWER(COALESCE(timestamp,'')) LIKE ? OR LOWER(COALESCE(source_ip,'')) LIKE ? OR LOWER(COALESCE(destination_ip,'')) LIKE ? OR LOWER(COALESCE(protocol,'')) LIKE ? OR LOWER(COALESCE(prediction,'')) LIKE ?")
            params.extend([like]*5)
        if detection_filter in {"BENIGN", "DDOS"}:
            where.append("UPPER(prediction) = ?")
            params.append(detection_filter)
        if start_date:
            where.append("substr(COALESCE(timestamp,''),1,10) >= ?")
            params.append(start_date)
        if end_date:
            where.append("substr(COALESCE(timestamp,''),1,10) <= ?")
            params.append(end_date)

        clause = (" WHERE " + " AND ".join(f"({x})" for x in where)) if where else ""
        conn=get_db()
        try:
            total=int(conn.execute(f"SELECT COUNT(*) FROM detection_events{clause}", params).fetchone()[0] or 0)
            total_pages=(total+per_page-1)//per_page if total else 0
            if total_pages and page>total_pages: page=total_pages
            offset=(page-1)*per_page
            rows=conn.execute(f"""
                SELECT timestamp, source_ip, destination_ip, protocol, prediction, confidence
                FROM detection_events {clause}
                ORDER BY id DESC LIMIT ? OFFSET ?
            """, params+[per_page,offset]).fetchall()
        finally:
            conn.close()

        records=[]
        for row in rows:
            prediction=convert_prediction_to_label(row["prediction"])
            records.append({
                "timestamp": row["timestamp"] or "—",
                "source_ip": row["source_ip"] or "Unknown",
                "destination_ip": row["destination_ip"] or "Unknown",
                "protocol": row["protocol"] or "Unknown",
                "prediction": prediction,
                "confidence": round(float(row["confidence"] or 0),2),
                "severity": "CRITICAL" if prediction == "DDoS" else "INFO"
            })
        return jsonify({"success":True,"source":"sqlite_detection_events","total":total,"page":page,"per_page":per_page,"total_pages":total_pages,"detections":records})
    except Exception as error:
        print("DETECTION HISTORY ERROR:",str(error))
        return jsonify({"success":False,"error":str(error),"detections":[]}),500


@app.route("/latest_alerts", methods=["GET"])
def latest_alerts():
    """Compatibility endpoint for dashboard integrations."""
    return security_alerts()


# ============================================================
# REAL-TIME PACKET CAPTURE INTEGRATION
# ============================================================

LIVE_LOG = os.path.join(
    LOG_DIR,
    "live_predictions.csv"
)

live_sniffer = None
live_capture_lock = threading.Lock()
live_capture_status = "stopped"
live_capture_error = None
live_capture_started_at = None
live_capture_interface = None
live_capture_worker = None
LIVE_FLOW_TIMEOUT = 5


def get_live_capture_module():
    """
    Import the Day 11 packet-capture engine only when live capture
    is requested. This keeps normal Flask startup lightweight.
    """
    import packet_capture
    return packet_capture



def live_capture_processing_worker():
    """
    Continuously classify flows that have been inactive for a short period
    while the Scapy sniffer is running.
    """
    global live_capture_worker

    try:
        packet_capture = get_live_capture_module()

        while True:
            try:
                running = (
                    live_sniffer is not None
                    and bool(live_sniffer.running)
                    and live_capture_status == "running"
                )
            except Exception:
                running = False

            if not running:
                break

            try:
                packet_capture.process_expired_flows(
                    LIVE_FLOW_TIMEOUT
                )
            except Exception as error:
                print(
                    "LIVE FLOW PROCESSING ERROR:",
                    str(error)
                )

            time.sleep(1)

    finally:
        live_capture_worker = None


def live_capture_start(interface=None):
    """
    Start Scapy packet capture in the background.

    The existing Day 11 packet_capture.py engine performs flow
    aggregation, feature extraction, Random Forest prediction,
    and writes logs/live_predictions.csv.
    """
    global live_sniffer
    global live_capture_status
    global live_capture_error
    global live_capture_started_at
    global live_capture_interface

    with live_capture_lock:
        if live_sniffer is not None:
            try:
                if live_sniffer.running:
                    return False, "Live packet capture is already running."
            except Exception:
                pass

        try:
            packet_capture = get_live_capture_module()

            # Start a fresh live session so old detections do not appear
            # as current live alerts or timeline events.
            packet_capture.flows.clear()

            if os.path.exists(LIVE_LOG):
                try:
                    os.remove(LIVE_LOG)
                except Exception as error:
                    print("LIVE LOG RESET WARNING:", str(error))

            from scapy.all import AsyncSniffer

            live_capture_interface = interface or "default"
            live_capture_error = None
            live_capture_started_at = datetime.now().isoformat()
            live_capture_status = "running"

            live_sniffer = AsyncSniffer(
                iface=interface if interface else None,
                prn=packet_capture.packet_handler,
                store=False
            )

            live_sniffer.start()

            global live_capture_worker
            live_capture_worker = threading.Thread(
                target=live_capture_processing_worker,
                daemon=True
            )
            live_capture_worker.start()

            print("=" * 60)
            print("AI-NET LIVE CAPTURE STARTED")
            print("Interface:", live_capture_interface)
            print("Output:", LIVE_LOG)
            print("=" * 60)

            return True, "Live packet capture started."

        except Exception as error:
            live_sniffer = None
            live_capture_status = "error"
            live_capture_error = str(error)

            print("LIVE CAPTURE START ERROR:", str(error))

            return False, str(error)


def live_capture_stop():
    """
    Stop Scapy capture and immediately classify remaining flows.
    """
    global live_sniffer
    global live_capture_status
    global live_capture_error

    with live_capture_lock:
        if live_sniffer is None:
            live_capture_status = "stopped"
            return False, "Live packet capture is not running."

        try:
            if live_sniffer.running:
                live_sniffer.stop()

            packet_capture = get_live_capture_module()

            # Process all flows still active at shutdown.
            packet_capture.process_expired_flows(0)

            live_sniffer = None
            live_capture_status = "stopped"
            live_capture_error = None

            print("=" * 60)
            print("AI-NET LIVE CAPTURE STOPPED")
            print("=" * 60)

            return True, "Live packet capture stopped."

        except Exception as error:
            live_capture_error = str(error)
            live_capture_status = "error"

            print("LIVE CAPTURE STOP ERROR:", str(error))

            return False, str(error)


def get_live_statistics():
    """Read current-session live detections from SQLite first, with CSV fallback."""
    stats = {
        "total": 0,
        "benign": 0,
        "ddos": 0,
        "attack_rate": 0.0,
        "updated_at": None,
        "available": False
    }

    # SQLite is the primary store for live detection telemetry.
    try:
        conn = get_db()
        try:
            query = """
                SELECT timestamp, prediction, confidence
                FROM detection_events
                WHERE source = 'live_packet_capture'
            """
        
            params = []
            if live_capture_started_at:
                try:
                    started = datetime.fromisoformat(live_capture_started_at).strftime("%Y-%m-%d %H:%M:%S")
                    query += " AND timestamp >= ?"
                    params.append(started)
                except Exception:
                    pass

            query += " ORDER BY timestamp ASC"
            results = conn.execute(query, params).fetchall()
        finally:
            conn.close()

        if results:
            total = len(results)
            ddos = sum(1 for row in results if convert_prediction_to_label(row[1]) == "DDoS")
            benign = total - ddos
            stats.update({
                "total": total,
                "benign": benign,
                "ddos": ddos,
                "attack_rate": round((ddos / total) * 100, 2) if total else 0.0,
                "updated_at": results[-1][0],
                "available": True
            })
            return stats
    except Exception as error:
        print("LIVE SQLITE STATISTICS WARNING:", error)

    # Compatibility fallback for older captures.
    if not os.path.exists(LIVE_LOG):
        return stats

    try:
        results = pd.read_csv(
            LIVE_LOG,
            usecols=[
                "Timestamp",
                "AI-Net Prediction",
                "AI-Net Confidence (%)"
            ]
        )

        if results.empty:
            return stats

        labels = results["AI-Net Prediction"].apply(convert_prediction_to_label)
        total = len(results)
        ddos = int((labels == "DDoS").sum())
        benign = total - ddos

        stats.update({
            "total": total,
            "benign": benign,
            "ddos": ddos,
            "attack_rate": round((ddos / total) * 100, 2) if total else 0.0,
            "updated_at": str(results["Timestamp"].iloc[-1]),
            "available": True
        })
        return stats
    except Exception as error:
        print("LIVE CSV STATISTICS WARNING:", error)
        return stats


def _migrate_ioc_json_to_db():
    """One-time migration of the legacy IOC JSON watchlist into SQLite."""
    conn = get_db()
    try:
        existing = int(conn.execute("SELECT COUNT(*) FROM ioc_watchlist").fetchone()[0])
        if existing > 0:
            return

        if not os.path.exists(IOC_STORE):
            return

        with open(IOC_STORE, "r", encoding="utf-8") as file:
            items = json.load(file)

        if not isinstance(items, list):
            return

        for item in items:
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO ioc_watchlist
                (value, ioc_type, notes, created_at, created_by)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    value,
                    str(item.get("type", "IP")).strip().upper(),
                    str(item.get("note", item.get("notes", ""))).strip(),
                    str(item.get("created_at", "")),
                    str(item.get("created_by", "migration"))
                )
            )
        conn.commit()
        Path(IOC_DB_MIGRATION_MARKER).touch()
        print(f"IOC DATABASE: migrated {len(items)} IOC record(s) from JSON")
    except Exception as error:
        conn.rollback()
        print("IOC DATABASE MIGRATION WARNING:", str(error))
    finally:
        conn.close()


def load_ioc_store():
    """Load the IOC watchlist from SQLite."""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT value, ioc_type, notes, created_at, created_by
            FROM ioc_watchlist ORDER BY id ASC"""
        ).fetchall()
        return [
            {
                "value": row["value"],
                "type": row["ioc_type"],
                "note": row["notes"] or "",
                "created_at": row["created_at"] or "",
                "created_by": row["created_by"] or ""
            }
            for row in rows
        ]
    finally:
        conn.close()


def save_ioc_store(items):
    """Compatibility helper: replace the SQLite IOC watchlist."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM ioc_watchlist")
        for item in items:
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO ioc_watchlist
                (value, ioc_type, notes, created_at, created_by)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    value,
                    str(item.get("type", "IP")).strip().upper(),
                    str(item.get("note", item.get("notes", ""))).strip(),
                    str(item.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))),
                    str(item.get("created_by", "system"))
                )
            )
        conn.commit()
    finally:
        conn.close()


_migrate_ioc_json_to_db()


@app.route("/ioc_management", methods=["GET", "POST", "DELETE"])
def ioc_management():
    """
    Local defensive IOC watchlist backed by SQLite.

    Supported:
      GET    -> list saved IOCs and current telemetry matches
      POST   -> add an IOC
      DELETE -> remove an IOC by value
    """
    if request.method != "GET":
        permission_error = viewer_read_only_guard()
        if permission_error:
            return permission_error

    try:
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            value = str(payload.get("value", "")).strip()
            ioc_type = str(payload.get("type", "IP")).strip().upper()
            note = str(payload.get("note", "")).strip()

            if not value:
                return jsonify({
                    "success": False,
                    "error": "IOC value is required."
                }), 400

            allowed_types = {"IP", "DOMAIN", "HASH", "URL"}
            if ioc_type not in allowed_types:
                return jsonify({
                    "success": False,
                    "error": "Unsupported IOC type."
                }), 400

            conn = get_db()
            try:
                existing = conn.execute(
                    "SELECT 1 FROM ioc_watchlist WHERE lower(value)=lower(?) LIMIT 1",
                    (value,)
                ).fetchone()
                if existing:
                    return jsonify({
                        "success": False,
                        "error": "IOC already exists in the watchlist."
                    }), 409

                item = {
                    "value": value,
                    "type": ioc_type,
                    "note": note,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "created_by": current_user().get("username", "system") if current_user() else "system"
                }
                conn.execute(
                    """INSERT INTO ioc_watchlist
                    (value, ioc_type, notes, created_at, created_by)
                    VALUES (?, ?, ?, ?, ?)""",
                    (item["value"], item["type"], item["note"], item["created_at"], item["created_by"])
                )
                conn.commit()
            finally:
                conn.close()

            return jsonify({
                "success": True,
                "message": "IOC added to watchlist.",
                "ioc": item
            })

        if request.method == "DELETE":
            value = str(request.args.get("value", "")).strip()
            if not value:
                return jsonify({
                    "success": False,
                    "error": "IOC value is required."
                }), 400

            conn = get_db()
            try:
                cursor = conn.execute(
                    "DELETE FROM ioc_watchlist WHERE lower(value)=lower(?)",
                    (value,)
                )
                conn.commit()
                deleted = cursor.rowcount
            finally:
                conn.close()

            if not deleted:
                return jsonify({
                    "success": False,
                    "error": "IOC was not found."
                }), 404

            return jsonify({
                "success": True,
                "message": "IOC removed from watchlist."
            })

        # GET
        items = load_ioc_store()

        # IOC matching is intentionally limited to collected IP telemetry.
        if os.path.exists(LIVE_LOG):
            df = pd.read_csv(LIVE_LOG)
            telemetry_source = "Live capture"
        elif os.path.exists(CSV_LOG):
            df = pd.read_csv(CSV_LOG)
            telemetry_source = "CSV analysis"
        else:
            df = pd.DataFrame()
            telemetry_source = "No telemetry"

        if not df.empty:
            df.columns = df.columns.astype(str).str.strip()

        source_col = next(
            (c for c in ["Source IP", "Src IP", "src_ip"] if c in df.columns),
            None
        )
        dest_col = next(
            (c for c in ["Destination IP", "Dst IP", "dst_ip"] if c in df.columns),
            None
        )
        prediction_col = next(
            (c for c in [
                "AI-Net Prediction", "Prediction", "prediction", "Label"
            ] if c in df.columns),
            None
        )

        for item in items:
            value = str(item.get("value", "")).strip()
            matches = pd.DataFrame()

            if (
                not df.empty and
                item.get("type") == "IP" and
                (source_col or dest_col)
            ):
                mask = pd.Series(False, index=df.index)
                if source_col:
                    mask = mask | df[source_col].astype(str).str.strip().eq(value)
                if dest_col:
                    mask = mask | df[dest_col].astype(str).str.strip().eq(value)
                matches = df.loc[mask]

            ddos_matches = 0
            if prediction_col and not matches.empty:
                ddos_matches = int(
                    matches[prediction_col]
                    .astype(str)
                    .str.strip()
                    .str.upper()
                    .eq("DDOS")
                    .sum()
                )

            item["match_count"] = int(len(matches))
            item["ddos_matches"] = ddos_matches
            item["status"] = "MATCHED" if len(matches) else "NO MATCH"

        return jsonify({
            "success": True,
            "source": telemetry_source,
            "iocs": items,
            "total_iocs": len(items),
            "matched_iocs": sum(
                1 for item in items if item.get("match_count", 0) > 0
            ),
            "ddos_iocs": sum(
                1 for item in items if item.get("ddos_matches", 0) > 0
            )
        })

    except Exception as error:
        print("IOC MANAGEMENT ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not process IOC watchlist.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 39 — SOC CASE MANAGEMENT
# ============================================================

CASE_STORE = os.path.join(LOG_DIR, "soc_cases.json")
CASE_DB_MIGRATION_MARKER = os.path.join(LOG_DIR, ".soc_cases_db_migrated")


def _migrate_soc_cases_json_to_db():
    """One-time migration of the existing SOC case JSON store into SQLite."""
    if os.path.exists(CASE_DB_MIGRATION_MARKER):
        return

    conn = get_db()
    try:
        existing = int(conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0])
        if existing == 0 and os.path.exists(CASE_STORE):
            try:
                with open(CASE_STORE, "r", encoding="utf-8") as file:
                    items = json.load(file)
                if isinstance(items, list):
                    for case in items:
                        case_id = str(case.get("case_id", "")).strip()
                        if not case_id:
                            continue
                        conn.execute("""
                            INSERT OR IGNORE INTO soc_cases
                            (case_id, title, source_ip, priority, status, notes,
                             created_at, updated_at, incident_id, created_by,
                             assigned_to, sla_due_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            case_id, case.get("title", ""), case.get("source_ip", ""),
                            case.get("priority", "MEDIUM"), case.get("status", "OPEN"),
                            case.get("notes", ""), case.get("created_at", ""),
                            case.get("updated_at", ""), case.get("incident_id", ""),
                            case.get("created_by", ""), case.get("assigned_to", "SOC Queue"),
                            case.get("sla_due_at", "")
                        ))
                    conn.commit()
                    print(f"SOC CASE DATABASE: migrated {len(items)} case(s) from soc_cases.json")
            except Exception as error:
                print("SOC CASE JSON MIGRATION ERROR:", error)
                return

        Path(CASE_DB_MIGRATION_MARKER).touch()
    finally:
        conn.close()


def load_case_store():
    _migrate_soc_cases_json_to_db()
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT case_id, title, source_ip, priority, status, notes,
                   created_at, updated_at, incident_id, created_by,
                   assigned_to, sla_due_at
            FROM soc_cases
            ORDER BY id DESC
        """).fetchall()
        return [dict(row) for row in rows]
    except Exception as error:
        print("CASE DB LOAD ERROR:", str(error))
        return []
    finally:
        conn.close()


def save_case_store(items):
    """Persist the complete SOC case collection in SQLite."""
    _migrate_soc_cases_json_to_db()
    conn = get_db()
    try:
        conn.execute("DELETE FROM soc_cases")
        for case in items:
            case_id = str(case.get("case_id", "")).strip()
            if not case_id:
                continue
            conn.execute("""
                INSERT INTO soc_cases
                (case_id, title, source_ip, priority, status, notes,
                 created_at, updated_at, incident_id, created_by,
                 assigned_to, sla_due_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id, case.get("title", ""), case.get("source_ip", ""),
                case.get("priority", "MEDIUM"), case.get("status", "OPEN"),
                case.get("notes", ""), case.get("created_at", ""),
                case.get("updated_at", ""), case.get("incident_id", ""),
                case.get("created_by", ""), case.get("assigned_to", "SOC Queue"),
                case.get("sla_due_at", "")
            ))
        conn.commit()
    except Exception as error:
        conn.rollback()
        print("CASE DB SAVE ERROR:", str(error))
        raise
    finally:
        conn.close()


def calculate_case_sla(priority):
    hours = {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 12, "LOW": 24}.get(str(priority).upper(), 12)
    return (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def auto_create_soc_cases(incidents):
    """Create one SOC case for each newly observed CRITICAL DDoS incident."""
    cases = load_case_store()
    created = []

    for incident in incidents:
        if str(incident.get("level", "")).upper() != "CRITICAL":
            continue

        incident_id = str(incident.get("incident_id", "")).strip()
        source_ip = str(incident.get("source_ip", "Unknown")).strip()
        if not incident_id:
            continue

        already_exists = any(
            str(case.get("incident_id", "")).strip() == incident_id
            for case in cases
        )

        if already_exists:
            continue

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case = {
            "case_id": "CASE-AUTO-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3],
            "title": f"Automatic Critical DDoS Investigation — {source_ip}",
            "source_ip": source_ip,
            "priority": "CRITICAL",
            "status": "OPEN",
            "notes": (
                f"Automatically created from {incident_id}. "
                f"Detected {incident.get('ddos_flows', 0)} DDoS flow(s), "
                f"attack share {incident.get('attack_share', 0):.2f}%, "
                f"average AI confidence {incident.get('average_confidence', 0):.2f}%. "
                "Analyst investigation is required."
            ),
            "incident_id": incident_id,
            "created_by": "AI-Net Automatic Correlation",
            "assigned_to": "SOC Queue",
            "sla_due_at": calculate_case_sla("CRITICAL"),
            "created_at": now,
            "updated_at": now
        }

        cases.insert(0, case)
        created.append(case)

    if created:
        save_case_store(cases)

    return created


@app.route("/soc_cases", methods=["GET", "POST", "PATCH", "DELETE"])
def soc_cases():
    """
    Defensive SOC case-management workspace.

    GET    -> list cases
    POST   -> create case
    PATCH  -> update status/priority/notes
    DELETE -> delete a case
    """
    if request.method != "GET":
        permission_error = viewer_read_only_guard()
        if permission_error:
            return permission_error

    try:
        cases = load_case_store()

        if request.method == "POST":
            payload = request.get_json(silent=True) or {}

            title = str(payload.get("title", "")).strip()
            source_ip = str(payload.get("source_ip", "")).strip()
            priority = str(payload.get("priority", "MEDIUM")).strip().upper()
            notes = str(payload.get("notes", "")).strip()

            if not title:
                return jsonify({
                    "success": False,
                    "error": "Case title is required."
                }), 400

            if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                return jsonify({
                    "success": False,
                    "error": "Invalid case priority."
                }), 400

            case_number = "CASE-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]

            case = {
                "case_id": case_number,
                "title": title,
                "source_ip": source_ip,
                "priority": priority,
                "status": "OPEN",
                "notes": notes,
                "assigned_to": str(payload.get("assigned_to", "SOC Queue")).strip() or "SOC Queue",
                "sla_due_at": calculate_case_sla(priority),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            cases.insert(0, case)
            save_case_store(cases)

            return jsonify({
                "success": True,
                "message": "SOC case created.",
                "case": case
            })

        if request.method == "PATCH":
            case_id = str(request.args.get("case_id", "")).strip()
            if not case_id:
                return jsonify({
                    "success": False,
                    "error": "case_id is required."
                }), 400

            payload = request.get_json(silent=True) or {}
            target = next(
                (case for case in cases if case.get("case_id") == case_id),
                None
            )

            if target is None:
                return jsonify({
                    "success": False,
                    "error": "Case not found."
                }), 404

            if "status" in payload:
                status = str(payload.get("status", "")).strip().upper()
                if status not in {"OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"}:
                    return jsonify({
                        "success": False,
                        "error": "Invalid case status."
                    }), 400
                target["status"] = status

            if "priority" in payload:
                priority = str(payload.get("priority", "")).strip().upper()
                if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                    return jsonify({
                        "success": False,
                        "error": "Invalid case priority."
                    }), 400
                target["priority"] = priority

            if "notes" in payload:
                target["notes"] = str(payload.get("notes", "")).strip()

            if "assigned_to" in payload:
                target["assigned_to"] = str(payload.get("assigned_to", "")).strip() or "SOC Queue"

            if "priority" in payload:
                target["sla_due_at"] = calculate_case_sla(target.get("priority", "MEDIUM"))

            target["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_case_store(cases)

            return jsonify({
                "success": True,
                "message": "SOC case updated.",
                "case": target
            })

        if request.method == "DELETE":
            case_id = str(request.args.get("case_id", "")).strip()
            before = len(cases)

            cases = [
                case for case in cases
                if case.get("case_id") != case_id
            ]

            if len(cases) == before:
                return jsonify({
                    "success": False,
                    "error": "Case not found."
                }), 404

            save_case_store(cases)

            return jsonify({
                "success": True,
                "message": "SOC case deleted."
            })

        # GET
        status_filter = str(request.args.get("status", "ALL")).strip().upper()
        priority_filter = str(request.args.get("priority", "ALL")).strip().upper()

        for case in cases:
            case.setdefault("assigned_to", "SOC Queue")
            if not case.get("sla_due_at"):
                case["sla_due_at"] = calculate_case_sla(case.get("priority", "MEDIUM"))

        filtered = cases

        if status_filter != "ALL":
            filtered = [
                case for case in filtered
                if str(case.get("status", "")).upper() == status_filter
            ]

        if priority_filter != "ALL":
            filtered = [
                case for case in filtered
                if str(case.get("priority", "")).upper() == priority_filter
            ]

        return jsonify({
            "success": True,
            "cases": filtered,
            "total_cases": len(cases),
            "open_cases": sum(
                1 for case in cases
                if case.get("status") in {"OPEN", "INVESTIGATING"}
            ),
            "critical_cases": sum(
                1 for case in cases
                if case.get("priority") == "CRITICAL"
                and case.get("status") != "CLOSED"
            ),
            "contained_cases": sum(
                1 for case in cases
                if case.get("status") == "CONTAINED"
            ),
            "closed_cases": sum(
                1 for case in cases
                if case.get("status") == "CLOSED"
            )
        })

    except Exception as error:
        print("SOC CASE ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not process SOC cases.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 42 — SOC CASE EVIDENCE & TIMELINE
# ============================================================

@app.route("/case_evidence", methods=["GET"])
def case_evidence():
    """Correlate a SOC case source IP with stored live telemetry."""
    try:
        case_id = str(request.args.get("case_id", "")).strip()
        if not case_id:
            return jsonify({"success": False, "error": "case_id is required."}), 400

        cases = load_case_store()
        case = next((c for c in cases if c.get("case_id") == case_id), None)
        if case is None:
            return jsonify({"success": False, "error": "Case not found."}), 404

        source_ip = str(case.get("source_ip", "")).strip()
        if not source_ip:
            return jsonify({
                "success": True,
                "available": False,
                "case": case,
                "message": "This case has no source IP attached, so telemetry evidence cannot be correlated."
            })

        rows = []
        live_log = LIVE_LOG if "LIVE_LOG" in globals() else os.path.join(LOG_DIR, "live_predictions.csv")
        if os.path.exists(live_log):
            try:
                df = pd.read_csv(live_log)
                df.columns = df.columns.astype(str).str.strip()
                source_col = next((c for c in ["Source IP", "Src IP", "SourceIP"] if c in df.columns), None)
                if source_col:
                    rows = df[df[source_col].astype(str).str.strip() == source_ip].to_dict(orient="records")
            except Exception as error:
                print("CASE EVIDENCE LOG ERROR:", str(error))

        total = len(rows)
        ddos = 0
        confidences = []
        destinations = {}
        protocols = {}
        evidence = []

        for row in rows:
            prediction = str(row.get("AI-Net Prediction", row.get("Prediction", ""))).strip()
            try:
                confidence = float(row.get("AI-Net Confidence (%)", row.get("Confidence (%)", row.get("Confidence", 0))))
            except Exception:
                confidence = 0.0
            if prediction.upper() == "DDOS":
                ddos += 1
                confidences.append(confidence)
            destination = str(row.get("Destination IP", row.get("Dst IP", ""))).strip()
            protocol = str(row.get("Protocol", "")).strip()
            if destination:
                destinations[destination] = destinations.get(destination, 0) + 1
            if protocol:
                protocols[protocol] = protocols.get(protocol, 0) + 1
            evidence.append({
                "timestamp": str(row.get("Timestamp", row.get("Time", ""))),
                "source_ip": source_ip,
                "destination_ip": destination,
                "protocol": protocol,
                "prediction": prediction or "UNKNOWN",
                "confidence": round(confidence, 2),
                "packets": row.get("Packets", row.get("Total Packets", 0))
            })

        evidence.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        attack_rate = (ddos / total * 100) if total else 0.0
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return jsonify({
            "success": True,
            "available": bool(rows),
            "case": case,
            "source_ip": source_ip,
            "total_flows": total,
            "ddos_flows": ddos,
            "attack_rate": round(attack_rate, 2),
            "average_attack_confidence": round(avg_confidence, 2),
            "top_destinations": [{"value": k, "flows": v} for k, v in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]],
            "protocol_distribution": [{"value": k, "flows": v} for k, v in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]],
            "evidence": evidence[:100]
        })
    except Exception as error:
        print("CASE EVIDENCE ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not build case evidence.", "details": str(error)}), 500


# ============================================================
# DAY 43 — SOC CASE REPORTING
# ============================================================

@app.route("/generate_case_report", methods=["GET"])
def generate_case_report():
    """Generate a professional PDF report for one SOC case."""
    try:
        case_id = str(request.args.get("case_id", "")).strip()
        if not case_id:
            return jsonify({"success": False, "error": "case_id is required."}), 400

        cases = load_case_store()
        case = next((c for c in cases if c.get("case_id") == case_id), None)
        if case is None:
            return jsonify({"success": False, "error": "Case not found."}), 404

        source_ip = str(case.get("source_ip", "")).strip()
        evidence = []
        if source_ip:
            try:
                df = pd.read_csv(LIVE_LOG)
                df.columns = df.columns.str.strip()
                if "Source IP" in df.columns:
                    matched = df[df["Source IP"].astype(str).str.strip() == source_ip].copy()
                    evidence = matched.to_dict("records")
            except Exception as error:
                print("CASE REPORT LOG ERROR:", str(error))

        total = len(evidence)
        ddos = sum(1 for row in evidence if str(row.get("AI-Net Prediction", "")).upper() == "DDOS")
        benign = total - ddos
        rate = (ddos / total * 100) if total else 0.0
        confidences = []
        for row in evidence:
            try:
                if str(row.get("AI-Net Prediction", "")).upper() == "DDOS":
                    confidences.append(float(row.get("AI-Net Confidence (%)", 0)))
            except Exception:
                pass
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

        destinations = {}
        protocols = {}
        for row in evidence:
            dst = str(row.get("Destination IP", "")).strip()
            proto = str(row.get("Protocol", "")).strip()
            if dst:
                destinations[dst] = destinations.get(dst, 0) + 1
            if proto:
                protocols[proto] = protocols.get(proto, 0) + 1

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

        report_dir = os.path.join(BASE_DIR, "logs", "reports")
        os.makedirs(report_dir, exist_ok=True)
        filename = f"{case_id}_security_report.pdf"
        filepath = os.path.join(report_dir, filename)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CaseTitle", parent=styles["Title"], alignment=TA_CENTER, fontSize=18, spaceAfter=14)
        heading = ParagraphStyle("CaseHeading", parent=styles["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=7)
        body = ParagraphStyle("CaseBody", parent=styles["BodyText"], fontSize=9, leading=13)

        story = [
            Paragraph("AI-Net SOC Security Case Report", title_style),
            Paragraph(f"Case ID: {case_id}", body),
            Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body),
            Spacer(1, 12),
            Paragraph("Case Summary", heading),
        ]

        summary = [
            ["Title", str(case.get("title", "-"))],
            ["Source IP", source_ip or "Not specified"],
            ["Priority", str(case.get("priority", "-"))],
            ["Status", str(case.get("status", "-"))],
            ["Created", str(case.get("created_at", "-"))],
            ["Updated", str(case.get("updated_at", "-"))],
            ["Notes", str(case.get("notes", "-") or "-")],
        ]
        t = Table(summary, colWidths=[95, 395])
        t.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#eff6ff")),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8.5),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 7),
            ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ]))
        story += [t, Spacer(1, 14), Paragraph("Telemetry Evidence", heading)]

        metrics = [
            ["Metric", "Value"],
            ["Observed flows", str(total)],
            ["DDoS flows", str(ddos)],
            ["BENIGN flows", str(benign)],
            ["Attack rate", f"{rate:.2f}%"],
            ["Average DDoS confidence", f"{avg_conf:.2f}%"],
        ]
        mt = Table(metrics, colWidths=[250, 240])
        mt.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1d4ed8")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8.5),
        ]))
        story += [mt, Spacer(1, 12)]

        if destinations:
            story.append(Paragraph("Top Targeted Destinations", heading))
            dt = [["Destination IP", "Flows"]] + [[k, str(v)] for k,v in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]]
            tab = Table(dt, colWidths=[350, 140])
            tab.setStyle(TableStyle([("GRID", (0,0), (-1,-1), .4, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eff6ff")), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8.5)]))
            story += [tab, Spacer(1, 10)]

        if protocols:
            story.append(Paragraph("Protocol Distribution", heading))
            pt = [["Protocol", "Flows"]] + [[k, str(v)] for k,v in sorted(protocols.items(), key=lambda x: x[1], reverse=True)]
            tab = Table(pt, colWidths=[350, 140])
            tab.setStyle(TableStyle([("GRID", (0,0), (-1,-1), .4, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eff6ff")), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8.5)]))
            story += [tab, Spacer(1, 10)]

        story += [
            Paragraph("Security Assessment", heading),
            Paragraph(
                (f"The case contains {ddos} DDoS flow(s) across {total} observed flow(s), "
                 f"with an attack rate of {rate:.2f}% and average DDoS confidence of {avg_conf:.2f}%. "
                 "Analysts should use the telemetry evidence and case lifecycle to document investigation, containment, and closure decisions."),
                body
            )
        ]

        doc = SimpleDocTemplate(filepath, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        doc.build(story)
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype="application/pdf")

    except Exception as error:
        print("CASE REPORT ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not generate case report.", "details": str(error)}), 500

# ------------------------------------------------------------
# START LIVE CAPTURE
# ------------------------------------------------------------

@app.route("/live_capture/start", methods=["POST"])
@role_required("SOC Analyst", "Admin")
def start_live_capture():
    if model is None:
        return jsonify({
            "success": False,
            "error": "Machine learning model is not loaded."
        }), 500

    try:
        data = request.get_json(
            silent=True
        ) or {}

        interface = data.get("interface")

        if interface is not None:
            interface = str(interface).strip()
            if interface == "":
                interface = None

        success, message = live_capture_start(
            interface=interface
        )

        return jsonify({
            "success": success,
            "message": message,
            "status": live_capture_status,
            "interface": live_capture_interface,
            "error": live_capture_error
        }), (200 if success else 500)

    except Exception as error:
        return jsonify({
            "success": False,
            "error": "Could not start live packet capture.",
            "details": str(error)
        }), 500


# ------------------------------------------------------------
# STOP LIVE CAPTURE
# ------------------------------------------------------------

@app.route("/live_capture/stop", methods=["POST"])
@role_required("SOC Analyst", "Admin")
def stop_live_capture():
    try:
        success, message = live_capture_stop()

        return jsonify({
            "success": success,
            "message": message,
            "status": live_capture_status,
            "error": live_capture_error
        }), (200 if success else 400)

    except Exception as error:
        return jsonify({
            "success": False,
            "error": "Could not stop live packet capture.",
            "details": str(error)
        }), 500


# ------------------------------------------------------------
# LIVE CAPTURE STATUS
# ------------------------------------------------------------

@app.route("/live_capture/status", methods=["GET"])
def live_capture_status_api():
    running = False

    try:
        if live_sniffer is not None:
            running = bool(
                live_sniffer.running
            )
    except Exception:
        running = False

    if not running and live_capture_status == "running":
        live_capture_status_local = "stopped"
    else:
        live_capture_status_local = live_capture_status

    stats = get_live_statistics()

    return jsonify({
        "success": True,
        "status": live_capture_status_local,
        "running": running,
        "interface": live_capture_interface,
        "started_at": live_capture_started_at,
        "error": live_capture_error,
        "total": stats["total"],
        "benign": stats["benign"],
        "ddos": stats["ddos"],
        "attack_rate": round(
            stats["attack_rate"],
            2
        ),
        "updated_at": stats["updated_at"],
        "analysis_available": stats["available"]
    })


# ------------------------------------------------------------
# DASHBOARD MONITOR STATUS
# ------------------------------------------------------------

@app.route("/monitor_status", methods=["GET"])
def monitor_status():
    """
    Dashboard monitoring endpoint.

    When real packet capture has produced predictions, those live
    predictions are reported. Otherwise the endpoint falls back to
    the latest CSV analysis so the existing dashboard remains useful.
    """
    live_stats = get_live_statistics()

    if live_stats["available"]:
        return jsonify({
            "success": True,
            "source": "live_packet_capture",
            "capture_status": live_capture_status,
            "running": (
                bool(live_sniffer.running)
                if live_sniffer is not None
                else False
            ),
            "analysis_available": True,
            "total": live_stats["total"],
            "benign": live_stats["benign"],
            "ddos": live_stats["ddos"],
            "attack_rate": round(
                live_stats["attack_rate"],
                2
            ),
            "updated_at": live_stats["updated_at"]
        })

    # Fallback to the existing saved CSV analysis.
    if os.path.exists(CSV_LOG):
        try:
            results = pd.read_csv(
                CSV_LOG,
                usecols=[
                    "AI-Net Prediction",
                    "AI-Net Confidence (%)"
                ]
            )

            if not results.empty:
                labels = results["AI-Net Prediction"].apply(
                    convert_prediction_to_label
                )

                total = len(results)
                benign = int(
                    (labels == "BENIGN").sum()
                )
                ddos = int(
                    (labels == "DDoS").sum()
                )

                updated_at = datetime.fromtimestamp(
                    os.path.getmtime(CSV_LOG)
                ).isoformat()

                return jsonify({
                    "success": True,
                    "source": "csv_analysis",
                    "capture_status": "stopped",
                    "running": False,
                    "analysis_available": True,
                    "total": total,
                    "benign": benign,
                    "ddos": ddos,
                    "attack_rate": round(
                        ddos / total * 100
                        if total > 0
                        else 0,
                        2
                    ),
                    "updated_at": updated_at
                })

        except Exception as error:
            print("MONITOR STATUS ERROR:", str(error))

    return jsonify({
        "success": True,
        "source": "none",
        "capture_status": live_capture_status,
        "running": False,
        "analysis_available": False,
        "total": 0,
        "benign": 0,
        "ddos": 0,
        "attack_rate": 0.0,
        "updated_at": None
    })






# ============================================================
# RESTORED DASHBOARD API ROUTES
# ============================================================
@app.route("/traffic_volume", methods=["GET"])
def traffic_volume():
    """
    Return time-bucketed flow-rate analytics from the newest
    live capture log, falling back to the latest CSV analysis.
    This measures analyzed flows per time bucket, not raw bytes/sec.
    """
    try:
        source_file = None
        source = "none"

        if os.path.exists(LIVE_LOG):
            source_file = LIVE_LOG
            source = "live_packet_capture"
        elif os.path.exists(CSV_LOG):
            source_file = CSV_LOG
            source = "csv_analysis"

        if source_file is None:
            return jsonify({
                "success": True,
                "source": "none",
                "total_flows": 0,
                "peak_flows_per_second": 0.0,
                "average_flows_per_second": 0.0,
                "current_flows_per_second": 0.0,
                "ddos_flows": 0,
                "points": []
            })

        header = pd.read_csv(source_file, nrows=0)
        available = set(header.columns)

        required = ["Timestamp", "AI-Net Prediction"]
        if not all(column in available for column in required):
            return jsonify({
                "success": False,
                "error": "Traffic analytics log is missing required columns."
            }), 500

        selected = [
            column for column in [
                "Timestamp",
                "AI-Net Prediction",
                "Flow Duration"
            ]
            if column in available
        ]

        # Only the latest 5000 records are needed for dashboard analytics.
        df = pd.read_csv(
            source_file,
            usecols=selected,
            skiprows=lambda x: False
        )

        if df.empty:
            return jsonify({
                "success": True,
                "source": source,
                "total_flows": 0,
                "peak_flows_per_second": 0.0,
                "average_flows_per_second": 0.0,
                "current_flows_per_second": 0.0,
                "ddos_flows": 0,
                "points": []
            })

        if len(df) > 5000:
            df = df.tail(5000).copy()

        timestamps = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )
        df = df.loc[timestamps.notna()].copy()
        df["__time"] = timestamps.loc[df.index]

        if df.empty:
            return jsonify({
                "success": True,
                "source": source,
                "total_flows": 0,
                "peak_flows_per_second": 0.0,
                "average_flows_per_second": 0.0,
                "current_flows_per_second": 0.0,
                "ddos_flows": 0,
                "points": []
            })

        # One-second buckets give a useful live flow-rate view.
        grouped = (
            df.set_index("__time")
              .assign(
                  ddos=lambda x: x["AI-Net Prediction"].apply(
                      lambda value: str(value).strip().lower() in {
                          "ddos", "1", "attack", "true"
                      }
                  )
              )
              .resample("1s")
              .agg(
                  flows=("AI-Net Prediction", "size"),
                  ddos=("ddos", "sum")
              )
              .reset_index()
        )

        grouped = grouped[grouped["flows"] > 0].tail(30)

        points = []
        for _, row in grouped.iterrows():
            points.append({
                "timestamp": row["__time"].isoformat(),
                "flows": int(row["flows"]),
                "ddos": int(row["ddos"])
            })

        if points:
            rates = [float(point["flows"]) for point in points]
            peak_rate = max(rates)
            average_rate = sum(rates) / len(rates)
            current_rate = rates[-1]
        else:
            peak_rate = average_rate = current_rate = 0.0

        labels = df["AI-Net Prediction"].astype(str).str.strip().str.lower()
        ddos_total = int(
            labels.isin({"ddos", "1", "attack", "true"}).sum()
        )

        return jsonify({
            "success": True,
            "source": source,
            "total_flows": int(len(df)),
            "peak_flows_per_second": round(peak_rate, 2),
            "average_flows_per_second": round(average_rate, 2),
            "current_flows_per_second": round(current_rate, 2),
            "ddos_flows": ddos_total,
            "points": points
        })

    except Exception as error:
        print("TRAFFIC VOLUME ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load traffic volume analytics.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 15 — THREAT INTELLIGENCE & ATTACK INSIGHTS API
# ============================================================

@app.route("/threat_intelligence", methods=["GET"])
def threat_intelligence():
    """Return aggregated threat-intelligence insights from the newest log."""
    try:
        if os.path.exists(LIVE_LOG):
            source_file = LIVE_LOG
            source = "live_packet_capture"
        elif os.path.exists(CSV_LOG):
            source_file = CSV_LOG
            source = "csv_analysis"
        else:
            return jsonify({
                "success": True,
                "source": "none",
                "available": False,
                "message": "No detection data is available yet.",
                "total_flows": 0,
                "ddos_flows": 0,
                "benign_flows": 0,
                "attack_rate": 0.0,
                "average_attack_confidence": 0.0,
                "top_source_ips": [],
                "top_destination_ips": [],
                "protocol_distribution": [],
                "severity": "LOW",
                "threat_level": "LOW"
            })

        header = pd.read_csv(source_file, nrows=0)
        header.columns = header.columns.astype(str).str.strip()
        available = set(header.columns)

        prediction_col = next(
            (c for c in ["AI-Net Prediction", "Prediction", "prediction", "Label"]
             if c in available),
            None
        )
        confidence_col = next(
            (c for c in ["AI-Net Confidence (%)", "Confidence", "confidence"]
             if c in available),
            None
        )
        source_col = next(
            (c for c in ["Source IP", "src_ip", "Source"] if c in available),
            None
        )
        destination_col = next(
            (c for c in ["Destination IP", "dst_ip", "Destination"] if c in available),
            None
        )
        protocol_col = next(
            (c for c in ["Protocol", "protocol"] if c in available),
            None
        )

        if prediction_col is None:
            return jsonify({
                "success": False,
                "error": "Detection log is missing the prediction column."
            }), 500

        selected = [prediction_col]
        for column in [confidence_col, source_col, destination_col, protocol_col]:
            if column and column not in selected:
                selected.append(column)

        df = pd.read_csv(source_file, usecols=selected)

        if df.empty:
            return jsonify({
                "success": True,
                "source": source,
                "available": False,
                "message": "Detection log is empty.",
                "total_flows": 0,
                "ddos_flows": 0,
                "benign_flows": 0,
                "attack_rate": 0.0,
                "average_attack_confidence": 0.0,
                "top_source_ips": [],
                "top_destination_ips": [],
                "protocol_distribution": [],
                "severity": "LOW",
                "threat_level": "LOW"
            })

        labels = df[prediction_col].apply(convert_prediction_to_label)
        total = int(len(df))
        ddos_mask = labels == "DDoS"
        benign_mask = labels == "BENIGN"
        ddos_count = int(ddos_mask.sum())
        benign_count = int(benign_mask.sum())
        attack_rate = (ddos_count / total * 100) if total else 0.0

        if confidence_col:
            confidence = pd.to_numeric(
                df.loc[ddos_mask, confidence_col], errors="coerce"
            ).dropna()
            average_attack_confidence = (
                float(confidence.mean()) if not confidence.empty else 0.0
            )
        else:
            average_attack_confidence = 0.0

        def top_values(column, mask, limit=5):
            if not column:
                return []
            values = (
                df.loc[mask, column]
                .astype(str)
                .str.strip()
            )
            values = values[
                (values != "") &
                (~values.str.lower().isin({"nan", "none", "unknown"}))
            ]
            counts = values.value_counts().head(limit)
            return [
                {"value": str(value), "count": int(count)}
                for value, count in counts.items()
            ]

        top_source_ips = top_values(source_col, ddos_mask)
        top_destination_ips = top_values(destination_col, ddos_mask)

        protocol_distribution = []
        if protocol_col:
            protocol_values = (
                df.loc[ddos_mask, protocol_col]
                .astype(str)
                .str.strip()
                .str.upper()
            )
            protocol_values = protocol_values[
                (protocol_values != "") &
                (~protocol_values.isin({"NAN", "NONE", "UNKNOWN"}))
            ]
            protocol_counts = protocol_values.value_counts().head(6)
            protocol_distribution = [
                {"protocol": str(value), "count": int(count)}
                for value, count in protocol_counts.items()
            ]

        if attack_rate >= 50 or ddos_count >= 100:
            threat_level = "CRITICAL"
        elif attack_rate >= 10 or ddos_count >= 20:
            threat_level = "HIGH"
        elif attack_rate > 0:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        if average_attack_confidence >= 95 and ddos_count > 0:
            severity = "CRITICAL"
        elif ddos_count > 0 and average_attack_confidence >= 80:
            severity = "HIGH"
        elif ddos_count > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Composite risk score for dashboard/SOC-style prioritization.
        # Attack rate contributes 60%; model confidence contributes 40%.
        risk_score = 0.0
        if ddos_count > 0:
            normalized_attack_rate = min(attack_rate, 100.0)
            risk_score = (normalized_attack_rate * 0.60) + (average_attack_confidence * 0.40)
            risk_score = min(max(risk_score, 0.0), 100.0)

        # Keep the risk band aligned with the dashboard threat hierarchy.
        if risk_score >= 70:
            risk_band = "CRITICAL"
        elif risk_score >= 40:
            risk_band = "HIGH"
        elif risk_score >= 15:
            risk_band = "MEDIUM"
        else:
            risk_band = "LOW"

        if risk_band == "CRITICAL":
            recommended_action = (
                "Immediately investigate top attacking source IPs, protect exposed services, "
                "and apply DDoS mitigation or rate-limiting controls."
            )
        elif risk_band == "HIGH":
            recommended_action = (
                "Investigate suspicious source IPs, review affected services, and prepare DDoS mitigation controls."
            )
        elif risk_band == "MEDIUM":
            recommended_action = (
                "Review anomalous flows and continue active monitoring for escalation."
            )
        else:
            recommended_action = (
                "Continue live monitoring. No significant DDoS risk is currently present in the analyzed flows."
            )

        return jsonify({
            "success": True,
            "available": True,
            "source": source,
            "total_flows": total,
            "ddos_flows": ddos_count,
            "benign_flows": benign_count,
            "attack_rate": round(attack_rate, 2),
            "average_attack_confidence": round(average_attack_confidence, 2),
            "top_source_ips": top_source_ips,
            "top_destination_ips": top_destination_ips,
            "protocol_distribution": protocol_distribution,
            "attack_type": "DDoS" if ddos_count > 0 else "None detected",
            "risk_score": round(risk_score, 2),
            "risk_band": risk_band,
            "recommended_action": recommended_action,
            "severity": severity,
            "threat_level": threat_level
        })

    except Exception as error:
        print("THREAT INTELLIGENCE ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load threat-intelligence analytics.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 20 — ATTACK SOURCE INTELLIGENCE
# ============================================================

@app.route("/attack_source_intelligence", methods=["GET"])
def attack_source_intelligence():
    """
    Return ranked DDoS source/destination intelligence.

    If both live and CSV logs exist, prefer the log that actually contains
    DDoS detections. This prevents a stale/benign live-capture log from
    hiding a newly analyzed DDoS CSV.
    """
    try:
        candidates = []

        for path, source_name in [
            (LIVE_LOG, "live_packet_capture"),
            (CSV_LOG, "csv_analysis")
        ]:
            if not os.path.exists(path):
                continue

            try:
                header = pd.read_csv(path, nrows=0)
                header.columns = header.columns.astype(str).str.strip()

                prediction_col = next(
                    (
                        c for c in
                        ["AI-Net Prediction", "Prediction", "prediction", "Label"]
                        if c in header.columns
                    ),
                    None
                )

                if prediction_col is None:
                    continue

                probe = pd.read_csv(
                    path,
                    usecols=[prediction_col]
                )

                labels = probe[prediction_col].apply(
                    convert_prediction_to_label
                )

                ddos_count = int(
                    (labels == "DDoS").sum()
                )

                candidates.append({
                    "path": path,
                    "source": source_name,
                    "ddos_count": ddos_count,
                    "total": int(len(probe))
                })

            except Exception as probe_error:
                print(
                    f"ATTACK SOURCE PROBE ERROR ({source_name}):",
                    str(probe_error)
                )

        if not candidates:
            return jsonify({
                "success": True,
                "available": False,
                "source": "none",
                "attack_type": "None detected",
                "total_ddos_flows": 0,
                "top_sources": [],
                "top_destinations": [],
                "source_details": [],
                "message": "No detection data is available yet."
            })

        # Prefer the newest/current dataset containing DDoS.
        # If both contain DDoS, prefer the one with more DDoS detections.
        # If neither contains DDoS, prefer the live capture.
        ddos_candidates = [
            item for item in candidates
            if item["ddos_count"] > 0
        ]

        if ddos_candidates:
            selected = max(
                ddos_candidates,
                key=lambda item: (
                    item["ddos_count"],
                    os.path.getmtime(item["path"])
                )
            )
        else:
            selected = next(
                (
                    item for item in candidates
                    if item["source"] == "live_packet_capture"
                ),
                max(
                    candidates,
                    key=lambda item: os.path.getmtime(item["path"])
                )
            )

        source_file = selected["path"]
        source = selected["source"]

        header = pd.read_csv(
            source_file,
            nrows=0
        )
        header.columns = header.columns.astype(str).str.strip()
        available = set(header.columns)

        prediction_col = next(
            (
                c for c in
                ["AI-Net Prediction", "Prediction", "prediction", "Label"]
                if c in available
            ),
            None
        )

        confidence_col = next(
            (
                c for c in
                ["AI-Net Confidence (%)", "Confidence", "confidence"]
                if c in available
            ),
            None
        )

        source_col = next(
            (
                c for c in
                ["Source IP", "src_ip", "Source", "Src IP"]
                if c in available
            ),
            None
        )

        destination_col = next(
            (
                c for c in
                ["Destination IP", "dst_ip", "Destination", "Dst IP"]
                if c in available
            ),
            None
        )

        protocol_col = next(
            (
                c for c in
                ["Protocol", "protocol"]
                if c in available
            ),
            None
        )

        if prediction_col is None:
            return jsonify({
                "success": False,
                "error": "Detection log is missing the prediction column."
            }), 500

        selected_columns = [prediction_col]

        for column in [
            confidence_col,
            source_col,
            destination_col,
            protocol_col
        ]:
            if column and column not in selected_columns:
                selected_columns.append(column)

        df = pd.read_csv(
            source_file,
            usecols=selected_columns
        )

        labels = df[prediction_col].apply(
            convert_prediction_to_label
        )

        ddos_df = df[labels == "DDoS"].copy()
        total_ddos = int(len(ddos_df))

        def clean_series(series):
            values = (
                series
                .astype(str)
                .str.strip()
            )

            return values[
                (values != "") &
                (~values.str.lower().isin({
                    "nan",
                    "none",
                    "unknown"
                }))
            ]

        def ranked_entities(column, limit=10):
            if not column or ddos_df.empty:
                return []

            values = clean_series(
                ddos_df[column]
            )

            counts = (
                values
                .value_counts()
                .head(limit)
            )

            results = []

            for rank, (value, count) in enumerate(
                counts.items(),
                start=1
            ):
                results.append({
                    "rank": rank,
                    "value": str(value),
                    "ddos_flows": int(count),
                    "attack_share": round(
                        (int(count) / total_ddos * 100),
                        2
                    ) if total_ddos else 0.0
                })

            return results

        def source_details():
            if not source_col or ddos_df.empty:
                return []

            values = clean_series(
                ddos_df[source_col]
            )

            counts = (
                values
                .value_counts()
                .head(10)
            )

            rows = []

            for rank, (value, count) in enumerate(
                counts.items(),
                start=1
            ):
                mask = (
                    ddos_df[source_col]
                    .astype(str)
                    .str.strip()
                    == str(value)
                )

                subset = ddos_df.loc[mask]

                confidence_value = 0.0

                if confidence_col:
                    conf = pd.to_numeric(
                        subset[confidence_col],
                        errors="coerce"
                    ).dropna()

                    if not conf.empty:
                        confidence_value = float(
                            conf.mean()
                        )

                protocols = []

                if protocol_col:
                    protocol_values = clean_series(
                        subset[protocol_col]
                        .astype(str)
                        .str.upper()
                    )

                    protocols = [
                        str(protocol)
                        for protocol in
                        protocol_values
                        .value_counts()
                        .head(3)
                        .index
                    ]

                try:
                    ip_obj = ipaddress.ip_address(str(value))
                    ip_scope = "Internal" if (
                        ip_obj.is_private or
                        ip_obj.is_loopback or
                        ip_obj.is_link_local
                    ) else "External"
                except ValueError:
                    ip_scope = "Unknown"

                source_attack_share = round(
                    (int(count) / total_ddos * 100),
                    2
                ) if total_ddos else 0.0

                if source_attack_share >= 75 or int(count) >= 20:
                    local_classification = "High Risk"
                elif source_attack_share >= 25 or int(count) >= 5:
                    local_classification = "Suspicious"
                else:
                    local_classification = "Low Risk"

                rows.append({
                    "rank": rank,
                    "source_ip": str(value),
                    "ddos_flows": int(count),
                    "attack_share": source_attack_share,
                    "average_confidence": round(
                        confidence_value,
                        2
                    ),
                    "protocols": protocols,
                    "ip_scope": ip_scope,
                    "classification": local_classification,
                    "investigation_endpoint":
                        "/source_investigation?source_ip="
                        + str(value)
                })

            return rows

        return jsonify({
            "success": True,
            "available": total_ddos > 0,
            "source": source,
            "attack_type": (
                "DDoS"
                if total_ddos > 0
                else "None detected"
            ),
            "total_ddos_flows": total_ddos,
            "top_sources": ranked_entities(
                source_col
            ),
            "top_destinations": ranked_entities(
                destination_col
            ),
            "source_details": source_details(),
            "message": (
                "DDoS source intelligence generated successfully."
                if total_ddos > 0
                else
                "No DDoS flows are present in the current detection data."
            )
        })

    except Exception as error:
        print(
            "ATTACK SOURCE INTELLIGENCE ERROR:",
            str(error)
        )

        return jsonify({
            "success": False,
            "error": "Could not load attack-source intelligence.",
            "details": str(error)
        }), 500

@app.route("/incident_correlation", methods=["GET"])
def incident_correlation():
    """
    Correlate live DDoS detections into incident-style security events.

    This uses only AI-Net live telemetry. It does not claim external
    reputation, attribution, or geolocation.
    """
    try:
        if not os.path.exists(LIVE_LOG):
            return jsonify({
                "success": True,
                "available": False,
                "incidents": [],
                "message": "No live packet-capture detections are available."
            })

        header = pd.read_csv(LIVE_LOG, nrows=0)
        header.columns = header.columns.astype(str).str.strip()
        available = set(header.columns)

        prediction_col = next(
            (c for c in [
                "AI-Net Prediction", "Prediction", "prediction", "Label"
            ] if c in available),
            None
        )
        confidence_col = next(
            (c for c in [
                "AI-Net Confidence (%)", "Confidence", "confidence"
            ] if c in available),
            None
        )
        timestamp_col = next(
            (c for c in ["Timestamp", "timestamp"] if c in available),
            None
        )
        source_col = next(
            (c for c in ["Source IP", "src_ip", "Source", "Src IP"]
             if c in available),
            None
        )
        destination_col = next(
            (c for c in [
                "Destination IP", "dst_ip", "Destination", "Dst IP"
            ] if c in available),
            None
        )
        protocol_col = next(
            (c for c in ["Protocol", "protocol"] if c in available),
            None
        )
        source_port_col = next(
            (c for c in ["Source Port", "src_port"] if c in available),
            None
        )
        destination_port_col = next(
            (c for c in ["Destination Port", "dst_port"] if c in available),
            None
        )

        if not prediction_col:
            return jsonify({
                "success": False,
                "error": "Live detection log is missing prediction data."
            }), 500

        columns = [prediction_col]
        for column in [
            timestamp_col, source_col, destination_col,
            protocol_col, source_port_col, destination_port_col,
            confidence_col
        ]:
            if column and column not in columns:
                columns.append(column)

        df = pd.read_csv(LIVE_LOG, usecols=columns)

        labels = df[prediction_col].apply(convert_prediction_to_label)
        ddos = df[labels == "DDoS"].copy()

        if ddos.empty:
            return jsonify({
                "success": True,
                "available": False,
                "incidents": [],
                "message": "No DDoS detections are present in the current live capture."
            })

        # Build incidents around each observed source IP.
        incidents = []

        source_values = (
            ddos[source_col].astype(str).str.strip().value_counts()
            if source_col else pd.Series(dtype="int64")
        )

        if source_values.empty:
            source_values = pd.Series(
                {"Unknown": len(ddos)}
            )

        total_ddos = len(ddos)

        for rank, (source_ip, count) in enumerate(
            source_values.head(10).items(), start=1
        ):
            if source_col:
                subset = ddos[
                    ddos[source_col].astype(str).str.strip() == str(source_ip)
                ]
            else:
                subset = ddos

            confidence = 0.0
            if confidence_col:
                conf = pd.to_numeric(
                    subset[confidence_col], errors="coerce"
                ).dropna()
                if not conf.empty:
                    confidence = float(conf.mean())

            attack_share = (
                float(count) / total_ddos * 100
                if total_ddos else 0.0
            )

            if attack_share >= 50 or count >= 20:
                incident_level = "CRITICAL"
            elif attack_share >= 20 or count >= 10:
                incident_level = "HIGH"
            else:
                incident_level = "MEDIUM"

            destinations = []
            if destination_col:
                destinations = [
                    str(x)
                    for x in subset[destination_col]
                    .astype(str).str.strip()
                    .value_counts().head(5).index
                ]

            protocols = []
            if protocol_col:
                protocols = [
                    str(x).upper()
                    for x in subset[protocol_col]
                    .astype(str).str.strip()
                    .value_counts().head(5).index
                ]

            latest_timestamp = None
            if timestamp_col:
                values = subset[timestamp_col].dropna().astype(str)
                if not values.empty:
                    latest_timestamp = values.iloc[-1]

            incidents.append({
                "incident_id": f"AINET-DDoS-{rank:03d}",
                "timestamp": latest_timestamp,
                "source_ip": str(source_ip),
                "destination_ips": destinations,
                "protocols": protocols,
                "ddos_flows": int(count),
                "attack_share": round(attack_share, 2),
                "average_confidence": round(confidence, 2),
                "level": incident_level,
                "attack_type": "DDoS",
                "status": (
                    "Investigate immediately"
                    if incident_level == "CRITICAL"
                    else "Review source activity"
                    if incident_level == "HIGH"
                    else "Continue monitoring"
                )
            })

        # Automatically open a SOC case for newly observed critical DDoS incidents.
        try:
            auto_created_cases = auto_create_soc_cases(incidents)
        except Exception as case_error:
            auto_created_cases = []
            print("AUTO SOC CASE WARNING:", str(case_error))

        # Persist a compact incident snapshot for audit/history.
        try:
            incident_rows = []
            for item in incidents:
                incident_rows.append({
                    "Timestamp": item["timestamp"],
                    "Incident ID": item["incident_id"],
                    "Source IP": item["source_ip"],
                    "Attack Type": item["attack_type"],
                    "DDoS Flows": item["ddos_flows"],
                    "Attack Share (%)": item["attack_share"],
                    "Average Confidence (%)": item["average_confidence"],
                    "Level": item["level"],
                    "Status": item["status"]
                })

            pd.DataFrame(incident_rows).to_csv(
                INCIDENT_LOG,
                index=False
            )
        except Exception as persist_error:
            print("INCIDENT LOG SAVE WARNING:", str(persist_error))

        # Day 48.3 — persist correlated incidents and initialize SLA deadlines.
        try:
            conn = get_db()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for item in incidents:
                incident_id = item["incident_id"]
                existing = conn.execute(
                    "SELECT lifecycle_status, assigned_to, resolution_note, first_seen, escalation_level FROM security_incidents WHERE incident_id = ?",
                    (incident_id,)
                ).fetchone()
                first_seen = (existing["first_seen"] if existing else None) or item.get("timestamp") or now
                due = _ensure_incident_sla(conn, incident_id, item["level"], first_seen) if existing else None
                if existing:
                    conn.execute("""
                        UPDATE security_incidents
                        SET source_ip = ?, level = ?, attack_count = ?, attack_share = ?,
                            last_seen = ?, updated_at = ?, first_seen = ?,
                            sla_status = ?
                        WHERE incident_id = ?
                    """, (
                        item["source_ip"], item["level"], item["ddos_flows"], item["attack_share"],
                        item.get("timestamp") or now, now, first_seen,
                        _sla_status(item["level"], due or existing.get("sla_due_at"), existing["lifecycle_status"]),
                        incident_id
                    ))
                else:
                    due = ( _parse_dt(first_seen) or datetime.now() ) + timedelta(hours=_sla_hours_for_level(item["level"]))
                    due_text = due.strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute("""
                        INSERT INTO security_incidents
                        (incident_id, source_ip, level, attack_count, total_flows, attack_share,
                         created_at, updated_at, lifecycle_status, assigned_to, resolution_note,
                         first_seen, last_seen, sla_due_at, sla_status, escalation_level)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, 'ON_TRACK', 0)
                    """, (
                        incident_id, item["source_ip"], item["level"], item["ddos_flows"],
                        0, item["attack_share"], item.get("timestamp") or now, now,
                        None, None, first_seen, item.get("timestamp") or now, due_text
                    ))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print("INCIDENT SLA DATABASE WARNING:", str(db_error))

        return jsonify({
            "success": True,
            "available": True,
            "source": "live_packet_capture",
            "total_ddos_flows": int(total_ddos),
            "incident_count": len(incidents),
            "incidents": incidents,
            "auto_created_case_count": len(auto_created_cases),
            "auto_created_cases": auto_created_cases,
            "message": (
                "Live DDoS detections correlated into incident records."
            )
        })

    except Exception as error:
        print("INCIDENT CORRELATION ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not correlate live security incidents.",
            "details": str(error)
        }), 500

@app.route("/incident_response", methods=["GET", "POST"])
def incident_response():
    """
    Incident Response Center.

    POST records a SAFE/SIMULATION response action. It does not alter
    firewall, routing, operating-system, or network configuration.
    """
    if request.method != "GET":
        permission_error = viewer_read_only_guard()
        if permission_error:
            return permission_error

    try:
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}

            source_ip = str(payload.get("source_ip", "")).strip()
            action = str(payload.get("action", "")).strip().lower()

            allowed_actions = {
                "block_source": "Block suspicious source (Simulation)",
                "rate_limit": "Apply DDoS rate limiting (Simulation)",
                "monitor": "Continue enhanced monitoring",
                "investigate_destination": "Investigate affected destination",
                "mark_reviewed": "Mark incident as reviewed"
            }

            if action not in allowed_actions:
                return jsonify({
                    "success": False,
                    "error": "Unsupported response action."
                }), 400

            if not source_ip:
                source_ip = "Unknown"

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            row = {
                "Timestamp": now,
                "Source IP": source_ip,
                "Action": allowed_actions[action],
                "Mode": "SIMULATION",
                "Status": "Recorded"
            }

            file_exists = os.path.exists(INCIDENT_RESPONSE_LOG)

            with open(
                INCIDENT_RESPONSE_LOG,
                "a",
                newline="",
                encoding="utf-8"
            ) as response_file:
                writer = csv.DictWriter(
                    response_file,
                    fieldnames=list(row.keys())
                )

                if not file_exists:
                    writer.writeheader()

                writer.writerow(row)

            return jsonify({
                "success": True,
                "mode": "SIMULATION",
                "status": "Recorded",
                "source_ip": source_ip,
                "action": allowed_actions[action],
                "timestamp": now,
                "message": (
                    "Response action recorded in simulation mode. "
                    "No real network blocking or rate limiting was performed."
                )
            })

        # GET: return latest recorded response actions.
        if not os.path.exists(INCIDENT_RESPONSE_LOG):
            return jsonify({
                "success": True,
                "actions": []
            })

        response_df = pd.read_csv(INCIDENT_RESPONSE_LOG)
        response_df.columns = response_df.columns.astype(str).str.strip()

        actions = []
        for _, row in response_df.tail(20).iloc[::-1].iterrows():
            actions.append({
                "timestamp": str(row.get("Timestamp", "")),
                "source_ip": str(row.get("Source IP", "Unknown")),
                "action": str(row.get("Action", "")),
                "mode": str(row.get("Mode", "SIMULATION")),
                "status": str(row.get("Status", "Recorded"))
            })

        return jsonify({
            "success": True,
            "actions": actions
        })

    except Exception as error:
        print("INCIDENT RESPONSE ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not process incident response action.",
            "details": str(error)
        }), 500

@app.route("/incident_dashboard", methods=["GET"])
def incident_dashboard():
    """
    Return a compact SOC incident dashboard.

    Status is derived from AI-Net's live correlated detections and the
    locally recorded response-action history. No external reputation
    or attribution is inferred.
    """
    try:
        incidents = []
        incident_count = 0

        # Reuse the live correlation data from the same log.
        if os.path.exists(LIVE_LOG):
            header = pd.read_csv(LIVE_LOG, nrows=0)
            header.columns = header.columns.astype(str).str.strip()
            available = set(header.columns)

            prediction_col = next(
                (c for c in [
                    "AI-Net Prediction", "Prediction", "prediction", "Label"
                ] if c in available),
                None
            )
            confidence_col = next(
                (c for c in [
                    "AI-Net Confidence (%)", "Confidence", "confidence"
                ] if c in available),
                None
            )
            timestamp_col = next(
                (c for c in ["Timestamp", "timestamp"] if c in available),
                None
            )
            source_col = next(
                (c for c in [
                    "Source IP", "src_ip", "Source", "Src IP"
                ] if c in available),
                None
            )

            if prediction_col:
                columns = [prediction_col]
                for column in [
                    timestamp_col, source_col, confidence_col
                ]:
                    if column and column not in columns:
                        columns.append(column)

                df = pd.read_csv(LIVE_LOG, usecols=columns)
                labels = df[prediction_col].apply(
                    convert_prediction_to_label
                )
                ddos = df[labels == "DDoS"].copy()

                if not ddos.empty:
                    incident_count = 0

                    if source_col:
                        grouped = (
                            ddos[source_col]
                            .astype(str)
                            .str.strip()
                            .value_counts()
                            .head(10)
                        )
                    else:
                        grouped = pd.Series({"Unknown": len(ddos)})

                    total_ddos = len(ddos)

                    for rank, (source_ip, count) in enumerate(
                        grouped.items(), start=1
                    ):
                        subset = (
                            ddos[
                                ddos[source_col].astype(str).str.strip()
                                == str(source_ip)
                            ]
                            if source_col
                            else ddos
                        )

                        confidence = 0.0
                        if confidence_col:
                            conf = pd.to_numeric(
                                subset[confidence_col],
                                errors="coerce"
                            ).dropna()
                            if not conf.empty:
                                confidence = float(conf.mean())

                        attack_share = (
                            float(count) / total_ddos * 100
                            if total_ddos else 0.0
                        )

                        if attack_share >= 50 or count >= 20:
                            level = "CRITICAL"
                        elif attack_share >= 20 or count >= 10:
                            level = "HIGH"
                        else:
                            level = "MEDIUM"

                        latest = None
                        if timestamp_col:
                            values = subset[timestamp_col].dropna().astype(str)
                            if not values.empty:
                                latest = values.iloc[-1]

                        incidents.append({
                            "incident_id": f"AINET-DDoS-{rank:03d}",
                            "source_ip": str(source_ip),
                            "level": level,
                            "ddos_flows": int(count),
                            "attack_share": round(attack_share, 2),
                            "average_confidence": round(confidence, 2),
                            "timestamp": latest,
                            "status": (
                                "Active"
                                if level in {"CRITICAL", "HIGH"}
                                else "Monitoring"
                            )
                        })

                    incident_count = len(incidents)

        # Response actions recorded by the simulation center.
        actions = []
        reviewed_sources = set()

        if os.path.exists(INCIDENT_RESPONSE_LOG):
            response_df = pd.read_csv(INCIDENT_RESPONSE_LOG)
            response_df.columns = response_df.columns.astype(str).str.strip()

            for _, row in response_df.tail(100).iterrows():
                source_ip = str(
                    row.get("Source IP", "Unknown")
                ).strip()
                action = str(
                    row.get("Action", "")
                ).strip()

                actions.append({
                    "timestamp": str(row.get("Timestamp", "")),
                    "source_ip": source_ip,
                    "action": action,
                    "status": str(row.get("Status", "Recorded"))
                })

                if "reviewed" in action.lower():
                    reviewed_sources.add(source_ip)

        active_count = sum(
            1 for item in incidents
            if item["source_ip"] not in reviewed_sources
            and item["level"] in {"CRITICAL", "HIGH"}
        )

        high_risk_count = sum(
            1 for item in incidents
            if item["level"] == "HIGH"
        )

        reviewed_count = sum(
            1 for item in incidents
            if item["source_ip"] in reviewed_sources
        )

        latest_incident = (
            incidents[0]
            if incidents else None
        )

        latest_action = (
            actions[-1]
            if actions else None
        )

        # Save a compact status snapshot.
        try:
            pd.DataFrame([{
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Active Incidents": active_count,
                "High Risk Incidents": high_risk_count,
                "Reviewed Incidents": reviewed_count,
                "Total Correlated Incidents": incident_count,
                "Total Response Actions": len(actions)
            }]).to_csv(
                INCIDENT_STATUS_LOG,
                index=False
            )
        except Exception as status_error:
            print("INCIDENT STATUS SAVE WARNING:", str(status_error))

        return jsonify({
            "success": True,
            "active_incidents": active_count,
            "high_risk_incidents": high_risk_count,
            "reviewed_incidents": reviewed_count,
            "total_incidents": incident_count,
            "total_response_actions": len(actions),
            "latest_incident": latest_incident,
            "latest_response": latest_action,
            "incidents": incidents,
            "response_actions": actions[-10:][::-1],
            "message": (
                "Incident dashboard generated from local AI-Net telemetry."
            )
        })

    except Exception as error:
        print("INCIDENT DASHBOARD ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load incident dashboard.",
            "details": str(error)
        }), 500



# ============================================================
# INCIDENT TIMELINE / AUDIT LOG
# ============================================================

@app.route("/incident_audit_log", methods=["GET"])
def incident_audit_log():
    """
    Return a chronological security audit trail built from local AI-Net
    telemetry and simulated incident-response actions.

    This endpoint is read-only. It does not perform any real network
    response operation.
    """
    try:
        events = []

        # --------------------------------------------------------
        # Live DDoS detection events
        # --------------------------------------------------------
        if os.path.exists(LIVE_LOG):
            try:
                header = pd.read_csv(LIVE_LOG, nrows=0)
                header.columns = header.columns.astype(str).str.strip()
                available = set(header.columns)

                prediction_col = next(
                    (c for c in [
                        "AI-Net Prediction", "Prediction", "prediction", "Label"
                    ] if c in available),
                    None
                )
                timestamp_col = next(
                    (c for c in ["Timestamp", "timestamp"] if c in available),
                    None
                )
                source_col = next(
                    (c for c in [
                        "Source IP", "src_ip", "Source", "Src IP"
                    ] if c in available),
                    None
                )
                destination_col = next(
                    (c for c in [
                        "Destination IP", "dst_ip", "Destination", "Dst IP"
                    ] if c in available),
                    None
                )
                confidence_col = next(
                    (c for c in [
                        "AI-Net Confidence (%)", "Confidence", "confidence"
                    ] if c in available),
                    None
                )
                protocol_col = next(
                    (c for c in ["Protocol", "protocol"] if c in available),
                    None
                )

                if prediction_col:
                    columns = [prediction_col]
                    for column in [
                        timestamp_col,
                        source_col,
                        destination_col,
                        confidence_col,
                        protocol_col
                    ]:
                        if column and column not in columns:
                            columns.append(column)

                    df = pd.read_csv(LIVE_LOG, usecols=columns)
                    labels = df[prediction_col].apply(
                        convert_prediction_to_label
                    )
                    ddos = df[labels == "DDoS"]

                    # Keep the audit page lightweight while preserving the
                    # most recent detection events.
                    for _, row in ddos.tail(100).iterrows():
                        timestamp = str(
                            row.get(timestamp_col, "")
                            if timestamp_col else ""
                        ).strip()
                        source_ip = str(
                            row.get(source_col, "Unknown")
                            if source_col else "Unknown"
                        ).strip()
                        destination_ip = str(
                            row.get(destination_col, "Unknown")
                            if destination_col else "Unknown"
                        ).strip()
                        protocol = str(
                            row.get(protocol_col, "Unknown")
                            if protocol_col else "Unknown"
                        ).strip()

                        confidence = 0.0
                        if confidence_col:
                            try:
                                confidence = float(
                                    pd.to_numeric(
                                        row.get(confidence_col),
                                        errors="coerce"
                                    )
                                )
                                if pd.isna(confidence):
                                    confidence = 0.0
                            except Exception:
                                confidence = 0.0

                        events.append({
                            "timestamp": timestamp,
                            "event_type": "DDoS Detection",
                            "severity": "CRITICAL",
                            "source_ip": source_ip or "Unknown",
                            "destination_ip": destination_ip or "Unknown",
                            "protocol": protocol or "Unknown",
                            "details": (
                                f"AI-Net detected DDoS traffic "
                                f"with {confidence:.2f}% confidence."
                            )
                        })

            except Exception as live_error:
                print("AUDIT LIVE LOG WARNING:", str(live_error))

        # --------------------------------------------------------
        # Simulated response actions
        # --------------------------------------------------------
        if os.path.exists(INCIDENT_RESPONSE_LOG):
            try:
                response_df = pd.read_csv(INCIDENT_RESPONSE_LOG)
                response_df.columns = response_df.columns.astype(str).str.strip()

                for _, row in response_df.tail(100).iterrows():
                    action = str(row.get("Action", "")).strip()
                    source_ip = str(
                        row.get("Source IP", "Unknown")
                    ).strip()
                    timestamp = str(
                        row.get("Timestamp", "")
                    ).strip()
                    status = str(
                        row.get("Status", "Recorded")
                    ).strip()

                    severity = "HIGH" if "block" in action.lower() else "INFO"
                    if "reviewed" in action.lower():
                        severity = "INFO"

                    events.append({
                        "timestamp": timestamp,
                        "event_type": "Response Action",
                        "severity": severity,
                        "source_ip": source_ip or "Unknown",
                        "destination_ip": "-",
                        "protocol": "-",
                        "details": f"{action} — {status}"
                    })
            except Exception as response_error:
                print("AUDIT RESPONSE LOG WARNING:", str(response_error))

        # --------------------------------------------------------
        # Correlation events: one event per currently observed source.
        # --------------------------------------------------------
        if os.path.exists(LIVE_LOG):
            try:
                header = pd.read_csv(LIVE_LOG, nrows=0)
                header.columns = header.columns.astype(str).str.strip()
                available = set(header.columns)

                prediction_col = next(
                    (c for c in [
                        "AI-Net Prediction", "Prediction", "prediction", "Label"
                    ] if c in available),
                    None
                )
                source_col = next(
                    (c for c in [
                        "Source IP", "src_ip", "Source", "Src IP"
                    ] if c in available),
                    None
                )

                if prediction_col and source_col:
                    df = pd.read_csv(
                        LIVE_LOG,
                        usecols=[prediction_col, source_col]
                    )
                    labels = df[prediction_col].apply(
                        convert_prediction_to_label
                    )
                    ddos = df[labels == "DDoS"]

                    if not ddos.empty:
                        counts = (
                            ddos[source_col]
                            .astype(str)
                            .str.strip()
                            .value_counts()
                            .head(20)
                        )

                        for source_ip, count in counts.items():
                            events.append({
                                "timestamp": "",
                                "event_type": "Incident Correlation",
                                "severity": "CRITICAL",
                                "source_ip": str(source_ip),
                                "destination_ip": "-",
                                "protocol": "-",
                                "details": (
                                    f"Correlated {int(count)} DDoS flow(s) "
                                    f"into a security incident."
                                )
                            })
            except Exception as correlation_error:
                print("AUDIT CORRELATION WARNING:", str(correlation_error))

        # Put events in chronological order when timestamps are available.
        # Blank correlation timestamps are placed after timestamped events.
        def sort_key(item):
            return str(item.get("timestamp", "") or "9999-99-99 99:99:99")

        events.sort(key=sort_key, reverse=True)
        events = events[:150]

        return jsonify({
            "success": True,
            "event_count": len(events),
            "events": events,
            "message": "AI-Net security audit trail generated from local telemetry."
        })

    except Exception as error:
        print("INCIDENT AUDIT ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load incident audit log.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 30 — SOC OPERATIONS DASHBOARD
# ============================================================

@app.route("/soc_dashboard", methods=["GET"])
def soc_dashboard():
    """Return a compact SOC command-center summary from local telemetry."""
    try:
        # Prefer current live telemetry; fall back to the latest CSV analysis.
        source = "none"
        source_file = None
        live_stats = get_live_statistics()

        if live_stats.get("available"):
            source = "live_packet_capture"
            source_file = LIVE_LOG
        elif os.path.exists(CSV_LOG):
            source = "csv_analysis"
            source_file = CSV_LOG

        total = benign = ddos = 0
        attack_rate = 0.0
        avg_confidence = 0.0
        updated_at = None
        top_events = []

        if source_file and os.path.exists(source_file):
            header = pd.read_csv(source_file, nrows=0)
            header.columns = header.columns.astype(str).str.strip()
            available = set(header.columns)

            prediction_col = next((c for c in [
                "AI-Net Prediction", "Prediction", "prediction", "Label"
            ] if c in available), None)
            confidence_col = next((c for c in [
                "AI-Net Confidence (%)", "Confidence", "confidence"
            ] if c in available), None)
            timestamp_col = next((c for c in ["Timestamp", "timestamp"] if c in available), None)
            source_col = next((c for c in ["Source IP", "src_ip", "Source", "Src IP"] if c in available), None)
            destination_col = next((c for c in ["Destination IP", "dst_ip", "Destination", "Dst IP"] if c in available), None)

            if prediction_col:
                cols = [prediction_col]
                for c in [confidence_col, timestamp_col, source_col, destination_col]:
                    if c and c not in cols:
                        cols.append(c)
                df = pd.read_csv(source_file, usecols=cols)
                if not df.empty:
                    labels = df[prediction_col].apply(convert_prediction_to_label)
                    total = len(df)
                    ddos = int((labels == "DDoS").sum())
                    benign = int((labels == "BENIGN").sum())
                    attack_rate = (ddos / total * 100) if total else 0.0

                    if confidence_col:
                        c = pd.to_numeric(df.loc[labels == "DDoS", confidence_col], errors="coerce").dropna()
                        if not c.empty:
                            avg_confidence = float(c.mean())
                    if timestamp_col:
                        updated_at = str(df[timestamp_col].iloc[-1])

                    # Recent critical DDoS events for the SOC command center.
                    ddos_df = df[labels == "DDoS"].tail(5).iloc[::-1]
                    for _, row in ddos_df.iterrows():
                        top_events.append({
                            "timestamp": str(row.get(timestamp_col, "Time unavailable")) if timestamp_col else "Time unavailable",
                            "source_ip": str(row.get(source_col, "Unknown")) if source_col else "Unknown",
                            "destination_ip": str(row.get(destination_col, "Unknown")) if destination_col else "Unknown",
                            "confidence": round(float(pd.to_numeric(row.get(confidence_col), errors="coerce")) if confidence_col and pd.notna(pd.to_numeric(row.get(confidence_col), errors="coerce")) else 0.0, 2)
                        })

        if attack_rate >= 50 or ddos >= 100:
            threat_level = "CRITICAL"
        elif attack_rate >= 10 or ddos >= 20:
            threat_level = "HIGH"
        elif attack_rate > 0:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        risk_score = min(100.0, (attack_rate * 0.7) + (avg_confidence * 0.3 if ddos else 0.0))
        if threat_level == "CRITICAL":
            risk_band = "CRITICAL"
        elif risk_score >= 60:
            risk_band = "HIGH"
        elif risk_score > 0:
            risk_band = "MEDIUM"
        else:
            risk_band = "LOW"

        # Response activity from the existing response log.
        response_actions = 0
        reviewed = 0
        latest_response = None
        if os.path.exists(INCIDENT_RESPONSE_LOG):
            rdf = pd.read_csv(INCIDENT_RESPONSE_LOG)
            response_actions = len(rdf)
            if not rdf.empty:
                reviewed = int(rdf["Action"].astype(str).str.contains("reviewed", case=False, na=False).sum()) if "Action" in rdf.columns else 0
                row = rdf.iloc[-1]
                latest_response = {
                    "timestamp": str(row.get("Timestamp", "Time unavailable")),
                    "source_ip": str(row.get("Source IP", "Unknown")),
                    "action": str(row.get("Action", "Response action")),
                    "status": str(row.get("Status", "Recorded"))
                }

        active_incidents = max(0, ddos - reviewed)
        if ddos == 0:
            active_incidents = 0

        capture_running = False
        try:
            capture_running = bool(live_sniffer is not None and live_sniffer.running)
        except Exception:
            capture_running = False

        recommended = (
            "Immediately investigate attacking sources and apply DDoS mitigation or rate limiting."
            if threat_level == "CRITICAL" else
            "Investigate suspicious traffic and prepare mitigation controls."
            if threat_level in ("HIGH", "MEDIUM") else
            "Continue live monitoring. No DDoS activity is currently present."
        )

        return jsonify({
            "success": True,
            "source": source,
            "capture_running": capture_running,
            "total_flows": total,
            "benign_flows": benign,
            "ddos_flows": ddos,
            "attack_rate": round(attack_rate, 2),
            "average_attack_confidence": round(avg_confidence, 2),
            "threat_level": threat_level,
            "risk_band": risk_band,
            "risk_score": round(risk_score, 2),
            "active_incidents": active_incidents,
            "reviewed_incidents": reviewed,
            "response_actions": response_actions,
            "latest_response": latest_response,
            "recent_critical_events": top_events,
            "recommended_action": recommended,
            "updated_at": updated_at
        })
    except Exception as error:
        print("SOC DASHBOARD ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not load SOC dashboard.", "details": str(error)}), 500


# ============================================================
# DAY 31 — ADVANCED ATTACK ANALYTICS
# ============================================================

@app.route("/attack_analytics", methods=["GET"])
def attack_analytics():
    """Return attack-focused analytics from live telemetry or CSV results."""
    try:
        live_stats = get_live_statistics()
        source = "none"
        source_file = None
        if live_stats.get("available"):
            source = "live_packet_capture"
            source_file = LIVE_LOG
        elif os.path.exists(CSV_LOG):
            source = "csv_analysis"
            source_file = CSV_LOG

        if not source_file or not os.path.exists(source_file):
            return jsonify({
                "success": True, "available": False, "source": source,
                "message": "No analyzed telemetry is available yet.",
                "total_flows": 0, "ddos_flows": 0, "attack_rate": 0.0,
                "avg_attack_confidence": 0.0, "protocol_distribution": [],
                "top_sources": [], "top_destinations": [], "flow_metrics": {},
                "timeline": []
            })

        header = pd.read_csv(source_file, nrows=0)
        header.columns = header.columns.astype(str).str.strip()
        available = set(header.columns)
        pred_col = next((c for c in ["AI-Net Prediction","Prediction","prediction","Label"] if c in available), None)
        conf_col = next((c for c in ["AI-Net Confidence (%)","Confidence","confidence"] if c in available), None)
        proto_col = next((c for c in ["Protocol","protocol"] if c in available), None)
        src_col = next((c for c in ["Source IP","src_ip","Source","Src IP"] if c in available), None)
        dst_col = next((c for c in ["Destination IP","dst_ip","Destination","Dst IP"] if c in available), None)
        packets_col = next((c for c in ["Packets","Total Packets","Total Fwd Packets"] if c in available), None)
        duration_col = next((c for c in ["Flow Duration","Duration"] if c in available), None)
        time_col = next((c for c in ["Timestamp","timestamp"] if c in available), None)

        cols = [c for c in [pred_col, conf_col, proto_col, src_col, dst_col, packets_col, duration_col, time_col] if c]
        df = pd.read_csv(source_file, usecols=cols)
        if df.empty or not pred_col:
            return jsonify({"success": True, "available": False, "source": source, "message": "No prediction data available."})

        labels = df[pred_col].apply(convert_prediction_to_label)
        dd = df[labels == "DDoS"].copy()
        total = len(df)
        ddos = len(dd)
        attack_rate = (ddos / total * 100) if total else 0.0

        avg_conf = 0.0
        if conf_col and not dd.empty:
            vals = pd.to_numeric(dd[conf_col], errors="coerce").dropna()
            if not vals.empty: avg_conf = float(vals.mean())

        def counts(col, frame):
            if not col or frame.empty: return []
            s = frame[col].astype(str).replace(["nan","None",""], pd.NA).dropna()
            return [{"name": str(k), "count": int(v)} for k,v in s.value_counts().head(10).items()]

        proto = counts(proto_col, dd)
        sources = counts(src_col, dd)
        destinations = counts(dst_col, dd)

        metrics = {}
        if packets_col:
            p = pd.to_numeric(dd[packets_col], errors="coerce").dropna()
            metrics["ddos_packets_total"] = int(p.sum()) if not p.empty else 0
            metrics["ddos_packets_avg"] = round(float(p.mean()), 2) if not p.empty else 0.0
            metrics["ddos_packets_peak"] = int(p.max()) if not p.empty else 0
        if duration_col:
            d = pd.to_numeric(dd[duration_col], errors="coerce").dropna()
            metrics["avg_duration"] = round(float(d.mean()), 2) if not d.empty else 0.0
            metrics["max_duration"] = round(float(d.max()), 2) if not d.empty else 0.0

        timeline=[]
        if time_col:
            t = pd.to_datetime(df[time_col], errors="coerce")
            temp = pd.DataFrame({"time":t, "label":labels}).dropna(subset=["time"])
            if not temp.empty:
                temp["bucket"] = temp["time"].dt.floor("min")
                grouped = temp.groupby("bucket").agg(total=("label","size"), ddos=("label", lambda x: int((x=="DDoS").sum())))
                for idx,row in grouped.tail(30).iterrows():
                    timeline.append({"time": idx.strftime("%Y-%m-%d %H:%M"), "total": int(row["total"]), "ddos": int(row["ddos"])})

        return jsonify({
            "success": True, "available": True, "source": source,
            "total_flows": total, "ddos_flows": ddos,
            "benign_flows": int((labels == "BENIGN").sum()),
            "attack_rate": round(attack_rate, 2),
            "avg_attack_confidence": round(avg_conf, 2),
            "protocol_distribution": proto, "top_sources": sources,
            "top_destinations": destinations, "flow_metrics": metrics,
            "timeline": timeline,
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as error:
        print("ATTACK ANALYTICS ERROR:", str(error))
        return jsonify({"success": False, "error": str(error)}), 500

@app.route("/model_explainability", methods=["GET"])
def model_explainability():
    """
    Return explainability information available directly from the
    serialized Random Forest model.

    Important: feature importance is model-level importance, not a
    causal explanation for an individual packet/flow.
    """
    try:
        if model is None:
            return jsonify({
                "success": False,
                "model_loaded": False,
                "error": "Machine learning model is not loaded."
            }), 503

        feature_names = list(FEATURES)

        importances = None
        if hasattr(model, "feature_importances_"):
            importances = np.asarray(
                model.feature_importances_,
                dtype=float
            ).reshape(-1)

        if importances is None or len(importances) != len(feature_names):
            importance_rows = [
                {
                    "feature": feature,
                    "importance": None,
                    "importance_percent": None
                }
                for feature in feature_names
            ]
        else:
            total_importance = float(importances.sum())
            if total_importance > 0:
                normalized = importances / total_importance
            else:
                normalized = np.zeros_like(importances)

            order = np.argsort(normalized)[::-1]

            importance_rows = []
            for index in order:
                value = float(normalized[index])
                importance_rows.append({
                    "feature": feature_names[index],
                    "importance": round(value, 6),
                    "importance_percent": round(value * 100, 2)
                })

        class_names = []
        if hasattr(model, "classes_"):
            class_names = [
                str(value) for value in model.classes_
            ]

        model_metadata = {
            "model_type": type(model).__name__,
            "feature_count": len(feature_names),
            "classes": class_names,
            "estimator_count": (
                int(model.n_estimators)
                if hasattr(model, "n_estimators")
                else None
            )
        }

        # Validation metrics are only displayed if a metrics JSON was
        # explicitly saved by the training pipeline. We do not invent
        # evaluation results from the serialized estimator alone.
        metrics = {}
        metrics_path = os.path.join(
            BASE_DIR,
            "models",
            "model_metrics.json"
        )

        if os.path.exists(metrics_path):
            try:
                with open(metrics_path, "r", encoding="utf-8") as metric_file:
                    loaded_metrics = json.load(metric_file)

                if isinstance(loaded_metrics, dict):
                    for key in [
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "f1_score",
                        "roc_auc",
                        "roc_auc_score"
                    ]:
                        if key in loaded_metrics:
                            metrics[key] = loaded_metrics[key]
            except Exception as metric_error:
                print(
                    "MODEL METRICS WARNING:",
                    str(metric_error)
                )

        return jsonify({
            "success": True,
            "model_loaded": True,
            "model": model_metadata,
            "features": feature_names,
            "feature_importance": importance_rows,
            "validation_metrics": metrics,
            "metrics_available": bool(metrics),
            "explanation_note": (
                "Feature importance shows how much each feature contributes "
                "to the Random Forest's overall decision process. It is not "
                "a causal explanation and does not by itself prove that a "
                "specific feature caused an individual DDoS classification."
            ),
            "updated_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        })

    except Exception as error:
        print("MODEL EXPLAINABILITY ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load model explainability data.",
            "details": str(error)
        }), 500


# ============================================================
# MODEL PERFORMANCE DASHBOARD
# ============================================================

@app.route("/model_performance", methods=["GET"])
def model_performance():
    """
    Return only evaluation metrics that were explicitly persisted by
    the training/evaluation pipeline. No metrics are invented from the
    serialized estimator alone.
    """
    try:
        candidate_paths = [
            os.path.join(BASE_DIR, "models", "model_metrics.json"),
            os.path.join(BASE_DIR, "models", "metrics.json"),
            os.path.join(BASE_DIR, "logs", "model_metrics.json"),
        ]

        loaded = {}
        metrics_source = None

        for metrics_path in candidate_paths:
            if not os.path.exists(metrics_path):
                continue

            try:
                with open(metrics_path, "r", encoding="utf-8") as metric_file:
                    candidate = json.load(metric_file)

                if isinstance(candidate, dict):
                    loaded = candidate
                    metrics_source = os.path.relpath(metrics_path, BASE_DIR)
                    break
            except Exception:
                continue

        def first_value(*keys):
            for key in keys:
                if key in loaded and loaded[key] is not None:
                    return loaded[key]
            return None

        metrics = {
            "accuracy": first_value("accuracy"),
            "precision": first_value("precision"),
            "recall": first_value("recall"),
            "f1_score": first_value("f1_score", "f1"),
            "roc_auc": first_value("roc_auc", "roc_auc_score"),
            "true_negative": first_value("true_negative", "tn"),
            "false_positive": first_value("false_positive", "fp"),
            "false_negative": first_value("false_negative", "fn"),
            "true_positive": first_value("true_positive", "tp"),
        }

        metrics_available = any(
            value is not None for value in metrics.values()
        )

        confusion_matrix = loaded.get("confusion_matrix")
        if confusion_matrix is not None:
            metrics["confusion_matrix"] = confusion_matrix

        return jsonify({
            "success": True,
            "model_loaded": model is not None,
            "model_type": type(model).__name__ if model is not None else None,
            "metrics_available": metrics_available,
            "metrics_source": metrics_source,
            "metrics": metrics,
            "evaluation_note": (
                "These values are shown only when explicitly saved by the "
                "training/evaluation pipeline. The dashboard does not "
                "derive validation performance from the serialized model."
            ),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    except Exception as error:
        print("MODEL PERFORMANCE ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load model performance data.",
            "details": str(error)
        }), 500


# ============================================================
# THREAT HUNTING / IOC INVESTIGATION
# ============================================================

@app.route("/threat_hunt", methods=["GET"])
def threat_hunt():
    """
    Search the live telemetry for a source/destination IP or return
    a compact overview of the most recent observed flows.
    """
    try:
        query = str(request.args.get("ip", "")).strip()
        limit = int(request.args.get("limit", 50))
        limit = max(1, min(limit, 200))

        if not os.path.exists(LIVE_LOG):
            return jsonify({
                "success": True,
                "available": False,
                "query": query,
                "matches": [],
                "summary": {
                    "total_matches": 0,
                    "ddos_matches": 0,
                    "benign_matches": 0
                }
            })

        df = pd.read_csv(LIVE_LOG)

        if df.empty:
            return jsonify({
                "success": True,
                "available": True,
                "query": query,
                "matches": [],
                "summary": {
                    "total_matches": 0,
                    "ddos_matches": 0,
                    "benign_matches": 0
                }
            })

        for column in [
            "Source IP",
            "Destination IP",
            "Protocol",
            "AI-Net Prediction"
        ]:
            if column not in df.columns:
                df[column] = ""

        if query:
            source_match = (
                df["Source IP"].astype(str).str.strip() == query
            )
            destination_match = (
                df["Destination IP"].astype(str).str.strip() == query
            )
            filtered = df[source_match | destination_match].copy()
        else:
            filtered = df.copy()

        prediction_series = (
            filtered["AI-Net Prediction"]
            .astype(str)
            .str.strip()
        )

        ddos_count = int(
            prediction_series.str.upper().eq("DDOS").sum()
        )
        benign_count = int(
            prediction_series.str.upper().eq("BENIGN").sum()
        )

        rows = []

        sort_column = None
        for candidate in ["Timestamp", "Date", "Time"]:
            if candidate in filtered.columns:
                sort_column = candidate
                break

        if sort_column:
            filtered = filtered.sort_values(
                sort_column,
                ascending=False
            )

        for _, row in filtered.head(limit).iterrows():
            record = {}

            for column in [
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Source Port",
                "Destination Port",
                "Protocol",
                "Packets",
                "Fwd Packets",
                "Bwd Packets",
                "AI-Net Prediction",
                "AI-Net Confidence (%)"
            ]:
                if column in filtered.columns:
                    value = row[column]

                    if pd.isna(value):
                        value = ""

                    if isinstance(value, (np.integer, np.floating)):
                        value = float(value)

                    record[column] = value

            rows.append(record)

        return jsonify({
            "success": True,
            "available": True,
            "query": query,
            "summary": {
                "total_matches": int(len(filtered)),
                "ddos_matches": ddos_count,
                "benign_matches": benign_count
            },
            "matches": rows
        })

    except Exception as error:
        print("THREAT HUNTING ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Threat hunting query failed.",
            "details": str(error)
        }), 500


# ============================================================
# MITRE ATT&CK TECHNIQUE MAPPING
# ============================================================

@app.route("/mitre_attack", methods=["GET"])
def mitre_attack():
    """
    Map AI-Net DDoS detections to relevant MITRE ATT&CK techniques.

    This is defensive classification only. It does not claim attacker
    attribution or identify a specific threat actor.
    """
    try:
        total_flows = 0
        ddos_flows = 0
        benign_flows = 0
        average_confidence = 0.0
        source = "No telemetry"

        if os.path.exists(LIVE_LOG):
            df = pd.read_csv(LIVE_LOG)
            source = "Live capture"
        elif os.path.exists(CSV_LOG):
            df = pd.read_csv(CSV_LOG)
            source = "CSV analysis"
        else:
            df = pd.DataFrame()

        if not df.empty:
            df.columns = df.columns.astype(str).str.strip()
            total_flows = int(len(df))

            prediction_col = next(
                (c for c in [
                    "AI-Net Prediction", "Prediction", "prediction", "Label"
                ] if c in df.columns),
                None
            )

            confidence_col = next(
                (c for c in [
                    "AI-Net Confidence (%)", "Confidence", "confidence"
                ] if c in df.columns),
                None
            )

            if prediction_col:
                predictions = df[prediction_col].astype(str).str.strip().str.upper()
                ddos_flows = int(predictions.eq("DDOS").sum())
                benign_flows = int(predictions.eq("BENIGN").sum())

            if confidence_col and ddos_flows:
                ddos_mask = (
                    df[prediction_col]
                    .astype(str)
                    .str.strip()
                    .str.upper()
                    .eq("DDOS")
                )
                confidence_values = pd.to_numeric(
                    df.loc[ddos_mask, confidence_col],
                    errors="coerce"
                ).dropna()

                if not confidence_values.empty:
                    average_confidence = round(
                        float(confidence_values.mean()), 2
                    )

        attack_rate = (
            round((ddos_flows / total_flows) * 100, 2)
            if total_flows else 0.0
        )

        techniques = []

        if ddos_flows > 0:
            techniques = [
                {
                    "id": "T1498",
                    "name": "Network Denial of Service",
                    "tactic": "Impact",
                    "description": (
                        "AI-Net detected DDoS traffic consistent with an "
                        "attempt to impair network availability."
                    ),
                    "sub_techniques": [
                        {
                            "id": "T1498.001",
                            "name": "Direct Network Flood"
                        },
                        {
                            "id": "T1498.002",
                            "name": "Service Exhaustion"
                        }
                    ],
                    "detections": ddos_flows,
                    "confidence": average_confidence
                }
            ]

        return jsonify({
            "success": True,
            "source": source,
            "total_flows": total_flows,
            "ddos_flows": ddos_flows,
            "benign_flows": benign_flows,
            "attack_rate": attack_rate,
            "techniques": techniques,
            "note": (
                "Technique mapping is based on AI-Net's DDoS classification "
                "and is not threat-actor attribution."
            )
        })

    except Exception as error:
        print("MITRE ATT&CK ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not generate MITRE ATT&CK mapping.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 37 — NETWORK FORENSICS / FLOW DRILLDOWN
# ============================================================

@app.route("/network_forensics", methods=["GET"])
def network_forensics():
    """
    Defensive flow-level investigation for an observed source IP.

    Only telemetry already collected by AI-Net is analyzed. This endpoint
    does not perform external IP lookups or active scanning.
    """
    try:
        requested_ip = str(request.args.get("source_ip", "")).strip()

        if os.path.exists(LIVE_LOG):
            df = pd.read_csv(LIVE_LOG)
            source = "Live capture"
        elif os.path.exists(CSV_LOG):
            df = pd.read_csv(CSV_LOG)
            source = "CSV analysis"
        else:
            df = pd.DataFrame()
            source = "No telemetry"

        if df.empty:
            return jsonify({
                "success": True,
                "available": False,
                "source": source,
                "message": "No network telemetry is currently available."
            })

        df.columns = df.columns.astype(str).str.strip()

        source_col = next(
            (c for c in ["Source IP", "Src IP", "src_ip"] if c in df.columns),
            None
        )

        dest_col = next(
            (c for c in ["Destination IP", "Dst IP", "dst_ip"] if c in df.columns),
            None
        )

        protocol_col = next(
            (c for c in ["Protocol", "protocol"] if c in df.columns),
            None
        )

        prediction_col = next(
            (c for c in [
                "AI-Net Prediction", "Prediction", "prediction", "Label"
            ] if c in df.columns),
            None
        )

        confidence_col = next(
            (c for c in [
                "AI-Net Confidence (%)", "Confidence", "confidence"
            ] if c in df.columns),
            None
        )

        packets_col = next(
            (c for c in ["Packets", "Total Packets", "Total Fwd Packets"]
             if c in df.columns),
            None
        )

        if not source_col:
            return jsonify({
                "success": True,
                "available": False,
                "source": source,
                "message": (
                    "Source IP telemetry is unavailable for this dataset. "
                    "Start live packet capture to collect flow-level IP evidence."
                )
            })

        # Normalize source IPs for safe comparison.
        source_series = df[source_col].astype(str).str.strip()

        # If no IP was supplied, return observed source IPs for selection.
        if not requested_ip:
            observed = source_series[
                (source_series != "") &
                (source_series.str.lower() != "nan")
            ]

            top_sources = (
                observed.value_counts()
                .head(15)
                .reset_index()
            )
            top_sources.columns = ["ip", "flows"]

            return jsonify({
                "success": True,
                "available": True,
                "source": source,
                "mode": "source_selection",
                "sources": top_sources.to_dict("records")
            })

        mask = source_series.eq(requested_ip)
        matched = df.loc[mask].copy()

        if matched.empty:
            return jsonify({
                "success": True,
                "available": True,
                "source": source,
                "mode": "investigation",
                "source_ip": requested_ip,
                "found": False,
                "message": "No observed flows match this source IP."
            })

        predictions = (
            matched[prediction_col].astype(str).str.strip().str.upper()
            if prediction_col else
            pd.Series([""] * len(matched), index=matched.index)
        )

        ddos_count = int(predictions.eq("DDOS").sum())
        benign_count = int(predictions.eq("BENIGN").sum())

        confidences = []
        if confidence_col and ddos_count:
            ddos_conf = pd.to_numeric(
                matched.loc[predictions.eq("DDOS"), confidence_col],
                errors="coerce"
            ).dropna()
            confidences = ddos_conf.tolist()

        avg_confidence = (
            round(float(sum(confidences) / len(confidences)), 2)
            if confidences else 0.0
        )

        destinations = []
        if dest_col:
            destinations = [
                {"ip": str(ip), "flows": int(count)}
                for ip, count in matched[dest_col]
                .astype(str)
                .str.strip()
                .replace("nan", "")
                .value_counts()
                .head(10)
                .items()
                if ip
            ]

        protocols = []
        if protocol_col:
            protocols = [
                {"protocol": str(protocol), "flows": int(count)}
                for protocol, count in matched[protocol_col]
                .astype(str)
                .str.strip()
                .replace("nan", "")
                .value_counts()
                .head(10)
                .items()
                if protocol
            ]

        total_packets = 0
        if packets_col:
            total_packets = int(
                pd.to_numeric(matched[packets_col], errors="coerce")
                .fillna(0)
                .sum()
            )

        risk = "LOW"
        if ddos_count >= 20 or avg_confidence >= 95:
            risk = "CRITICAL"
        elif ddos_count >= 5 or avg_confidence >= 80:
            risk = "HIGH"
        elif ddos_count > 0:
            risk = "MEDIUM"

        recent_flows = []
        display_columns = [
            c for c in [
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Source Port",
                "Destination Port",
                "Protocol",
                "Packets",
                "AI-Net Prediction",
                "AI-Net Confidence (%)"
            ] if c in matched.columns
        ]

        if display_columns:
            recent = matched[display_columns].tail(12).copy()
            recent = recent.replace({np.nan: ""})
            recent_flows = recent.to_dict("records")

        return jsonify({
            "success": True,
            "available": True,
            "source": source,
            "mode": "investigation",
            "source_ip": requested_ip,
            "found": True,
            "risk": risk,
            "total_flows": int(len(matched)),
            "ddos_flows": ddos_count,
            "benign_flows": benign_count,
            "attack_rate": round(
                (ddos_count / len(matched)) * 100, 2
            ) if len(matched) else 0.0,
            "average_attack_confidence": avg_confidence,
            "total_packets": total_packets,
            "top_destinations": destinations,
            "protocol_distribution": protocols,
            "recent_flows": recent_flows
        })

    except Exception as error:
        print("NETWORK FORENSICS ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not generate network forensics data.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 38 — IOC MANAGEMENT / THREAT HUNTING WORKSPACE
# ============================================================

IOC_STORE = os.path.join(LOG_DIR, "ioc_watchlist.json")


def load_ioc_store():
    try:
        if os.path.exists(IOC_STORE):
            with open(IOC_STORE, "r", encoding="utf-8") as file:
                data = json.load(file)
                return data if isinstance(data, list) else []
    except Exception as error:
        print("IOC LOAD ERROR:", str(error))
    return []


def save_ioc_store(items):
    with open(IOC_STORE, "w", encoding="utf-8") as file:
        json.dump(items, file, indent=2)

# ============================================================
# SOURCE INVESTIGATION — RESTORED / SQLITE FIRST
# ============================================================
@app.route("/source_investigation", methods=["GET"])
def source_investigation():
    """Investigate one observed source IP using persisted AI-Net telemetry."""
    try:
        source_ip = str(request.args.get("source_ip", "")).strip()
        if not source_ip:
            return jsonify({"success": False, "error": "source_ip is required."}), 400

        try:
            ip_obj = ipaddress.ip_address(source_ip)
            ip_scope = "Internal" if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local) else "External"
        except ValueError:
            ip_scope = "Unknown"

        conn = get_db()
        rows = conn.execute("""
            SELECT timestamp, source_ip, destination_ip, protocol,
                   prediction, confidence
            FROM detection_events
            WHERE source_ip = ?
            ORDER BY id DESC
        """, (source_ip,)).fetchall()
        conn.close()

        if not rows:
            return jsonify({
                "success": True,
                "available": False,
                "source_ip": source_ip,
                "ip_scope": ip_scope,
                "message": "No persisted flows were observed for this source IP."
            })

        labels = [convert_prediction_to_label(r["prediction"]) for r in rows]
        total_flows = len(rows)
        ddos_flows = sum(1 for x in labels if x == "DDoS")
        benign_flows = sum(1 for x in labels if x == "BENIGN")
        attack_share = round(ddos_flows / total_flows * 100, 2) if total_flows else 0.0

        confidences = []
        for r in rows:
            try:
                if r["confidence"] is not None:
                    confidences.append(float(r["confidence"]))
            except (TypeError, ValueError):
                pass
        average_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.0

        if ddos_flows == 0:
            classification = "Normal"
            investigation_status = "No DDoS behavior observed"
        elif attack_share >= 75 or ddos_flows >= 20:
            classification = "High Risk"
            investigation_status = "Immediate investigation recommended"
        elif attack_share >= 25 or ddos_flows >= 5:
            classification = "Suspicious"
            investigation_status = "Review source activity"
        else:
            classification = "Low Risk"
            investigation_status = "Continue monitoring"

        protocols = []
        protocol_counts = {}
        destinations = {}
        for r in rows:
            proto = str(r["protocol"] or "Unknown").strip().upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            dst = str(r["destination_ip"] or "Unknown").strip()
            destinations[dst] = destinations.get(dst, 0) + 1

        protocols = [p for p, _ in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
        targeted_destinations = [
            {"rank": i, "destination_ip": dst, "flows": count}
            for i, (dst, count) in enumerate(
                sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10], start=1
            )
        ]

        return jsonify({
            "success": True,
            "available": True,
            "source": "sqlite_detection_events",
            "source_ip": source_ip,
            "ip_scope": ip_scope,
            "classification": classification,
            "investigation_status": investigation_status,
            "total_flows": total_flows,
            "ddos_flows": ddos_flows,
            "benign_flows": benign_flows,
            "attack_share": attack_share,
            "average_confidence": average_confidence,
            "protocols": protocols,
            "targeted_destinations": targeted_destinations,
            "message": "Investigation data is based on AI-Net persisted packet telemetry. No external IP reputation lookup was performed."
        })
    except Exception as error:
        print("SOURCE INVESTIGATION ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not investigate the selected source IP.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 48.1 — SOC INCIDENT LIFECYCLE API
# ============================================================
INCIDENT_LIFECYCLE_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}


def _incident_lifecycle_rows():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT incident_id, source_ip, level, attack_count, total_flows,
                   attack_share, created_at, updated_at, lifecycle_status,
                   assigned_to, resolution_note, first_seen, last_seen,
                   sla_due_at, sla_status, escalation_level, escalated_at,
                   sla_acknowledged_at
            FROM security_incidents
            ORDER BY
                CASE lifecycle_status
                    WHEN 'OPEN' THEN 1
                    WHEN 'INVESTIGATING' THEN 2
                    WHEN 'CONTAINED' THEN 3
                    WHEN 'RESOLVED' THEN 4
                    WHEN 'CLOSED' THEN 5
                    ELSE 6
                END, updated_at DESC
            LIMIT 100
        """).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@app.route("/incident_lifecycle", methods=["GET", "PATCH"])
def incident_lifecycle():
    """Persistent SOC incident state, assignment and resolution tracking."""
    try:
        if request.method == "GET":
            rows = _incident_lifecycle_rows()
            return jsonify({
                "success": True,
                "count": len(rows),
                "incidents": rows,
                "statuses": sorted(INCIDENT_LIFECYCLE_STATUSES),
                "storage": "sqlite"
            })

        permission_error = viewer_read_only_guard()
        if permission_error:
            return permission_error

        payload = request.get_json(silent=True) or {}
        incident_id = str(payload.get("incident_id", "")).strip()
        if not incident_id:
            return jsonify({"success": False, "error": "incident_id is required."}), 400

        status = str(payload.get("status", "")).strip().upper()
        if status not in INCIDENT_LIFECYCLE_STATUSES:
            return jsonify({
                "success": False,
                "error": "Invalid incident lifecycle status.",
                "allowed_statuses": sorted(INCIDENT_LIFECYCLE_STATUSES)
            }), 400

        assigned_to = str(payload.get("assigned_to", "")).strip() or None
        resolution_note = str(payload.get("resolution_note", "")).strip() or None
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT incident_id, source_ip, first_seen, lifecycle_status, assigned_to, resolution_note "
                "FROM security_incidents WHERE incident_id = ?",
                (incident_id,)
            ).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Incident not found."}), 404

            first_seen = row["first_seen"] or now
            conn.execute("""
                UPDATE security_incidents
                SET lifecycle_status = ?, assigned_to = ?, resolution_note = ?,
                    first_seen = ?, last_seen = ?, updated_at = ?
                WHERE incident_id = ?
            """, (status, assigned_to, resolution_note, first_seen, now, now, incident_id))

            # Persist a dedicated lifecycle transition history record.
            actor = session.get("username", "unknown")
            conn.execute("""
                INSERT INTO incident_lifecycle_history
                (incident_id, timestamp, from_status, to_status, assigned_to,
                 resolution_note, actor, source_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id, now, row["lifecycle_status"] or "OPEN", status,
                assigned_to, resolution_note, actor, row["source_ip"] or "Unknown"
            ))

            # Keep the existing response-actions audit trail for compatibility.
            conn.execute("""
                INSERT INTO incident_response_actions
                (timestamp, incident_id, source_ip, action, actor, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                now, incident_id, row["source_ip"] or "Unknown",
                f"Incident lifecycle -> {status}", actor,
                resolution_note or "Lifecycle state changed"
            ))
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            "success": True,
            "incident_id": incident_id,
            "status": status,
            "assigned_to": assigned_to,
            "resolution_note": resolution_note,
            "updated_at": now,
            "message": "Incident lifecycle state persisted to SQLite."
        })
    except Exception as error:
        print("INCIDENT LIFECYCLE ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not update incident lifecycle.", "details": str(error)}), 500



# ============================================================
# DAY 48.3 — INCIDENT SLA & ESCALATION API
# ============================================================
@app.route("/incident_sla", methods=["GET", "PATCH"])
def incident_sla():
    """Persistent incident SLA state and controlled escalation."""
    try:
        if request.method == "GET":
            conn = get_db()
            try:
                rows = conn.execute("""
                    SELECT incident_id, source_ip, level, lifecycle_status,
                           assigned_to, sla_due_at, sla_status,
                           escalation_level, escalated_at,
                           sla_acknowledged_at, updated_at
                    FROM security_incidents
                    ORDER BY
                        CASE sla_status
                            WHEN 'OVERDUE' THEN 1
                            WHEN 'AT_RISK' THEN 2
                            WHEN 'ON_TRACK' THEN 3
                            WHEN 'COMPLETED' THEN 4
                            ELSE 5
                        END,
                        CASE level
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            ELSE 4
                        END,
                        updated_at DESC
                    LIMIT 200
                """).fetchall()
                result = []
                for row in rows:
                    item = dict(row)
                    computed = _sla_status(item.get("level"), item.get("sla_due_at"), item.get("lifecycle_status"))
                    if computed != item.get("sla_status"):
                        conn.execute(
                            "UPDATE security_incidents SET sla_status = ? WHERE incident_id = ?",
                            (computed, item["incident_id"])
                        )
                    item["sla_status"] = computed
                    due = _parse_dt(item.get("sla_due_at"))
                    item["remaining_seconds"] = max(0, int((due - datetime.now()).total_seconds())) if due and computed not in {"COMPLETED", "OVERDUE"} else 0
                    result.append(item)
                conn.commit()
            finally:
                conn.close()
            return jsonify({
                "success": True,
                "count": len(result),
                "incidents": result,
                "sla_targets_hours": INCIDENT_SLA_HOURS,
                "statuses": ["ON_TRACK", "AT_RISK", "OVERDUE", "COMPLETED", "NO_DEADLINE"],
                "storage": "sqlite"
            })

        permission_error = viewer_read_only_guard()
        if permission_error:
            return permission_error

        payload = request.get_json(silent=True) or {}
        incident_id = str(payload.get("incident_id", "")).strip()
        if not incident_id:
            return jsonify({"success": False, "error": "incident_id is required."}), 400

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT incident_id, level, lifecycle_status, escalation_level, sla_due_at FROM security_incidents WHERE incident_id = ?",
                (incident_id,)
            ).fetchone()
            if not row:
                return jsonify({"success": False, "error": "Incident not found."}), 404

            action = str(payload.get("action", "")).strip().upper()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if action == "ACKNOWLEDGE":
                conn.execute("""
                    UPDATE security_incidents
                    SET sla_acknowledged_at = ?, sla_status = ?
                    WHERE incident_id = ?
                """, (now, _sla_status(row["level"], row["sla_due_at"], row["lifecycle_status"]), incident_id))
                message = "Incident SLA acknowledged."
            elif action == "ESCALATE":
                new_level = int(row["escalation_level"] or 0) + 1
                conn.execute("""
                    UPDATE security_incidents
                    SET escalation_level = ?, escalated_at = ?, sla_status = ?
                    WHERE incident_id = ?
                """, (new_level, now, "OVERDUE" if _sla_status(row["level"], row["sla_due_at"], row["lifecycle_status"]) == "OVERDUE" else "AT_RISK", incident_id))
                conn.execute("""
                    INSERT INTO incident_response_actions
                    (timestamp, incident_id, source_ip, action, actor, details)
                    SELECT ?, incident_id, source_ip, ?, ?, ?
                    FROM security_incidents WHERE incident_id = ?
                """, (now, incident_id, session.get("username", "unknown"), f"SLA escalation level {new_level}", incident_id))
                message = f"Incident escalated to level {new_level}."
            else:
                return jsonify({"success": False, "error": "Unsupported SLA action. Use ACKNOWLEDGE or ESCALATE."}), 400
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": True, "incident_id": incident_id, "action": action, "message": message, "updated_at": now})
    except Exception as error:
        print("INCIDENT SLA ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not process incident SLA action.", "details": str(error)}), 500


# ============================================================
# DAY 48.2 — INCIDENT LIFECYCLE HISTORY API
# ============================================================
@app.route("/incident_lifecycle_history", methods=["GET"])
def incident_lifecycle_history():
    """Return persistent status-transition history for SOC incidents."""
    try:
        incident_id = str(request.args.get("incident_id", "")).strip()
        limit_raw = request.args.get("limit", "200")
        try:
            limit = max(1, min(int(limit_raw), 500))
        except ValueError:
            limit = 200

        conn = get_db()
        try:
            if incident_id:
                rows = conn.execute("""
                    SELECT incident_id, timestamp, from_status, to_status,
                           assigned_to, resolution_note, actor, source_ip
                    FROM incident_lifecycle_history
                    WHERE incident_id = ?
                    ORDER BY id DESC LIMIT ?
                """, (incident_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT incident_id, timestamp, from_status, to_status,
                           assigned_to, resolution_note, actor, source_ip
                    FROM incident_lifecycle_history
                    ORDER BY id DESC LIMIT ?
                """, (limit,)).fetchall()
            history = [dict(row) for row in rows]
        finally:
            conn.close()

        return jsonify({
            "success": True,
            "count": len(history),
            "incident_id": incident_id or None,
            "history": history,
            "storage": "sqlite"
        })
    except Exception as error:
        print("INCIDENT LIFECYCLE HISTORY ERROR:", str(error))
        return jsonify({
            "success": False,
            "error": "Could not load incident lifecycle history.",
            "details": str(error)
        }), 500


# ============================================================
# DAY 48.4 — AUTOMATED SLA ESCALATION & SOC NOTIFICATIONS
# ============================================================

def _create_soc_notification(conn, incident_id, source_ip, severity, event_type, message, now):
    key = f"{incident_id}:{event_type}"
    cur = conn.execute("""
        INSERT OR IGNORE INTO soc_notifications
        (notification_key, incident_id, source_ip, severity, event_type, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (key, incident_id, source_ip, severity, event_type, message, now))
    if cur.rowcount:
        notification_id = cur.lastrowid
        conn.execute("""
            INSERT INTO soc_notification_audit
            (notification_id, notification_key, incident_id, event, actor, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (notification_id, key, incident_id, "CREATED", "AI-Net", now, message))


def evaluate_incident_escalations():
    """Evaluate SLA state and persist one notification per escalation event."""
    now_dt = datetime.now()
    now = now_dt.isoformat(timespec="seconds")
    changed = []
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT incident_id, source_ip, level, lifecycle_status,
                   assigned_to, sla_due_at, sla_status, escalation_level, escalated_at
            FROM security_incidents
            WHERE sla_due_at IS NOT NULL
        """).fetchall()
        for row in rows:
            incident_id = row["incident_id"]
            level = str(row["level"] or "MEDIUM").upper()
            lifecycle = str(row["lifecycle_status"] or "OPEN").upper()
            due_raw = row["sla_due_at"]
            try:
                due_dt = datetime.fromisoformat(str(due_raw).replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                continue

            if lifecycle in {"RESOLVED", "CLOSED"}:
                if row["sla_status"] != "COMPLETED":
                    conn.execute("UPDATE security_incidents SET sla_status='COMPLETED', updated_at=? WHERE incident_id=?", (now, incident_id))
                    changed.append(incident_id)
                continue

            remaining = (due_dt - now_dt).total_seconds()
            current_level = int(row["escalation_level"] or 0)
            if remaining <= 0:
                new_status = "OVERDUE"
                desired_level = max(current_level, 1)
                event_type = "SLA_OVERDUE"
                message = f"{level} incident {incident_id} is overdue and requires immediate SOC escalation."
            elif remaining <= 900:
                new_status = "AT_RISK"
                desired_level = max(current_level, 0)
                event_type = "SLA_AT_RISK"
                message = f"{level} incident {incident_id} is within 15 minutes of its SLA deadline."
            else:
                new_status = "ON_TRACK"
                desired_level = current_level
                event_type = None
                message = None

            if row["sla_status"] != new_status or desired_level != current_level:
                conn.execute("""
                    UPDATE security_incidents
                    SET sla_status=?, escalation_level=?, escalated_at=?, updated_at=?
                    WHERE incident_id=?
                """, (new_status, desired_level, now if desired_level > current_level else row["escalated_at"], now, incident_id))
                changed.append(incident_id)

            if event_type:
                _create_soc_notification(conn, incident_id, row["source_ip"], level, event_type, message, now)

        conn.commit()
    finally:
        conn.close()
    return changed


@app.route("/soc_notifications", methods=["GET"])
def soc_notifications():
    """Return persistent SOC SLA/escalation notifications."""
    try:
        evaluate_incident_escalations()
        limit = min(max(int(request.args.get("limit", 100)), 1), 300)
        conn = get_db()
        try:
            rows = conn.execute("""
                SELECT id, incident_id, source_ip, severity, event_type, message,
                       created_at, acknowledged_at, acknowledged_by
                FROM soc_notifications
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        finally:
            conn.close()
        return jsonify({"success": True, "count": len(rows), "notifications": [dict(r) for r in rows], "storage": "sqlite"})
    except Exception as error:
        return jsonify({"success": False, "error": "Could not load SOC notifications.", "details": str(error)}), 500


@app.route("/soc_notifications/<int:notification_id>/ack", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def acknowledge_soc_notification(notification_id):
    try:
        actor = session.get("username", "Unknown")
        now = datetime.now().isoformat(timespec="seconds")
        conn = get_db()
        try:
            cur = conn.execute("""
                UPDATE soc_notifications SET acknowledged_at=?, acknowledged_by=?
                WHERE id=? AND acknowledged_at IS NULL
            """, (now, actor, notification_id))
            conn.commit()
            if cur.rowcount == 0:
                return jsonify({"success": False, "error": "Notification not found or already acknowledged."}), 404
            row = conn.execute("SELECT notification_key, incident_id FROM soc_notifications WHERE id=?", (notification_id,)).fetchone()
            conn.execute("""
                INSERT INTO soc_notification_audit
                (notification_id, notification_key, incident_id, event, actor, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (notification_id, row["notification_key"] if row else None, row["incident_id"] if row else None, "ACKNOWLEDGED", actor, now, "SOC notification acknowledged"))
        finally:
            conn.close()
        return jsonify({"success": True, "notification_id": notification_id, "acknowledged_by": actor, "acknowledged_at": now})
    except Exception as error:
        return jsonify({"success": False, "error": "Could not acknowledge notification.", "details": str(error)}), 500


@app.route("/soc_escalation_status", methods=["GET"])
def soc_escalation_status():
    try:
        evaluate_incident_escalations()
        conn = get_db()
        try:
            row = conn.execute("""
                SELECT
                  COUNT(*) AS total,
                  SUM(CASE WHEN sla_status='OVERDUE' THEN 1 ELSE 0 END) AS overdue,
                  SUM(CASE WHEN sla_status='AT_RISK' THEN 1 ELSE 0 END) AS at_risk,
                  SUM(CASE WHEN escalation_level > 0 THEN 1 ELSE 0 END) AS escalated
                FROM security_incidents
            """).fetchone()
            unread = conn.execute("SELECT COUNT(*) FROM soc_notifications WHERE acknowledged_at IS NULL").fetchone()[0]
        finally:
            conn.close()
        return jsonify({"success": True, "total_incidents": row["total"] or 0, "overdue": row["overdue"] or 0, "at_risk": row["at_risk"] or 0, "escalated": row["escalated"] or 0, "unacknowledged_notifications": unread})
    except Exception as error:
        return jsonify({"success": False, "error": "Could not load escalation status.", "details": str(error)}), 500


# ============================================================
# DAY 48.7 — SOC NOTIFICATION AUDIT & DELIVERY HISTORY
# ============================================================
@app.route("/soc_notification_audit", methods=["GET"])
@role_required("Admin", "SOC Analyst")
def soc_notification_audit():
    try:
        limit = min(max(int(request.args.get("limit", 200)), 1), 500)
        incident_id = str(request.args.get("incident_id", "")).strip()
        conn = get_db()
        try:
            if incident_id:
                rows = conn.execute("""
                    SELECT id, notification_id, notification_key, incident_id, event, actor, timestamp, details
                    FROM soc_notification_audit WHERE incident_id=? ORDER BY id DESC LIMIT ?
                """, (incident_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, notification_id, notification_key, incident_id, event, actor, timestamp, details
                    FROM soc_notification_audit ORDER BY id DESC LIMIT ?
                """, (limit,)).fetchall()
        finally:
            conn.close()
        return jsonify({"success": True, "count": len(rows), "events": [dict(r) for r in rows], "storage": "sqlite"})
    except Exception as error:
        return jsonify({"success": False, "error": "Could not load notification audit.", "details": str(error)}), 500


# ============================================================
# DAY 48.8 — SOC OPERATIONS COMMAND CENTER
# ============================================================
@app.route("/soc_command_center", methods=["GET"])
def soc_command_center():
    """Return a persistent SOC command-center view combining incidents, SLA, notifications and cases."""
    try:
        conn = get_db()
        try:
            # Incident posture
            incident_rows = conn.execute("""
                SELECT lifecycle_status, level, sla_status, escalation_level,
                       assigned_to, incident_id, source_ip, first_seen, last_seen
                FROM security_incidents
                ORDER BY COALESCE(last_seen, first_seen, '') DESC
            """).fetchall()

            # Notification posture
            notification_summary = conn.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN acknowledged_at IS NULL THEN 1 ELSE 0 END) AS unacknowledged
                FROM soc_notifications
            """).fetchone()

            # Case posture and analyst workload
            case_rows = conn.execute("""
                SELECT case_id, priority, status, assigned_to, source_ip, created_at, updated_at
                FROM soc_cases
                ORDER BY COALESCE(updated_at, created_at, '') DESC
            """).fetchall()

            workload_rows = conn.execute("""
                SELECT COALESCE(NULLIF(assigned_to,''),'Unassigned') AS analyst,
                       COUNT(*) AS total_cases,
                       SUM(CASE WHEN status NOT IN ('CLOSED','RESOLVED') THEN 1 ELSE 0 END) AS active_cases,
                       SUM(CASE WHEN priority='CRITICAL' THEN 1 ELSE 0 END) AS critical_cases
                FROM soc_cases
                GROUP BY COALESCE(NULLIF(assigned_to,''),'Unassigned')
                ORDER BY active_cases DESC, total_cases DESC
            """).fetchall()
        finally:
            conn.close()

        incidents = [dict(r) for r in incident_rows]
        cases = [dict(r) for r in case_rows]
        workload = [dict(r) for r in workload_rows]

        active_statuses = {"OPEN", "INVESTIGATING", "CONTAINED"}
        active_incidents = [r for r in incidents if str(r.get("lifecycle_status") or "OPEN").upper() in active_statuses]
        overdue = [r for r in incidents if str(r.get("sla_status") or "").upper() == "OVERDUE"]
        at_risk = [r for r in incidents if str(r.get("sla_status") or "").upper() == "AT_RISK"]
        escalated = [r for r in incidents if int(r.get("escalation_level") or 0) > 0]
        critical_incidents = [r for r in active_incidents if str(r.get("level") or "").upper() == "CRITICAL"]

        open_case_statuses = {"OPEN", "INVESTIGATING", "CONTAINED"}
        active_cases = [r for r in cases if str(r.get("status") or "OPEN").upper() in open_case_statuses]
        critical_cases = [r for r in active_cases if str(r.get("priority") or "").upper() == "CRITICAL"]

        # Produce a compact priority queue for the command center.
        queue = []
        for r in overdue:
            queue.append({
                "type": "INCIDENT_SLA",
                "priority": "CRITICAL" if str(r.get("level") or "").upper() == "CRITICAL" else "HIGH",
                "item_id": r.get("incident_id"),
                "source_ip": r.get("source_ip"),
                "status": r.get("sla_status"),
                "assigned_to": r.get("assigned_to") or "Unassigned",
                "action": "Escalate and acknowledge SLA breach"
            })
        for r in critical_incidents:
            queue.append({
                "type": "INCIDENT",
                "priority": "CRITICAL",
                "item_id": r.get("incident_id"),
                "source_ip": r.get("source_ip"),
                "status": r.get("lifecycle_status") or "OPEN",
                "assigned_to": r.get("assigned_to") or "Unassigned",
                "action": "Investigate and contain critical incident"
            })
        for r in critical_cases:
            queue.append({
                "type": "SOC_CASE",
                "priority": "CRITICAL",
                "item_id": r.get("case_id"),
                "source_ip": r.get("source_ip"),
                "status": r.get("status") or "OPEN",
                "assigned_to": r.get("assigned_to") or "Unassigned",
                "action": "Work critical case"
            })
        if int(notification_summary["unacknowledged"] or 0) > 0:
            queue.append({
                "type": "NOTIFICATION",
                "priority": "HIGH",
                "item_id": "SOC-NOTIFICATIONS",
                "source_ip": "-",
                "status": "UNACKNOWLEDGED",
                "assigned_to": "SOC Queue",
                "action": "Review and acknowledge notifications"
            })

        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        queue.sort(key=lambda x: rank.get(str(x.get("priority")).upper(), 9))

        capture_running = False
        try:
            capture_running = bool(live_sniffer is not None and live_sniffer.running)
        except Exception:
            pass

        return jsonify({
            "success": True,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "capture_running": capture_running,
            "incidents": {
                "total": len(incidents),
                "active": len(active_incidents),
                "critical_active": len(critical_incidents),
                "overdue": len(overdue),
                "at_risk": len(at_risk),
                "escalated": len(escalated)
            },
            "notifications": {
                "total": int(notification_summary["total"] or 0),
                "unacknowledged": int(notification_summary["unacknowledged"] or 0)
            },
            "cases": {
                "total": len(cases),
                "active": len(active_cases),
                "critical_active": len(critical_cases)
            },
            "analyst_workload": workload,
            "priority_queue": queue[:25],
            "storage": "sqlite"
        })
    except Exception as error:
        print("SOC COMMAND CENTER ERROR:", str(error))
        return jsonify({"success": False, "error": "Could not load SOC command center.", "details": str(error)}), 500



# ============================================================
# DAY 48.9 — SOC METRICS, KPIs & EXECUTIVE SECURITY DASHBOARD
# ============================================================
@app.route("/soc_kpi_dashboard", methods=["GET"])
def soc_kpi_dashboard():
    """Return persistent SOC KPIs for operational and executive reporting."""
    try:
        conn = get_db()
        try:
            now = datetime.now()
            since_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            since_7d = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

            detection = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(TRIM(prediction))='DDoS' THEN 1 ELSE 0 END) AS ddos,
                       AVG(CASE WHEN UPPER(TRIM(prediction))='DDoS' THEN confidence END) AS ddos_confidence
                FROM detection_events
            """).fetchone()
            detection_24 = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(TRIM(prediction))='DDoS' THEN 1 ELSE 0 END) AS ddos
                FROM detection_events WHERE timestamp >= ?
            """, (since_24h,)).fetchone()
            detection_7 = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(TRIM(prediction))='DDoS' THEN 1 ELSE 0 END) AS ddos
                FROM detection_events WHERE timestamp >= ?
            """, (since_7d,)).fetchone()

            incidents = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(TRIM(level))='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN UPPER(TRIM(lifecycle_status)) IN ('OPEN','INVESTIGATING','CONTAINED') THEN 1 ELSE 0 END) AS active,
                       SUM(CASE WHEN UPPER(TRIM(sla_status))='OVERDUE' THEN 1 ELSE 0 END) AS overdue,
                       SUM(CASE WHEN UPPER(TRIM(sla_status))='AT_RISK' THEN 1 ELSE 0 END) AS at_risk,
                       SUM(CASE WHEN UPPER(TRIM(sla_status)) IN ('COMPLETED','ON_TRACK') THEN 1 ELSE 0 END) AS sla_ok
                FROM security_incidents
            """).fetchone()

            cases = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN UPPER(TRIM(status)) IN ('OPEN','INVESTIGATING','CONTAINED') THEN 1 ELSE 0 END) AS active,
                       SUM(CASE WHEN UPPER(TRIM(status)) IN ('CLOSED','RESOLVED') THEN 1 ELSE 0 END) AS closed,
                       SUM(CASE WHEN UPPER(TRIM(priority))='CRITICAL' THEN 1 ELSE 0 END) AS critical
                FROM soc_cases
            """).fetchone()

            notifications = conn.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN acknowledged_at IS NOT NULL THEN 1 ELSE 0 END) AS acknowledged,
                       SUM(CASE WHEN acknowledged_at IS NULL THEN 1 ELSE 0 END) AS unacknowledged
                FROM soc_notifications
            """).fetchone()

            responses = conn.execute("SELECT COUNT(*) AS total FROM incident_response_actions").fetchone()
            audit = conn.execute("SELECT COUNT(*) AS total FROM soc_notification_audit").fetchone()
            workload = conn.execute("""
                SELECT COALESCE(NULLIF(assigned_to,''),'Unassigned') AS owner,
                       COUNT(*) AS total_cases,
                       SUM(CASE WHEN UPPER(TRIM(status)) NOT IN ('CLOSED','RESOLVED') THEN 1 ELSE 0 END) AS active_cases
                FROM soc_cases GROUP BY COALESCE(NULLIF(assigned_to,''),'Unassigned')
                ORDER BY active_cases DESC, total_cases DESC
            """).fetchall()
        finally:
            conn.close()

        def num(row, key):
            try:
                return int(row[key] or 0)
            except Exception:
                return 0

        total_det = num(detection, 'total')
        ddos = num(detection, 'ddos')
        total_notif = num(notifications, 'total')
        ack = num(notifications, 'acknowledged')
        total_cases = num(cases, 'total')
        closed_cases = num(cases, 'closed')
        total_inc = num(incidents, 'total')
        sla_ok = num(incidents, 'sla_ok')

        attack_rate = round((ddos / total_det * 100), 2) if total_det else 0.0
        notification_ack_rate = round((ack / total_notif * 100), 2) if total_notif else 100.0
        case_closure_rate = round((closed_cases / total_cases * 100), 2) if total_cases else 100.0
        sla_compliance = round((sla_ok / total_inc * 100), 2) if total_inc else 100.0
        avg_conf = float(detection['ddos_confidence'] or 0)

        if num(incidents, 'overdue') > 0 or num(incidents, 'critical') > 0:
            posture = 'ATTENTION_REQUIRED'
        elif attack_rate >= 10 or num(incidents, 'at_risk') > 0:
            posture = 'ELEVATED'
        else:
            posture = 'STABLE'

        return jsonify({
            'success': True,
            'updated_at': now.isoformat(timespec='seconds'),
            'storage': 'sqlite',
            'posture': posture,
            'detection': {
                'total': total_det, 'ddos': ddos, 'attack_rate': attack_rate,
                'average_ddos_confidence': round(avg_conf, 2),
                'last_24h_total': num(detection_24, 'total'), 'last_24h_ddos': num(detection_24, 'ddos'),
                'last_7d_total': num(detection_7, 'total'), 'last_7d_ddos': num(detection_7, 'ddos')
            },
            'incidents': {
                'total': total_inc, 'active': num(incidents, 'active'), 'critical': num(incidents, 'critical'),
                'overdue': num(incidents, 'overdue'), 'at_risk': num(incidents, 'at_risk'),
                'sla_compliance': sla_compliance
            },
            'cases': {
                'total': total_cases, 'active': num(cases, 'active'), 'closed': closed_cases,
                'critical': num(cases, 'critical'), 'closure_rate': case_closure_rate
            },
            'notifications': {
                'total': total_notif, 'acknowledged': ack, 'unacknowledged': num(notifications, 'unacknowledged'),
                'acknowledgement_rate': notification_ack_rate
            },
            'response_actions': num(responses, 'total'),
            'notification_audit_events': num(audit, 'total'),
            'analyst_workload': [dict(r) for r in workload],
            'kpi_definitions': {
                'attack_rate': 'DDoS detections divided by all persisted detection events.',
                'sla_compliance': 'Incidents in completed or on-track SLA states divided by all incidents.',
                'case_closure_rate': 'Closed/resolved SOC cases divided by all SOC cases.',
                'notification_acknowledgement_rate': 'Acknowledged notifications divided by all notifications.'
            }
        })
    except Exception as error:
        print('SOC KPI DASHBOARD ERROR:', str(error))
        return jsonify({'success': False, 'error': 'Could not load SOC KPI dashboard.', 'details': str(error)}), 500

# ============================================================
# RUN FLASK SERVER
# ============================================================


# ============================================================
# DAY 48.10 — SOC EXECUTIVE REPORTING & AUTOMATED SECURITY SUMMARY
# ============================================================

def _executive_metrics():
    """Build an executive security snapshot entirely from SQLite."""
    conn = get_db()
    try:
        total = int(conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0])
        ddos = int(conn.execute(
            "SELECT COUNT(*) FROM detection_events "
            "WHERE UPPER(TRIM(prediction))='DDoS'"
        ).fetchone()[0])
        benign = max(total - ddos, 0)

        avg_conf_row = conn.execute(
            "SELECT AVG(confidence) FROM detection_events "
            "WHERE UPPER(TRIM(prediction))='DDoS'"
        ).fetchone()[0]
        avg_conf = float(avg_conf_row or 0)

        incidents = int(conn.execute(
            "SELECT COUNT(*) FROM security_incidents"
        ).fetchone()[0])
        critical_incidents = int(conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE UPPER(level)='CRITICAL'"
        ).fetchone()[0])
        active_incidents = int(conn.execute(
            "SELECT COUNT(*) FROM security_incidents "
            "WHERE UPPER(COALESCE(lifecycle_status,'OPEN')) NOT IN ('RESOLVED','CLOSED')"
        ).fetchone()[0])
        overdue = int(conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE UPPER(COALESCE(sla_status,''))='OVERDUE' "
            "AND UPPER(COALESCE(lifecycle_status,'OPEN')) NOT IN ('RESOLVED','CLOSED')"
        ).fetchone()[0])
        escalated = int(conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE COALESCE(escalation_level,0) > 0 "
            "AND UPPER(COALESCE(lifecycle_status,'OPEN')) NOT IN ('RESOLVED','CLOSED')"
        ).fetchone()[0])

        cases = int(conn.execute("SELECT COUNT(*) FROM soc_cases").fetchone()[0])
        open_cases = int(conn.execute(
            "SELECT COUNT(*) FROM soc_cases WHERE UPPER(COALESCE(status,'OPEN')) <> 'CLOSED'"
        ).fetchone()[0])
        closed_cases = int(conn.execute(
            "SELECT COUNT(*) FROM soc_cases WHERE UPPER(COALESCE(status,''))='CLOSED'"
        ).fetchone()[0])

        notifications = int(conn.execute(
            "SELECT COUNT(*) FROM soc_notifications"
        ).fetchone()[0])
        unack = int(conn.execute(
            "SELECT COUNT(*) FROM soc_notifications WHERE acknowledged_at IS NULL"
        ).fetchone()[0])

        actions = int(conn.execute(
            "SELECT COUNT(*) FROM incident_response_actions"
        ).fetchone()[0])

        now = datetime.now()
        day_ago = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        last24 = int(conn.execute(
            "SELECT COUNT(*) FROM detection_events WHERE timestamp >= ?", (day_ago,)
        ).fetchone()[0])
        ddos24 = int(conn.execute(
            "SELECT COUNT(*) FROM detection_events "
            "WHERE timestamp >= ? AND UPPER(TRIM(prediction))='DDoS'", (day_ago,)
        ).fetchone()[0])
        last7 = int(conn.execute(
            "SELECT COUNT(*) FROM detection_events WHERE timestamp >= ?", (week_ago,)
        ).fetchone()[0])
        ddos7 = int(conn.execute(
            "SELECT COUNT(*) FROM detection_events "
            "WHERE timestamp >= ? AND UPPER(TRIM(prediction))='DDoS'", (week_ago,)
        ).fetchone()[0])

        attack_rate = (ddos / total * 100) if total else 0
        sla_compliance = max(0, 100 - (overdue / incidents * 100)) if incidents else 100
        case_closure = (closed_cases / cases * 100) if cases else 100
        notification_ack = ((notifications - unack) / notifications * 100) if notifications else 100

        if attack_rate >= 50 or critical_incidents >= 5:
            posture = "CRITICAL"
        elif attack_rate >= 10 or overdue > 0 or critical_incidents > 0:
            posture = "HIGH"
        elif attack_rate > 0 or active_incidents > 0 or unack > 0:
            posture = "ELEVATED"
        else:
            posture = "NORMAL"

        return {
            "generated_at": now.isoformat(timespec="seconds"),
            "posture": posture,
            "total_flows": total,
            "ddos_flows": ddos,
            "benign_flows": benign,
            "attack_rate": round(attack_rate, 2),
            "average_ddos_confidence": round(avg_conf, 2),
            "incidents": incidents,
            "active_incidents": active_incidents,
            "critical_incidents": critical_incidents,
            "overdue_incidents": overdue,
            "escalated_incidents": escalated,
            "soc_cases": cases,
            "open_cases": open_cases,
            "closed_cases": closed_cases,
            "case_closure_rate": round(case_closure, 2),
            "notifications": notifications,
            "unacknowledged_notifications": unack,
            "notification_ack_rate": round(notification_ack, 2),
            "response_actions": actions,
            "sla_compliance": round(sla_compliance, 2),
            "last_24h_flows": last24,
            "last_24h_ddos": ddos24,
            "last_7d_flows": last7,
            "last_7d_ddos": ddos7,
        }
    finally:
        conn.close()


def _executive_summary_text(metrics):
    posture = metrics["posture"]
    if posture == "CRITICAL":
        headline = "Immediate executive attention is required."
    elif posture == "HIGH":
        headline = "The environment has material security risk requiring prompt SOC attention."
    elif posture == "ELEVATED":
        headline = "The environment shows active security signals that should remain under SOC observation."
    else:
        headline = "The current telemetry indicates a stable security posture."

    return (
        f"Security posture: {posture}. {headline} "
        f"The platform recorded {metrics['ddos_flows']} DDoS detections across "
        f"{metrics['total_flows']} analyzed flows, an attack rate of "
        f"{metrics['attack_rate']:.2f}%. "
        f"There are {metrics['active_incidents']} active incidents, "
        f"{metrics['overdue_incidents']} overdue SLAs, and "
        f"{metrics['unacknowledged_notifications']} unacknowledged notifications. "
        f"SOC case closure is {metrics['case_closure_rate']:.2f}% and "
        f"notification acknowledgement is {metrics['notification_ack_rate']:.2f}%."
    )


@app.route("/soc_executive_report", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_executive_report():
    metrics = _executive_metrics()
    return jsonify({
        "status": "OK",
        "metrics": metrics,
        "executive_summary": _executive_summary_text(metrics),
        "recommendations": [
            "Review all overdue incident SLAs.",
            "Investigate unacknowledged high-severity notifications.",
            "Prioritize critical and escalated incidents.",
            "Continue monitoring DDoS detection trends and SOC case closure."
        ],
    })




# ============================================================
# DAY 48.11 — SOC REPORTING HISTORY & REPORT ARCHIVE
# ============================================================

def _archive_report(report_type, generated_at, posture, file_name, file_path,
                   summary, generated_by=None, retention_days=90):
    """Persist a generated report plus a cryptographic integrity fingerprint."""
    report_id = "RPT-" + datetime.now().strftime("%Y%m%d%H%M%S%f")
    if generated_by is None:
        try:
            user = current_user() or {}
            generated_by = user.get("username", "system")
        except RuntimeError:
            generated_by = "AI-Net Scheduler"

    sha256 = None
    file_size = None
    integrity_status = "FILE_MISSING"
    if file_path and os.path.isfile(file_path):
        digest = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()
        file_size = os.path.getsize(file_path)
        integrity_status = "VERIFIED"
    retention_until = (
        datetime.fromisoformat(generated_at) + timedelta(days=int(retention_days))
    ).isoformat(timespec="seconds")

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO soc_report_archive
            (report_id, report_type, generated_at, generated_by, posture,
             file_name, file_path, summary, sha256, file_size,
             integrity_status, retention_until, verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id, report_type, generated_at, generated_by, posture,
            file_name, file_path, summary, sha256, file_size,
            integrity_status, retention_until,
            generated_at if sha256 else None
        ))
        conn.commit()
    finally:
        conn.close()
    # Version 1 is recorded immediately when a report is archived.
    try:
        conn = get_db()
        report_row = conn.execute("SELECT * FROM soc_report_archive WHERE report_id=?", (report_id,)).fetchone()
        conn.close()
        if report_row:
            _create_report_version(dict(report_row), "Initial archived report version", "GENERATED")
    except Exception:
        pass
    return report_id


def _verify_report_file(report):
    """Compare the archived SHA-256 and size with the current PDF."""
    path = report.get("file_path")
    if not path or not os.path.isfile(path):
        return {
            "status": "MISSING",
            "sha256": None,
            "file_size": None,
            "checked_at": datetime.now().isoformat(timespec="seconds")
        }

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    current_hash = digest.hexdigest()
    current_size = os.path.getsize(path)
    expected_hash = report.get("sha256")
    expected_size = report.get("file_size")

    if expected_hash and expected_size is not None:
        ok = (current_hash == expected_hash and int(current_size) == int(expected_size))
    else:
        ok = False

    return {
        "status": "VERIFIED" if ok else "TAMPERED",
        "sha256": current_hash,
        "file_size": current_size,
        "checked_at": datetime.now().isoformat(timespec="seconds")
    }


@app.route("/soc_report_archive", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_archive():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT id, report_id, report_type, generated_at, generated_by,
                   posture, file_name, file_path, summary, sha256, file_size,
                   integrity_status, retention_until, verified_at
            FROM soc_report_archive
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()
        return jsonify({
            "status": "OK",
            "reports": [dict(row) for row in rows]
        })
    finally:
        conn.close()


@app.route("/soc_report_archive/<report_id>", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_archive_detail(report_id):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT id, report_id, report_type, generated_at, generated_by,
                   posture, file_name, file_path, summary, sha256, file_size,
                   integrity_status, retention_until, verified_at
            FROM soc_report_archive
            WHERE report_id = ?
        """, (report_id,)).fetchone()
        if not row:
            return jsonify({"error": "Report not found."}), 404

        item = dict(row)
        available = bool(item.get("file_path") and os.path.isfile(item["file_path"]))
        item["file_available"] = available
        return jsonify({"status": "OK", "report": item})
    finally:
        conn.close()



def _generate_executive_report_pdf(generated_by="AI-Net Scheduler", report_type="SCHEDULED_EXECUTIVE_SECURITY_REPORT"):
    """Generate and archive an executive security PDF. Returns report metadata."""
    metrics = _executive_metrics()
    report_dir = os.path.join(BASE_DIR, "logs", "reports")
    os.makedirs(report_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = os.path.join(report_dir, f"soc_executive_security_report_{stamp}.pdf")

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ExecutiveTitle", parent=styles["Title"], alignment=TA_CENTER,
                           fontSize=20, leading=24, spaceAfter=12)
    summary = _executive_summary_text(metrics)
    story = [
        Paragraph("AI-Net SOC Executive Security Report", title),
        Paragraph(f"Generated: {metrics['generated_at']}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(summary, styles["BodyText"]),
        Spacer(1, 16),
    ]

    rows = [
        ["Metric", "Value"],
        ["Security Posture", metrics["posture"]],
        ["Total Flows", f"{metrics['total_flows']:,}"],
        ["DDoS Flows", f"{metrics['ddos_flows']:,}"],
        ["Attack Rate", f"{metrics['attack_rate']:.2f}%"],
        ["Avg. DDoS Confidence", f"{metrics['average_ddos_confidence']:.2f}%"],
        ["Active Incidents", f"{metrics['active_incidents']:,}"],
        ["Critical Incidents", f"{metrics['critical_incidents']:,}"],
        ["Overdue SLAs", f"{metrics['overdue_incidents']:,}"],
        ["Escalated Incidents", f"{metrics['escalated_incidents']:,}"],
        ["Open SOC Cases", f"{metrics['open_cases']:,}"],
        ["Case Closure Rate", f"{metrics['case_closure_rate']:.2f}%"],
        ["Unacknowledged Notifications", f"{metrics['unacknowledged_notifications']:,}"],
        ["Notification Ack Rate", f"{metrics['notification_ack_rate']:.2f}%"],
        ["Response Actions", f"{metrics['response_actions']:,}"],
        ["SLA Compliance", f"{metrics['sla_compliance']:.2f}%"],
        ["Last 24h DDoS", f"{metrics['last_24h_ddos']:,}"],
        ["Last 7d DDoS", f"{metrics['last_7d_ddos']:,}"],
    ]
    table = Table(rows, colWidths=[280, 180])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0,0), (-1,-1), 7),
    ]))
    story.append(table)
    story.append(Spacer(1, 18))
    story.append(Paragraph("Recommended Executive Actions", styles["Heading2"]))
    for item in [
        "Review all overdue incident SLAs.",
        "Investigate unacknowledged high-severity notifications.",
        "Prioritize critical and escalated incidents.",
        "Continue monitoring DDoS detection trends and SOC case closure."
    ]:
        story.append(Paragraph("• " + item, styles["BodyText"]))
        story.append(Spacer(1, 5))

    doc.build(story)
    report_id = _archive_report(
        report_type,
        metrics["generated_at"],
        metrics["posture"],
        os.path.basename(path),
        path,
        summary,
        generated_by=generated_by
    )
    return {
        "report_id": report_id,
        "path": path,
        "file_name": os.path.basename(path),
        "metrics": metrics,
        "summary": summary,
        "generated_by": generated_by,
        "report_type": report_type,
    }


@app.route("/soc_executive_report/pdf", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_executive_report_pdf():
    """Generate a concise executive security report PDF."""
    try:
        result = _generate_executive_report_pdf(
            generated_by=(current_user() or {}).get("username", "system"),
            report_type="EXECUTIVE_SECURITY_REPORT"
        )
        response = send_file(
            result["path"],
            as_attachment=True,
            download_name=result["file_name"],
            mimetype="application/pdf"
        )
        response.headers["X-AI-Net-Report-ID"] = result["report_id"]
        return response
    except Exception as exc:
        return jsonify({"error": f"Executive report generation failed: {exc}"}), 500



@app.route("/soc_report_archive/verify/<report_id>", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def verify_soc_report_archive(report_id):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM soc_report_archive WHERE report_id = ?
        """, (report_id,)).fetchone()
        if not row:
            return jsonify({"status": "ERROR", "error": "Report not found."}), 404
        report = dict(row)
        result = _verify_report_file(report)
        conn.execute("""
            UPDATE soc_report_archive
            SET integrity_status=?, verified_at=?
            WHERE report_id=?
        """, (result["status"], result["checked_at"], report_id))
        conn.commit()
        return jsonify({
            "status": "OK",
            "report_id": report_id,
            "integrity": result
        })
    finally:
        conn.close()


@app.route("/soc_report_archive/integrity", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_archive_integrity():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM soc_report_archive ORDER BY id DESC LIMIT 100").fetchall()
        results = []
        verified = tampered = missing = 0
        for row in rows:
            report = dict(row)
            result = _verify_report_file(report)
            results.append({
                "report_id": report["report_id"],
                "file_name": report["file_name"],
                "integrity_status": result["status"],
                "generated_at": report["generated_at"],
                "retention_until": report.get("retention_until")
            })
            if result["status"] == "VERIFIED":
                verified += 1
            elif result["status"] == "TAMPERED":
                tampered += 1
            else:
                missing += 1
        return jsonify({
            "status": "OK",
            "total": len(results),
            "verified": verified,
            "tampered": tampered,
            "missing": missing,
            "reports": results
        })
    finally:
        conn.close()


@app.route("/soc_report_archive/retention", methods=["POST"])
@role_required("Admin")
def apply_report_retention():
    payload = request.get_json(silent=True) or {}
    try:
        retention_days = int(payload.get("retention_days", 90))
        if retention_days < 1 or retention_days > 3650:
            raise ValueError("Retention must be between 1 and 3650 days.")
        cutoff = datetime.now() - timedelta(days=retention_days)

        conn = get_db()
        try:
            rows = conn.execute("""
                SELECT id, report_id, file_path, generated_at
                FROM soc_report_archive
                WHERE generated_at < ?
            """, (cutoff.isoformat(timespec="seconds"),)).fetchall()

            deleted_files = 0
            deleted_records = 0
            for row in rows:
                path = row["file_path"]
                if path and os.path.isfile(path):
                    os.remove(path)
                    deleted_files += 1
                conn.execute("DELETE FROM soc_report_archive WHERE id=?", (row["id"],))
                deleted_records += 1
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            "status": "OK",
            "retention_days": retention_days,
            "deleted_files": deleted_files,
            "deleted_records": deleted_records
        })
    except (TypeError, ValueError) as exc:
        return jsonify({"status": "ERROR", "error": str(exc)}), 400












# ============================================================
# DAY 48.22 — SOC GOVERNANCE CERTIFICATION & SIGN-OFF
# ============================================================

GOV_CERT_STATES = {"DRAFT", "REVIEW", "CERTIFIED", "REJECTED"}

def _ensure_governance_certification(report_id):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM soc_report_governance_certifications
            WHERE report_id=?
        """, (report_id,)).fetchone()
        if row:
            return dict(row)

        findings = _governance_check(report_id)
        severities = {"NORMAL": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        governance_status = max(
            (x["severity"] for x in findings),
            key=lambda x: severities.get(x, 0),
            default="NORMAL"
        )
        now = datetime.now().isoformat(timespec="seconds")
        cert_id = "CERT-" + uuid4().hex[:12].upper()

        conn.execute("""
            INSERT INTO soc_report_governance_certifications
            (certification_id, report_id, governance_status, state,
             created_at, updated_at)
            VALUES (?, ?, ?, 'DRAFT', ?, ?)
        """, (cert_id, report_id, governance_status, now, now))

        conn.execute("""
            INSERT INTO soc_report_governance_cert_history
            (certification_id, report_id, from_state, to_state,
             actor, timestamp, note)
            VALUES (?, ?, NULL, 'DRAFT', ?, ?, ?)
        """, (cert_id, report_id, "system", now, "Certification record initialized."))
        conn.commit()

        return dict(conn.execute("""
            SELECT * FROM soc_report_governance_certifications
            WHERE certification_id=?
        """, (cert_id,)).fetchone())
    finally:
        conn.close()


def _cert_transition_allowed(role, current_state, target_state):
    if target_state not in GOV_CERT_STATES:
        return False
    if role == "Admin":
        return target_state != current_state
    if role == "SOC Analyst":
        return (
            (current_state == "DRAFT" and target_state == "REVIEW") or
            (current_state == "REVIEW" and target_state in {"CERTIFIED", "REJECTED"}) or
            (current_state == "REJECTED" and target_state == "REVIEW")
        )
    return False


def _refresh_governance_cert_status(report_id):
    findings = _governance_check(report_id)
    severity_order = {"NORMAL": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    status = max(
        (x["severity"] for x in findings),
        key=lambda x: severity_order.get(x, 0),
        default="NORMAL"
    )
    conn = get_db()
    try:
        conn.execute("""
            UPDATE soc_report_governance_certifications
            SET governance_status=?, updated_at=?
            WHERE report_id=?
        """, (status, datetime.now().isoformat(timespec="seconds"), report_id))
        conn.commit()
    finally:
        conn.close()
    return status, findings


@app.route("/soc_report_governance/certifications", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_governance_certifications():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT * FROM soc_report_governance_certifications
            ORDER BY updated_at DESC
        """).fetchall()
        return jsonify({"status": "OK", "certifications": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/soc_report_governance/<report_id>/certify/initialize", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def initialize_governance_certification(report_id):
    conn = get_db()
    try:
        exists = conn.execute(
            "SELECT 1 FROM soc_report_archive WHERE report_id=?",
            (report_id,)
        ).fetchone()
    finally:
        conn.close()

    if not exists:
        return jsonify({"status": "ERROR", "error": "Report not found."}), 404

    cert = _ensure_governance_certification(report_id)
    return jsonify({"status": "OK", "certification": cert})


@app.route("/soc_report_governance/certifications/<certification_id>", methods=["PATCH"])
@role_required("Admin", "SOC Analyst")
def update_governance_certification(certification_id):
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("state", "")).upper().strip()
    note = str(payload.get("note", "")).strip()
    rejection_reason = str(payload.get("rejection_reason", "")).strip()

    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM soc_report_governance_certifications
            WHERE certification_id=?
        """, (certification_id,)).fetchone()
        if not row:
            return jsonify({"status": "ERROR", "error": "Certification not found."}), 404

        cert = dict(row)
        role = (current_user() or {}).get("role", "Viewer")
        current_state = cert["state"]

        if not _cert_transition_allowed(role, current_state, target):
            return jsonify({
                "status": "ERROR",
                "error": f"Transition {current_state} → {target} is not allowed for {role}."
            }), 403

        if target == "REJECTED" and not rejection_reason and not note:
            return jsonify({
                "status": "ERROR",
                "error": "A rejection reason or note is required."
            }), 400

        # Certification requires a clean governance check.
        if target == "CERTIFIED":
            _, findings = _refresh_governance_cert_status(cert["report_id"])
            failures = [x for x in findings if x["status"] == "FAIL"]
            if failures:
                return jsonify({
                    "status": "ERROR",
                    "error": "Report cannot be certified while governance checks contain failures.",
                    "failures": failures
                }), 409

        actor = (current_user() or {}).get("username", "system")
        now = datetime.now().isoformat(timespec="seconds")
        certified_by = cert.get("certified_by")
        certified_at = cert.get("certified_at")

        if target == "CERTIFIED":
            certified_by = actor
            certified_at = now

        conn.execute("""
            UPDATE soc_report_governance_certifications
            SET state=?, certified_by=?, certified_at=?,
                certification_note=?, rejection_reason=?, updated_at=?
            WHERE certification_id=?
        """, (
            target, certified_by, certified_at,
            note or cert.get("certification_note"),
            rejection_reason or (None if target != "REJECTED" else cert.get("rejection_reason")),
            now, certification_id
        ))

        conn.execute("""
            INSERT INTO soc_report_governance_cert_history
            (certification_id, report_id, from_state, to_state,
             actor, timestamp, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            certification_id, cert["report_id"], current_state, target,
            actor, now, note or rejection_reason or ""
        ))
        conn.commit()

        _write_report_compliance_audit(
            cert["report_id"], "GOVERNANCE_CERTIFICATION",
            actor, "SUCCESS", f"{current_state} → {target}"
        )

        updated = conn.execute("""
            SELECT * FROM soc_report_governance_certifications
            WHERE certification_id=?
        """, (certification_id,)).fetchone()
        return jsonify({"status": "OK", "certification": dict(updated)})
    finally:
        conn.close()


@app.route("/soc_report_governance/certification_history", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def governance_certification_history():
    report_id = request.args.get("report_id")
    conn = get_db()
    try:
        if report_id:
            rows = conn.execute("""
                SELECT * FROM soc_report_governance_cert_history
                WHERE report_id=?
                ORDER BY id DESC LIMIT 200
            """, (report_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM soc_report_governance_cert_history
                ORDER BY id DESC LIMIT 200
            """).fetchall()
        return jsonify({"status": "OK", "history": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/soc_report_governance/certification_summary", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def governance_certification_summary():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT state, COUNT(*) AS count
            FROM soc_report_governance_certifications
            GROUP BY state
        """).fetchall()
        summary = {r["state"]: r["count"] for r in rows}
        return jsonify({
            "status": "OK",
            "draft": summary.get("DRAFT", 0),
            "review": summary.get("REVIEW", 0),
            "certified": summary.get("CERTIFIED", 0),
            "rejected": summary.get("REJECTED", 0)
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.21 — SOC REPORT GOVERNANCE & EVIDENCE INTEGRITY
# ============================================================

def _governance_check(report_id):
    state = _report_compliance_state(report_id)
    findings = []
    report = state.get("report")
    approval = state.get("approval")
    version = state.get("version")
    delivery = state.get("delivery") or {}
    downloads = state.get("downloads") or {}

    if not report:
        return [{
            "check_type": "ARCHIVE",
            "status": "FAIL",
            "severity": "CRITICAL",
            "details": "Archive record does not exist."
        }]

    if not approval:
        findings.append({
            "check_type": "APPROVAL_CHAIN",
            "status": "FAIL",
            "severity": "HIGH",
            "details": "No approval workflow record exists."
        })
    else:
        state_name = str(approval.get("state") or "").upper()
        if state_name == "PUBLISHED":
            findings.append({
                "check_type": "APPROVAL_CHAIN",
                "status": "PASS",
                "severity": "NORMAL",
                "details": "Report has reached PUBLISHED state."
            })
        elif state_name == "REJECTED":
            findings.append({
                "check_type": "APPROVAL_CHAIN",
                "status": "FAIL",
                "severity": "HIGH",
                "details": "Report is REJECTED."
            })
        else:
            findings.append({
                "check_type": "APPROVAL_CHAIN",
                "status": "WARN",
                "severity": "MEDIUM",
                "details": f"Approval state is {state_name}; report is not published."
            })

    if version:
        same_hash = (
            not report.get("sha256") or
            not version.get("sha256") or
            str(report.get("sha256")) == str(version.get("sha256"))
        )
        findings.append({
            "check_type": "VERSION_INTEGRITY",
            "status": "PASS" if same_hash else "FAIL",
            "severity": "NORMAL" if same_hash else "CRITICAL",
            "details": "Archive and latest version hashes are consistent."
                if same_hash else
                "Archive and latest version hashes differ."
        })
    else:
        findings.append({
            "check_type": "VERSION_INTEGRITY",
            "status": "WARN",
            "severity": "MEDIUM",
            "details": "No version record is initialized."
        })

    integrity = str(report.get("integrity_status") or "").upper()
    integrity_ok = integrity in {"VERIFIED", "OK"}
    findings.append({
        "check_type": "FILE_INTEGRITY",
        "status": "PASS" if integrity_ok else "WARN",
        "severity": "NORMAL" if integrity_ok else "MEDIUM",
        "details": f"Stored integrity status: {integrity or 'UNKNOWN'}."
    })

    retention = _parse_dt(report.get("retention_until"))
    if retention and retention < datetime.now():
        findings.append({
            "check_type": "RETENTION",
            "status": "FAIL",
            "severity": "HIGH",
            "details": "Retention deadline has passed."
        })
    else:
        findings.append({
            "check_type": "RETENTION",
            "status": "PASS",
            "severity": "NORMAL",
            "details": "Retention deadline is current or not configured."
        })

    if str(approval.get("state") if approval else "").upper() != "PUBLISHED" and int(delivery.get("sent") or 0) > 0:
        findings.append({
            "check_type": "DISTRIBUTION_CONTROL",
            "status": "FAIL",
            "severity": "CRITICAL",
            "details": "A delivery is marked SENT while the report is not PUBLISHED."
        })
    else:
        findings.append({
            "check_type": "DISTRIBUTION_CONTROL",
            "status": "PASS",
            "severity": "NORMAL",
            "details": f"Delivery records: {int(delivery.get('total') or 0)}; sent: {int(delivery.get('sent') or 0)}."
        })

    if int(downloads.get("denied_or_failed") or 0) > 0:
        findings.append({
            "check_type": "ACCESS_AUDIT",
            "status": "WARN",
            "severity": "MEDIUM",
            "details": f"{int(downloads.get('denied_or_failed') or 0)} denied/failed download events recorded."
        })
    else:
        findings.append({
            "check_type": "ACCESS_AUDIT",
            "status": "PASS",
            "severity": "NORMAL",
            "details": "No denied/failed report download events recorded."
        })

    return findings


def _persist_governance_results(report_id, findings, actor):
    now = datetime.now().isoformat(timespec="seconds")
    conn = get_db()
    try:
        for item in findings:
            conn.execute("""
                INSERT INTO soc_report_governance_audit
                (governance_id, report_id, check_type, status, severity,
                 checked_at, checked_by, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "GOV-" + uuid4().hex[:12].upper(),
                report_id,
                item["check_type"],
                item["status"],
                item["severity"],
                now,
                actor or "-",
                item["details"]
            ))
        conn.commit()
    finally:
        conn.close()


@app.route("/soc_report_governance", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_governance():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT report_id FROM soc_report_archive
            ORDER BY generated_at DESC
        """).fetchall()
    finally:
        conn.close()

    actor = (current_user() or {}).get("username", "system")
    reports = []
    order = {"NORMAL": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    for row in rows:
        findings = _governance_check(row["report_id"])
        worst = max(
            (x["severity"] for x in findings),
            key=lambda x: order.get(x, 0),
            default="NORMAL"
        )
        reports.append({
            "report_id": row["report_id"],
            "governance_status": worst,
            "pass_count": sum(x["status"] == "PASS" for x in findings),
            "warn_count": sum(x["status"] == "WARN" for x in findings),
            "fail_count": sum(x["status"] == "FAIL" for x in findings),
            "findings": findings
        })

    counts = {
        "reports": len(reports),
        "healthy": sum(x["governance_status"] == "NORMAL" for x in reports),
        "medium": sum(x["governance_status"] == "MEDIUM" for x in reports),
        "high": sum(x["governance_status"] == "HIGH" for x in reports),
        "critical": sum(x["governance_status"] == "CRITICAL" for x in reports),
        "checks": sum(x["pass_count"] + x["warn_count"] + x["fail_count"] for x in reports),
        "failures": sum(x["fail_count"] for x in reports)
    }

    return jsonify({
        "status": "OK",
        "counts": counts,
        "reports": reports,
        "checked_by": actor,
        "checked_at": datetime.now().isoformat(timespec="seconds")
    })


@app.route("/soc_report_governance/<report_id>/check", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def check_soc_report_governance(report_id):
    conn = get_db()
    try:
        exists = conn.execute(
            "SELECT 1 FROM soc_report_archive WHERE report_id=?",
            (report_id,)
        ).fetchone()
    finally:
        conn.close()

    if not exists:
        return jsonify({"status": "ERROR", "error": "Report not found."}), 404

    actor = (current_user() or {}).get("username", "system")
    findings = _governance_check(report_id)
    _persist_governance_results(report_id, findings, actor)
    _write_report_compliance_audit(
        report_id, "GOVERNANCE_CHECK", actor, "SUCCESS",
        f"Governance check completed with {sum(x['status']=='FAIL' for x in findings)} failure(s)."
    )

    return jsonify({
        "status": "OK",
        "report_id": report_id,
        "findings": findings
    })


@app.route("/soc_report_governance/audit", methods=["GET"])
@role_required("Admin", "SOC Analyst")
def soc_report_governance_audit():
    limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT governance_id, report_id, check_type, status,
                   severity, checked_at, checked_by, details
            FROM soc_report_governance_audit
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return jsonify({
            "status": "OK",
            "events": [dict(row) for row in rows]
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.20 — SOC COMPLIANCE EVIDENCE & AUDIT EXPORT
# ============================================================

def _build_compliance_payload():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT report_id FROM soc_report_archive
            ORDER BY generated_at DESC
        """).fetchall()
    finally:
        conn.close()

    reports = []
    for row in rows:
        state = _report_compliance_state(row["report_id"])
        findings = _compliance_findings(state)
        order = {"NORMAL": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        status = max(
            (f["severity"] for f in findings),
            key=lambda x: order.get(x, 0),
            default="NORMAL"
        )
        reports.append({
            "report_id": row["report_id"],
            "approval_state": (state["approval"] or {}).get("state", "NOT_INITIALIZED"),
            "integrity_status": (state["report"] or {}).get("integrity_status") or "UNKNOWN",
            "retention_until": (state["report"] or {}).get("retention_until"),
            "compliance_status": status,
            "findings": findings
        })

    counts = {
        "reports": len(reports),
        "published": sum(x["approval_state"] == "PUBLISHED" for x in reports),
        "verified": sum(str(x["integrity_status"]).upper() in {"VERIFIED", "OK"} for x in reports),
        "critical_findings": sum(x["compliance_status"] == "CRITICAL" for x in reports),
        "high_findings": sum(x["compliance_status"] == "HIGH" for x in reports),
        "medium_findings": sum(x["compliance_status"] == "MEDIUM" for x in reports)
    }
    return {"counts": counts, "reports": reports}


def _save_compliance_snapshot(payload, actor):
    snapshot_id = "RCS-" + uuid4().hex[:12].upper()
    now = datetime.now().isoformat(timespec="seconds")
    c = payload["counts"]
    summary = (
        f"{c['reports']} reports; {c['published']} published; "
        f"{c['verified']} integrity verified; "
        f"{c['critical_findings']} critical, {c['high_findings']} high, "
        f"{c['medium_findings']} medium findings."
    )

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO soc_report_compliance_snapshots
            (snapshot_id, created_at, created_by, report_count,
             published_count, verified_count, critical_findings,
             high_findings, medium_findings, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot_id, now, actor or "-",
            c["reports"], c["published"], c["verified"],
            c["critical_findings"], c["high_findings"], c["medium_findings"],
            summary
        ))
        conn.commit()
    finally:
        conn.close()

    return snapshot_id


@app.route("/soc_report_compliance/snapshot", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def create_soc_report_compliance_snapshot():
    actor = (current_user() or {}).get("username", "system")
    payload = _build_compliance_payload()
    snapshot_id = _save_compliance_snapshot(payload, actor)
    _write_report_compliance_audit(
        None, "COMPLIANCE_SNAPSHOT_CREATED", actor,
        "SUCCESS", f"Snapshot {snapshot_id} created."
    )
    return jsonify({
        "status": "OK",
        "snapshot_id": snapshot_id,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "counts": payload["counts"]
    })


@app.route("/soc_report_compliance/snapshots", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def list_soc_report_compliance_snapshots():
    limit = min(max(int(request.args.get("limit", 50)), 1), 200)
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT snapshot_id, created_at, created_by, report_count,
                   published_count, verified_count, critical_findings,
                   high_findings, medium_findings, summary
            FROM soc_report_compliance_snapshots
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return jsonify({
            "status": "OK",
            "snapshots": [dict(row) for row in rows]
        })
    finally:
        conn.close()


@app.route("/soc_report_compliance/export", methods=["GET"])
@role_required("Admin", "SOC Analyst")
def export_soc_report_compliance():
    payload = _build_compliance_payload()
    actor = (current_user() or {}).get("username", "system")
    _write_report_compliance_audit(
        None, "COMPLIANCE_EXPORT", actor,
        "SUCCESS", "Current compliance evidence exported as JSON."
    )

    response = jsonify({
        "status": "OK",
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "exported_by": actor,
        "counts": payload["counts"],
        "reports": payload["reports"]
    })
    response.headers["Content-Disposition"] = "attachment; filename=ai_net_compliance_evidence.json"
    response.headers["Content-Type"] = "application/json"
    return response


@app.route("/soc_report_compliance/health", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_compliance_health():
    conn = get_db()
    try:
        tables = {
            "soc_report_archive",
            "soc_report_approvals",
            "soc_report_approval_history",
            "soc_report_versions",
            "soc_report_download_audit",
            "soc_report_delivery",
            "soc_report_compliance_audit",
            "soc_report_compliance_snapshots"
        }
        actual = {
            row["name"] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        missing = sorted(tables - actual)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        return jsonify({
            "status": "OK",
            "database_integrity": integrity,
            "required_tables_present": not missing,
            "missing_tables": missing,
            "compliance_engine": "SQLite-backed",
            "evidence_export": True,
            "audit_logging": True,
            "snapshot_history": True
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.19 — SOC REPORT COMPLIANCE & AUDIT DASHBOARD
# ============================================================

def _write_report_compliance_audit(report_id, event_type, actor,
                                   outcome="SUCCESS", details=""):
    audit_id = "RCA-" + uuid4().hex[:12].upper()
    timestamp = datetime.now().isoformat(timespec="seconds")
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO soc_report_compliance_audit
            (audit_id, report_id, event_type, actor, timestamp, outcome, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id, report_id, event_type, actor or "-",
            timestamp, outcome, details or "-"
        ))
        conn.commit()
    finally:
        conn.close()


def _report_compliance_state(report_id):
    conn = get_db()
    try:
        archive = conn.execute("""
            SELECT report_id, report_type, generated_at, generated_by,
                   posture, file_name, sha256, file_size,
                   integrity_status, retention_until, verified_at
            FROM soc_report_archive
            WHERE report_id=?
        """, (report_id,)).fetchone()

        approval = conn.execute("""
            SELECT approval_id, state, submitted_by, submitted_at,
                   reviewed_by, reviewed_at, published_by, published_at,
                   rejection_reason, approval_note
            FROM soc_report_approvals
            WHERE report_id=?
            ORDER BY id DESC LIMIT 1
        """, (report_id,)).fetchone()

        version = conn.execute("""
            SELECT version_id, version_number, generated_at, generated_by,
                   sha256, file_size, change_summary
            FROM soc_report_versions
            WHERE report_id=?
            ORDER BY version_number DESC, id DESC LIMIT 1
        """, (report_id,)).fetchone()

        delivery = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status='SENT' THEN 1 ELSE 0 END) AS sent,
                SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN status='QUEUED' THEN 1 ELSE 0 END) AS queued
            FROM soc_report_delivery
            WHERE report_id=?
        """, (report_id,)).fetchone()

        downloads = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN outcome='SUCCESS' THEN 1 ELSE 0 END) AS successful,
                SUM(CASE WHEN outcome!='SUCCESS' THEN 1 ELSE 0 END) AS denied_or_failed
            FROM soc_report_download_audit
            WHERE report_id=?
        """, (report_id,)).fetchone()

        return {
            "report": dict(archive) if archive else None,
            "approval": dict(approval) if approval else None,
            "version": dict(version) if version else None,
            "delivery": dict(delivery) if delivery else
                {"total": 0, "sent": 0, "failed": 0, "queued": 0},
            "downloads": dict(downloads) if downloads else
                {"total": 0, "successful": 0, "denied_or_failed": 0}
        }
    finally:
        conn.close()


def _compliance_findings(state):
    findings = []
    report = state.get("report")
    approval = state.get("approval")
    version = state.get("version")

    if not report:
        findings.append({
            "severity": "CRITICAL",
            "finding": "Report archive record is missing."
        })
        return findings

    if not approval:
        findings.append({
            "severity": "HIGH",
            "finding": "Approval workflow has not been initialized."
        })
    else:
        if approval.get("state") == "REJECTED":
            findings.append({
                "severity": "HIGH",
                "finding": "Report is REJECTED and requires review before publishing."
            })
        elif approval.get("state") != "PUBLISHED":
            findings.append({
                "severity": "MEDIUM",
                "finding": f"Report is not published; current approval state is {approval.get('state')}."
            })

    if not version:
        findings.append({
            "severity": "MEDIUM",
            "finding": "Report version history is not initialized."
        })

    if not report.get("sha256") or not report.get("file_size"):
        findings.append({
            "severity": "HIGH",
            "finding": "Report integrity metadata is incomplete."
        })

    if str(report.get("integrity_status") or "").upper() not in {"VERIFIED", "OK"}:
        findings.append({
            "severity": "MEDIUM",
            "finding": f"Report integrity status is {report.get('integrity_status') or 'UNKNOWN'}."
        })

    retention = _parse_dt(report.get("retention_until"))
    if retention and retention < datetime.now():
        findings.append({
            "severity": "HIGH",
            "finding": "Report has passed its configured retention date."
        })

    if not findings:
        findings.append({
            "severity": "NORMAL",
            "finding": "No compliance findings detected for this report."
        })
    return findings


@app.route("/soc_report_compliance", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_compliance():
    conn = get_db()
    try:
        reports = conn.execute("""
            SELECT report_id, report_type, generated_at, generated_by,
                   posture, file_name, integrity_status, retention_until,
                   verified_at
            FROM soc_report_archive
            ORDER BY generated_at DESC
        """).fetchall()

        result = []
        for row in reports:
            report_id = row["report_id"]
            state = _report_compliance_state(report_id)
            findings = _compliance_findings(state)
            highest = "NORMAL"
            order = {"NORMAL": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            for item in findings:
                if order.get(item["severity"], 0) > order.get(highest, 0):
                    highest = item["severity"]

            result.append({
                "report_id": report_id,
                "report_type": row["report_type"],
                "generated_at": row["generated_at"],
                "generated_by": row["generated_by"],
                "posture": row["posture"],
                "file_name": row["file_name"],
                "approval_state": (state["approval"] or {}).get("state", "NOT_INITIALIZED"),
                "integrity_status": row["integrity_status"] or "UNKNOWN",
                "retention_until": row["retention_until"],
                "verified_at": row["verified_at"],
                "compliance_status": highest,
                "findings": findings
            })

        counts = {
            "reports": len(result),
            "published": sum(x["approval_state"] == "PUBLISHED" for x in result),
            "approved": sum(x["approval_state"] == "APPROVED" for x in result),
            "review": sum(x["approval_state"] == "REVIEW" for x in result),
            "draft": sum(x["approval_state"] == "DRAFT" for x in result),
            "rejected": sum(x["approval_state"] == "REJECTED" for x in result),
            "verified": sum(str(x["integrity_status"]).upper() in {"VERIFIED", "OK"} for x in result),
            "critical_findings": sum(x["compliance_status"] == "CRITICAL" for x in result),
            "high_findings": sum(x["compliance_status"] == "HIGH" for x in result),
            "medium_findings": sum(x["compliance_status"] == "MEDIUM" for x in result)
        }

        return jsonify({
            "status": "OK",
            "counts": counts,
            "reports": result,
            "updated_at": datetime.now().isoformat(timespec="seconds")
        })
    finally:
        conn.close()


@app.route("/soc_report_compliance/<report_id>", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_compliance_detail(report_id):
    state = _report_compliance_state(report_id)
    if not state["report"]:
        return jsonify({"status": "ERROR", "error": "Report not found."}), 404

    findings = _compliance_findings(state)
    actor = (current_user() or {}).get("username", "system")
    _write_report_compliance_audit(
        report_id, "COMPLIANCE_VIEWED", actor,
        "SUCCESS", "Compliance detail viewed."
    )

    return jsonify({
        "status": "OK",
        "report_id": report_id,
        "state": state,
        "findings": findings
    })


@app.route("/soc_report_compliance/audit", methods=["GET"])
@role_required("Admin", "SOC Analyst")
def soc_report_compliance_audit():
    limit = min(max(int(request.args.get("limit", 100)), 1), 500)
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT audit_id, report_id, event_type, actor,
                   timestamp, outcome, details
            FROM soc_report_compliance_audit
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return jsonify({
            "status": "OK",
            "events": [dict(row) for row in rows]
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.18 — SOC REPORT PUBLISHING & DISTRIBUTION POLICY
# ============================================================

def _get_report_publishing_policy():
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM soc_report_publishing_policy WHERE id=1
        """).fetchone()
        if not row:
            return {
                "require_approval": 1,
                "allow_admin_override": 1,
                "require_published_for_delivery": 1
            }
        return dict(row)
    finally:
        conn.close()


def _get_report_approval_state(report_id):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT state FROM soc_report_approvals
            WHERE report_id=?
            ORDER BY id DESC LIMIT 1
        """, (report_id,)).fetchone()
        return row["state"] if row else None
    finally:
        conn.close()


def _report_delivery_allowed(report_id):
    policy = _get_report_publishing_policy()
    if not policy.get("require_published_for_delivery"):
        return True, "Distribution policy does not require PUBLISHED state."

    state = _get_report_approval_state(report_id)
    if state == "PUBLISHED":
        return True, "Report is PUBLISHED."
    return False, f"Report must be PUBLISHED before distribution. Current state: {state or 'NOT_INITIALIZED'}."


@app.route("/soc_report_publishing_policy", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_publishing_policy():
    policy = _get_report_publishing_policy()
    return jsonify({"status": "OK", "policy": policy})


@app.route("/soc_report_publishing_policy", methods=["POST"])
@role_required("Admin")
def update_soc_report_publishing_policy():
    payload = request.get_json(silent=True) or {}
    def flag(name, default):
        value = payload.get(name, default)
        if isinstance(value, str):
            value = value.lower() in {"1", "true", "yes", "on"}
        return 1 if bool(value) else 0

    policy = {
        "require_approval": flag("require_approval", 1),
        "allow_admin_override": flag("allow_admin_override", 1),
        "require_published_for_delivery": flag("require_published_for_delivery", 1)
    }
    actor = (current_user() or {}).get("username", "system")
    now = datetime.now().isoformat(timespec="seconds")

    conn = get_db()
    try:
        conn.execute("""
            UPDATE soc_report_publishing_policy
            SET require_approval=?, allow_admin_override=?,
                require_published_for_delivery=?, updated_at=?, updated_by=?
            WHERE id=1
        """, (
            policy["require_approval"],
            policy["allow_admin_override"],
            policy["require_published_for_delivery"],
            now,
            actor
        ))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "OK", "policy": policy})


@app.route("/soc_report_publishing_status/<report_id>", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_publishing_status(report_id):
    policy = _get_report_publishing_policy()
    state = _get_report_approval_state(report_id)
    allowed, reason = _report_delivery_allowed(report_id)

    return jsonify({
        "status": "OK",
        "report_id": report_id,
        "approval_state": state or "NOT_INITIALIZED",
        "distribution_allowed": allowed,
        "reason": reason,
        "policy": policy
    })


@app.route("/soc_report_publish/<report_id>", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def publish_soc_report(report_id):
    actor, role = _approval_actor()
    policy = _get_report_publishing_policy()

    conn = get_db()
    try:
        report = conn.execute("""
            SELECT * FROM soc_report_archive WHERE report_id=?
        """, (report_id,)).fetchone()
        if not report:
            return jsonify({"status": "ERROR", "error": "Report not found."}), 404

        approval = conn.execute("""
            SELECT * FROM soc_report_approvals
            WHERE report_id=? ORDER BY id DESC LIMIT 1
        """, (report_id,)).fetchone()

        if not approval:
            return jsonify({
                "status": "ERROR",
                "error": "Approval workflow is not initialized."
            }), 409

        current = approval["state"]

        if current == "PUBLISHED":
            return jsonify({
                "status": "OK",
                "message": "Report is already published.",
                "approval": dict(approval)
            })

        # Only Admin can use an override, and the policy must permit it.
        if role == "Admin" and policy.get("allow_admin_override"):
            target = "PUBLISHED"
        else:
            if policy.get("require_approval") and current != "APPROVED":
                return jsonify({
                    "status": "ERROR",
                    "error": f"Publishing requires APPROVED state. Current state: {current}."
                }), 403
            target = "PUBLISHED"

        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("""
            UPDATE soc_report_approvals
            SET state=?, published_by=?, published_at=?, approval_note=?
            WHERE approval_id=?
        """, (
            target, actor, now,
            "Published through controlled publishing policy.",
            approval["approval_id"]
        ))
        _record_approval_history(
            conn, approval["approval_id"], report_id,
            current, target, actor,
            "Report published through controlled publishing workflow."
        )
        conn.commit()

        updated = conn.execute("""
            SELECT * FROM soc_report_approvals WHERE approval_id=?
        """, (approval["approval_id"],)).fetchone()

        return jsonify({
            "status": "OK",
            "message": "Report published.",
            "approval": dict(updated)
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.17 — SOC REPORT APPROVAL WORKFLOW
# ============================================================

REPORT_APPROVAL_STATES = {"DRAFT", "REVIEW", "APPROVED", "PUBLISHED", "REJECTED"}

def _approval_actor():
    try:
        user = current_user() or {}
        return user.get("username", "system"), user.get("role", "Unknown")
    except RuntimeError:
        return "system", "Unknown"


def _record_approval_history(conn, approval_id, report_id, from_state,
                              to_state, actor, note=""):
    conn.execute("""
        INSERT INTO soc_report_approval_history
        (approval_id, report_id, from_state, to_state, actor, timestamp, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        approval_id, report_id, from_state, to_state, actor,
        datetime.now().isoformat(timespec="seconds"), note
    ))


def _ensure_report_approval(report_id):
    conn = get_db()
    try:
        existing = conn.execute("""
            SELECT * FROM soc_report_approvals
            WHERE report_id=?
            ORDER BY id DESC LIMIT 1
        """, (report_id,)).fetchone()
        if existing:
            return dict(existing)

        report = conn.execute("""
            SELECT report_id FROM soc_report_archive WHERE report_id=?
        """, (report_id,)).fetchone()
        if not report:
            return None

        approval_id = "APR-" + datetime.now().strftime("%Y%m%d%H%M%S%f")
        actor, _ = _approval_actor()
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("""
            INSERT INTO soc_report_approvals
            (approval_id, report_id, state, submitted_by, submitted_at, approval_note)
            VALUES (?, ?, 'DRAFT', ?, ?, ?)
        """, (approval_id, report_id, actor, now, "Initial approval workflow"))
        _record_approval_history(
            conn, approval_id, report_id, None, "DRAFT", actor,
            "Approval workflow initialized."
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM soc_report_approvals WHERE approval_id=?",
            (approval_id,)
        ).fetchone()
        return dict(row)
    finally:
        conn.close()


def _approval_transition_allowed(role, from_state, to_state):
    if role == "Admin":
        return to_state in REPORT_APPROVAL_STATES
    if role == "SOC Analyst":
        return (
            (from_state == "DRAFT" and to_state == "REVIEW") or
            (from_state == "REVIEW" and to_state in {"APPROVED", "REJECTED"})
        )
    return False


@app.route("/soc_report_approvals", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_approvals():
    report_id = request.args.get("report_id", "").strip()
    conn = get_db()
    try:
        if report_id:
            rows = conn.execute("""
                SELECT * FROM soc_report_approvals
                WHERE report_id=? ORDER BY id DESC
            """, (report_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM soc_report_approvals
                ORDER BY id DESC LIMIT 200
            """).fetchall()
        return jsonify({"status": "OK", "approvals": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/soc_report_approvals/<report_id>/initialize", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def initialize_report_approval(report_id):
    approval = _ensure_report_approval(report_id)
    if not approval:
        return jsonify({"status": "ERROR", "error": "Report not found."}), 404
    return jsonify({"status": "OK", "approval": approval})


@app.route("/soc_report_approvals/<approval_id>", methods=["PATCH"])
@role_required("Admin", "SOC Analyst")
def transition_report_approval(approval_id):
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("state", "")).upper().strip()
    note = str(payload.get("note", "")).strip()

    if target not in REPORT_APPROVAL_STATES:
        return jsonify({"status": "ERROR", "error": "Invalid approval state."}), 400

    actor, role = _approval_actor()
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT * FROM soc_report_approvals WHERE approval_id=?
        """, (approval_id,)).fetchone()
        if not row:
            return jsonify({"status": "ERROR", "error": "Approval record not found."}), 404

        current = row["state"]
        if current == target:
            return jsonify({"status": "OK", "message": "Report is already in this state."})

        if not _approval_transition_allowed(role, current, target):
            return jsonify({
                "status": "ERROR",
                "error": f"{role} cannot transition {current} → {target}."
            }), 403

        now = datetime.now().isoformat(timespec="seconds")
        submitted_by = row["submitted_by"]
        submitted_at = row["submitted_at"]
        reviewed_by = row["reviewed_by"]
        reviewed_at = row["reviewed_at"]
        published_by = row["published_by"]
        published_at = row["published_at"]
        rejection_reason = row["rejection_reason"]

        if target == "REVIEW":
            submitted_by = submitted_by or actor
            submitted_at = submitted_at or now
        elif target in {"APPROVED", "REJECTED"}:
            reviewed_by = actor
            reviewed_at = now
            if target == "REJECTED":
                rejection_reason = note or "Rejected during report review."
        elif target == "PUBLISHED":
            published_by = actor
            published_at = now

        conn.execute("""
            UPDATE soc_report_approvals
            SET state=?, submitted_by=?, submitted_at=?,
                reviewed_by=?, reviewed_at=?, published_by=?, published_at=?,
                rejection_reason=?, approval_note=?
            WHERE approval_id=?
        """, (
            target, submitted_by, submitted_at, reviewed_by, reviewed_at,
            published_by, published_at, rejection_reason, note, approval_id
        ))
        _record_approval_history(
            conn, approval_id, row["report_id"], current, target, actor, note
        )
        conn.commit()

        updated = conn.execute(
            "SELECT * FROM soc_report_approvals WHERE approval_id=?",
            (approval_id,)
        ).fetchone()

        return jsonify({"status": "OK", "approval": dict(updated)})
    finally:
        conn.close()


@app.route("/soc_report_approval_history", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_approval_history():
    approval_id = request.args.get("approval_id", "").strip()
    conn = get_db()
    try:
        if approval_id:
            rows = conn.execute("""
                SELECT * FROM soc_report_approval_history
                WHERE approval_id=? ORDER BY id DESC
            """, (approval_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM soc_report_approval_history
                ORDER BY id DESC LIMIT 300
            """).fetchall()
        return jsonify({"status": "OK", "history": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/soc_report_approval_summary", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_approval_summary():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT state, COUNT(*) AS count
            FROM soc_report_approvals GROUP BY state
        """).fetchall()
        counts = {r["state"]: r["count"] for r in rows}
        return jsonify({
            "status": "OK",
            "total": sum(counts.values()),
            "draft": counts.get("DRAFT", 0),
            "review": counts.get("REVIEW", 0),
            "approved": counts.get("APPROVED", 0),
            "published": counts.get("PUBLISHED", 0),
            "rejected": counts.get("REJECTED", 0)
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.16 — SOC REPORT VERSIONING & CHANGE HISTORY
# ============================================================

def _create_report_version(report, change_summary="", source_type="GENERATED"):
    """Create an immutable version-history record for an archived report."""
    conn = get_db()
    try:
        count = conn.execute("""
            SELECT COUNT(*) FROM soc_report_versions
            WHERE report_id=?
        """, (report["report_id"],)).fetchone()[0]
        version_number = int(count) + 1
        version_id = f'{report["report_id"]}-V{version_number:03d}'
        user = current_user() or {}
        conn.execute("""
            INSERT OR IGNORE INTO soc_report_versions
            (version_id, report_id, parent_report_id, version_number,
             generated_at, generated_by, report_type, posture, file_name,
             sha256, file_size, change_summary, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            version_id,
            report["report_id"],
            report.get("parent_report_id"),
            version_number,
            report["generated_at"],
            user.get("username", report.get("generated_by", "system")),
            report.get("report_type"),
            report.get("posture"),
            report.get("file_name"),
            report.get("sha256"),
            report.get("file_size"),
            change_summary or "Initial archived report version",
            source_type
        ))
        conn.commit()
        return version_id
    finally:
        conn.close()


def _ensure_report_version(report):
    conn = get_db()
    try:
        exists = conn.execute("""
            SELECT 1 FROM soc_report_versions WHERE report_id=? LIMIT 1
        """, (report["report_id"],)).fetchone()
    finally:
        conn.close()
    if not exists:
        return _create_report_version(report)
    return None


@app.route("/soc_report_versions", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_versions():
    report_id = request.args.get("report_id", "").strip()
    conn = get_db()
    try:
        if report_id:
            rows = conn.execute("""
                SELECT version_id, report_id, parent_report_id, version_number,
                       generated_at, generated_by, report_type, posture,
                       file_name, sha256, file_size, change_summary, source_type
                FROM soc_report_versions
                WHERE report_id=?
                ORDER BY version_number DESC
            """, (report_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT version_id, report_id, parent_report_id, version_number,
                       generated_at, generated_by, report_type, posture,
                       file_name, sha256, file_size, change_summary, source_type
                FROM soc_report_versions
                ORDER BY id DESC
                LIMIT 200
            """).fetchall()
        return jsonify({"status": "OK", "versions": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/soc_report_versions/<report_id>/initialize", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def initialize_report_version(report_id):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM soc_report_archive WHERE report_id=?",
            (report_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"status": "ERROR", "error": "Report not found."}), 404

    version_id = _ensure_report_version(dict(row))
    return jsonify({
        "status": "OK",
        "report_id": report_id,
        "version_id": version_id,
        "message": "Report version history initialized."
    })


@app.route("/soc_report_versions/summary", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_versions_summary():
    conn = get_db()
    try:
        total_reports = conn.execute(
            "SELECT COUNT(*) FROM soc_report_archive"
        ).fetchone()[0]
        total_versions = conn.execute(
            "SELECT COUNT(*) FROM soc_report_versions"
        ).fetchone()[0]
        latest = conn.execute("""
            SELECT report_id, version_id, version_number, generated_at,
                   generated_by, change_summary
            FROM soc_report_versions
            ORDER BY id DESC LIMIT 1
        """).fetchone()
        return jsonify({
            "status": "OK",
            "total_reports": total_reports,
            "total_versions": total_versions,
            "latest_version": dict(latest) if latest else None
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.15 — SOC REPORT ACCESS CONTROL & SECURE DOWNLOADS
# ============================================================

def _audit_report_download(report_id, outcome, details="", file_name=None, sha256=None):
    user = current_user() or {}
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO soc_report_download_audit
            (report_id, username, role, timestamp, outcome, ip_address,
             file_name, sha256, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id,
            user.get("username", "anonymous"),
            user.get("role", "Unknown"),
            datetime.now().isoformat(timespec="seconds"),
            outcome,
            request.remote_addr or "unknown",
            file_name,
            sha256,
            details
        ))
        conn.commit()
    finally:
        conn.close()


def _secure_report_path(path):
    """Allow only PDF files physically inside logs/reports."""
    if not path:
        return None
    reports_dir = os.path.realpath(os.path.join(BASE_DIR, "logs", "reports"))
    real_path = os.path.realpath(path)

    try:
        inside = os.path.commonpath([reports_dir, real_path]) == reports_dir
    except ValueError:
        inside = False

    if not inside or not os.path.isfile(real_path):
        return None
    if not real_path.lower().endswith(".pdf"):
        return None
    return real_path


@app.route("/soc_report_archive/download/<report_id>", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_archive_download_secure(report_id):
    user = current_user() or {}
    if user.get("role") == "Viewer":
        _audit_report_download(
            report_id, "DENIED",
            "Viewer role is read-only; report downloads require Admin or SOC Analyst."
        )
        return jsonify({
            "success": False,
            "error": "Report download requires Admin or SOC Analyst access.",
            "current_role": "Viewer",
            "required_roles": ["Admin", "SOC Analyst"]
        }), 403

    # Strict report ID format prevents path/query abuse.
    if not re.fullmatch(r"RPT-\d{20,30}", str(report_id or "")):
        _audit_report_download(report_id, "DENIED", "Invalid report ID format.")
        return jsonify({"error": "Invalid report ID."}), 400

    conn = get_db()
    try:
        row = conn.execute("""
            SELECT report_id, file_path, file_name, sha256, file_size,
                   integrity_status
            FROM soc_report_archive
            WHERE report_id=?
        """, (report_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        _audit_report_download(report_id, "NOT_FOUND", "Report not found.")
        return jsonify({"error": "Report not found."}), 404

    path = _secure_report_path(row["file_path"])
    if not path:
        _audit_report_download(
            report_id, "DENIED",
            "Archived path failed secure path validation.",
            row["file_name"], row["sha256"]
        )
        return jsonify({"error": "Secure report path validation failed."}), 403

    # Never serve a report whose archived fingerprint no longer matches.
    report = dict(row)
    integrity = _verify_report_file(report)
    if integrity["status"] != "VERIFIED":
        _audit_report_download(
            report_id, integrity["status"],
            "Report download blocked because integrity verification failed.",
            row["file_name"], row["sha256"]
        )
        return jsonify({
            "error": "Report download blocked: archived PDF integrity verification failed.",
            "integrity_status": integrity["status"]
        }), 409

    _audit_report_download(
        report_id, "SUCCESS",
        "Secure PDF download authorized and integrity verified.",
        row["file_name"], row["sha256"]
    )

    return send_file(
        path,
        as_attachment=True,
        download_name=os.path.basename(row["file_name"] or os.path.basename(path)),
        mimetype="application/pdf"
    )


@app.route("/soc_report_download_audit", methods=["GET"])
@role_required("Admin")
def soc_report_download_audit():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT id, report_id, username, role, timestamp, outcome,
                   ip_address, file_name, sha256, details
            FROM soc_report_download_audit
            ORDER BY id DESC
            LIMIT 200
        """).fetchall()

        total = len(rows)
        success = sum(1 for r in rows if r["outcome"] == "SUCCESS")
        denied = sum(1 for r in rows if r["outcome"] == "DENIED")
        failed = total - success - denied

        return jsonify({
            "status": "OK",
            "total": total,
            "success": success,
            "denied": denied,
            "failed_or_other": failed,
            "events": [dict(r) for r in rows]
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.14 — SOC REPORT DISTRIBUTION & DELIVERY TRACKING
# ============================================================

DELIVERY_METHODS = {"EMAIL", "DOWNLOAD", "PORTAL"}
DELIVERY_STATUSES = {"QUEUED", "SENT", "FAILED", "CANCELLED"}

def _create_report_delivery(report_id, method, recipient, status="QUEUED",
                            notes="", error_message=None, actor=None):
    method = str(method or "").upper().strip()
    recipient = str(recipient or "").strip()
    status = str(status or "QUEUED").upper().strip()

    if method not in DELIVERY_METHODS:
        raise ValueError("Delivery method must be EMAIL, DOWNLOAD, or PORTAL.")
    if status not in DELIVERY_STATUSES:
        raise ValueError("Invalid delivery status.")
    if not recipient:
        raise ValueError("Recipient is required.")

    now = datetime.now().isoformat(timespec="seconds")
    delivery_id = "DLV-" + datetime.now().strftime("%Y%m%d%H%M%S%f")

    if actor is None:
        try:
            user = current_user() or {}
            actor = user.get("username", "system")
        except RuntimeError:
            actor = "system"

    sent_at = now if status == "SENT" else None

    conn = get_db()
    try:
        exists = conn.execute(
            "SELECT 1 FROM soc_report_archive WHERE report_id=?",
            (report_id,)
        ).fetchone()
        if not exists:
            raise ValueError("Report not found.")

        conn.execute("""
            INSERT INTO soc_report_delivery
            (delivery_id, report_id, method, recipient, status, queued_at,
             sent_at, actor, error_message, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            delivery_id, report_id, method, recipient, status, now,
            sent_at, actor, error_message, notes
        ))
        conn.commit()
    finally:
        conn.close()

    return delivery_id


@app.route("/soc_report_delivery", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_delivery():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT d.id, d.delivery_id, d.report_id, d.method, d.recipient,
                   d.status, d.queued_at, d.sent_at, d.actor,
                   d.error_message, d.notes,
                   r.file_name, r.report_type, r.posture
            FROM soc_report_delivery d
            LEFT JOIN soc_report_archive r ON r.report_id=d.report_id
            ORDER BY d.id DESC
            LIMIT 200
        """).fetchall()
        return jsonify({"status": "OK", "deliveries": [dict(row) for row in rows]})
    finally:
        conn.close()


@app.route("/soc_report_delivery", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def create_soc_report_delivery():
    payload = request.get_json(silent=True) or {}
    try:
        delivery_id = _create_report_delivery(
            payload.get("report_id"),
            payload.get("method"),
            payload.get("recipient"),
            payload.get("status", "QUEUED"),
            payload.get("notes", ""),
            payload.get("error_message"),
        )
        return jsonify({
            "status": "OK",
            "delivery_id": delivery_id,
            "message": "Report delivery record created."
        }), 201
    except ValueError as exc:
        return jsonify({"status": "ERROR", "error": str(exc)}), 400


@app.route("/soc_report_delivery/<delivery_id>", methods=["PATCH"])
@role_required("Admin", "SOC Analyst")
def update_soc_report_delivery(delivery_id):
    payload = request.get_json(silent=True) or {}
    new_status = str(payload.get("status", "")).upper().strip()
    if new_status not in DELIVERY_STATUSES:
        return jsonify({"status": "ERROR", "error": "Invalid delivery status."}), 400

    now = datetime.now().isoformat(timespec="seconds")
    actor = (current_user() or {}).get("username", "system")

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM soc_report_delivery WHERE delivery_id=?",
            (delivery_id,)
        ).fetchone()
        if not row:
            return jsonify({"status": "ERROR", "error": "Delivery record not found."}), 404

        sent_at = row["sent_at"]
        if new_status == "SENT":
            sent_at = sent_at or now

        error_message = payload.get("error_message", row["error_message"])
        notes = payload.get("notes", row["notes"])

        conn.execute("""
            UPDATE soc_report_delivery
            SET status=?, sent_at=?, actor=?, error_message=?, notes=?
            WHERE delivery_id=?
        """, (new_status, sent_at, actor, error_message, notes, delivery_id))
        conn.commit()

        return jsonify({
            "status": "OK",
            "delivery_id": delivery_id,
            "delivery_status": new_status
        })
    finally:
        conn.close()


@app.route("/soc_report_delivery/summary", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_delivery_summary():
    conn = get_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM soc_report_delivery"
        ).fetchone()[0]
        sent = conn.execute(
            "SELECT COUNT(*) FROM soc_report_delivery WHERE status='SENT'"
        ).fetchone()[0]
        queued = conn.execute(
            "SELECT COUNT(*) FROM soc_report_delivery WHERE status='QUEUED'"
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT COUNT(*) FROM soc_report_delivery WHERE status='FAILED'"
        ).fetchone()[0]
        cancelled = conn.execute(
            "SELECT COUNT(*) FROM soc_report_delivery WHERE status='CANCELLED'"
        ).fetchone()[0]

        by_method = {
            row["method"]: row["count"]
            for row in conn.execute("""
                SELECT method, COUNT(*) AS count
                FROM soc_report_delivery
                GROUP BY method
                ORDER BY count DESC
            """).fetchall()
        }

        return jsonify({
            "status": "OK",
            "total": total,
            "sent": sent,
            "queued": queued,
            "failed": failed,
            "cancelled": cancelled,
            "delivery_success_rate": round((sent / total) * 100, 2) if total else 0,
            "by_method": by_method
        })
    finally:
        conn.close()


# ============================================================
# DAY 48.12 — AUTOMATED SCHEDULED SOC EXECUTIVE REPORTS
# ============================================================

def _get_report_schedule():
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM soc_report_schedule WHERE id=1").fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _set_report_schedule(enabled, frequency, run_hour, run_minute, day_of_week, updated_by):
    conn = get_db()
    try:
        conn.execute("""
            UPDATE soc_report_schedule
            SET enabled=?, frequency=?, run_hour=?, run_minute=?, day_of_week=?,
                updated_at=?, updated_by=?
            WHERE id=1
        """, (
            int(enabled), frequency, int(run_hour), int(run_minute), int(day_of_week),
            datetime.now().isoformat(timespec="seconds"), updated_by
        ))
        conn.commit()
    finally:
        conn.close()


def _scheduled_report_due(schedule, now=None):
    if not schedule or not int(schedule.get("enabled", 0)):
        return False
    now = now or datetime.now()
    if now.hour != int(schedule.get("run_hour", 9)) or now.minute != int(schedule.get("run_minute", 0)):
        return False
    frequency = str(schedule.get("frequency", "DAILY")).upper()
    if frequency == "WEEKLY" and now.weekday() != int(schedule.get("day_of_week", 0)):
        return False
    last_run = schedule.get("last_run_at")
    if last_run:
        try:
            last_dt = datetime.fromisoformat(last_run)
            if frequency == "DAILY" and last_dt.date() == now.date():
                return False
            if frequency == "WEEKLY" and (now - last_dt).total_seconds() < 6 * 24 * 3600:
                return False
        except ValueError:
            pass
    return True


def _mark_schedule_run(run_at):
    conn = get_db()
    try:
        conn.execute("UPDATE soc_report_schedule SET last_run_at=? WHERE id=1", (run_at,))
        conn.commit()
    finally:
        conn.close()


def _run_scheduled_report_once():
    schedule = _get_report_schedule()
    now = datetime.now()
    if not _scheduled_report_due(schedule, now):
        return None
    try:
        result = _generate_executive_report_pdf(
            generated_by="AI-Net Scheduler",
            report_type="SCHEDULED_EXECUTIVE_SECURITY_REPORT"
        )
        _mark_schedule_run(now.isoformat(timespec="seconds"))
        print(f"[SOC REPORT SCHEDULER] Generated {result['report_id']} at {now.isoformat(timespec='seconds')}")
        return result
    except Exception as exc:
        # Do not mark as completed if PDF generation failed; next scheduler tick can retry.
        print(f"[SOC REPORT SCHEDULER] ERROR: {exc}")
        return None


def _soc_report_scheduler_loop():
    print("[SOC REPORT SCHEDULER] Background scheduler started")
    while True:
        try:
            _run_scheduled_report_once()
        except Exception as exc:
            print(f"[SOC REPORT SCHEDULER] LOOP ERROR: {exc}")
        time.sleep(30)


@app.route("/soc_report_schedule", methods=["GET"])
@role_required("Admin", "SOC Analyst", "Viewer")
def soc_report_schedule():
    return jsonify({"status": "OK", "schedule": _get_report_schedule()})


@app.route("/soc_report_schedule", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def update_soc_report_schedule():
    payload = request.get_json(silent=True) or {}
    try:
        enabled = bool(payload.get("enabled", False))
        frequency = str(payload.get("frequency", "DAILY")).upper()
        run_hour = int(payload.get("run_hour", 9))
        run_minute = int(payload.get("run_minute", 0))
        day_of_week = int(payload.get("day_of_week", 0))
        if frequency not in {"DAILY", "WEEKLY"}:
            raise ValueError("Frequency must be DAILY or WEEKLY.")
        if not 0 <= run_hour <= 23:
            raise ValueError("Run hour must be between 0 and 23.")
        if not 0 <= run_minute <= 59:
            raise ValueError("Run minute must be between 0 and 59.")
        if not 0 <= day_of_week <= 6:
            raise ValueError("Day of week must be between 0 and 6.")

        user = current_user() or {}
        _set_report_schedule(
            enabled, frequency, run_hour, run_minute, day_of_week,
            user.get("username", "system")
        )
        return jsonify({"status": "OK", "schedule": _get_report_schedule()})
    except (TypeError, ValueError) as exc:
        return jsonify({"status": "ERROR", "error": str(exc)}), 400


@app.route("/soc_report_schedule/run_now", methods=["POST"])
@role_required("Admin", "SOC Analyst")
def run_scheduled_report_now():
    try:
        result = _generate_executive_report_pdf(
            generated_by=(current_user() or {}).get("username", "system"),
            report_type="MANUAL_SCHEDULE_TEST_REPORT"
        )
        return jsonify({
            "status": "OK",
            "report_id": result["report_id"],
            "file_name": result["file_name"],
            "generated_at": result["metrics"]["generated_at"]
        })
    except Exception as exc:
        return jsonify({"status": "ERROR", "error": str(exc)}), 500




if __name__ == "__main__":
    print("\n")
    print("=" * 60)
    print("AI-NET NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)

    if model is not None:
        print("MODEL STATUS : ONLINE")
    else:
        print("MODEL STATUS : OFFLINE")

    print(
        "MODEL TYPE   :",
        type(model).__name__
        if model is not None
        else "Unavailable"
    )

    print("FEATURES     :", len(FEATURES))
    print("CLASSES      : BENIGN / DDoS")
    print("SCALER       :", scaler_status)

    print("=" * 60)
    scheduler_thread = threading.Thread(target=_soc_report_scheduler_loop, name="soc-report-scheduler", daemon=True)
    scheduler_thread.start()

    print("Starting Flask server...")
    print("Open: http://127.0.0.1:5000")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
