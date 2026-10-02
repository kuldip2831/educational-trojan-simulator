import hashlib
from datetime import datetime, timezone

from database import execute, fetch_all, fetch_one


GENESIS_HASH = "0" * 64


def calculate_hash(timestamp, user_label, action, resource, status, previous_hash):
    raw = f"{timestamp}{user_label}{action}{resource}{status}{previous_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def add_audit_entry(user_label, action, resource, status):
    previous = fetch_one("SELECT current_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
    previous_hash = previous["current_hash"] if previous else GENESIS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    current_hash = calculate_hash(timestamp, user_label, action, resource, status, previous_hash)
    execute(
        """
        INSERT INTO audit_chain
        (timestamp, user_label, action, resource, status, previous_hash, current_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (timestamp, user_label, action, resource, status, previous_hash, current_hash),
    )
    return current_hash


def verify_audit_chain():
    rows = fetch_all("SELECT * FROM audit_chain ORDER BY id ASC")
    previous_hash = GENESIS_HASH
    for row in rows:
        expected = calculate_hash(
            row["timestamp"],
            row["user_label"],
            row["action"],
            row["resource"],
            row["status"],
            previous_hash,
        )
        if row["previous_hash"] != previous_hash or row["current_hash"] != expected:
            return False
        previous_hash = row["current_hash"]
    return True
