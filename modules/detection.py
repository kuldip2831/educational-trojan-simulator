from datetime import datetime, timedelta

from database import execute, fetch_all, fetch_one


def log_security_event(user_id, event_type, description, severity, resource, decision="DETECTED"):
    return execute(
        """
        INSERT INTO security_events
        (user_id, event_type, description, severity, resource, decision)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (user_id, event_type, description, severity, resource, decision),
    )


def evaluate_event(user_id, action, target, status):
    detections = []
    upper_action = action.upper()
    if "TRAVERSAL" in upper_action or "OUTSIDE_SANDBOX" in status.upper():
        detections.append(("PATH_TRAVERSAL_ATTEMPT", "Path traversal or sandbox escape attempt", "HIGH"))
    if "PERSISTENCE" in upper_action:
        detections.append(("SIMULATED_PERSISTENCE", "Simulated persistence configuration was created", "MEDIUM"))
    if "DELETE" in upper_action or "QUARANTINE" in status.upper():
        detections.append(("SIMULATED_DELETION", "Dummy file moved to quarantine", "MEDIUM"))
    if "DENY" in status.upper() or "BLOCKED" in status.upper():
        detections.append(("ZERO_TRUST_DENY", "Denied operation recorded", "MEDIUM"))

    recent_cutoff = datetime.utcnow() - timedelta(minutes=1)
    recent = fetch_one(
        """
        SELECT COUNT(*) AS count FROM activity_logs
        WHERE user_id = %s AND created_at >= %s
        """,
        (user_id, recent_cutoff),
    )
    if recent and recent["count"] >= 5:
        detections.append(("RAPID_FILE_OPERATIONS", "Multiple rapid dummy-file operations", "HIGH"))

    for event_type, description, severity in detections:
        log_security_event(user_id, event_type, description, severity, target)
    return ", ".join(item[0] for item in detections) if detections else "NONE"


def recent_security_events(limit=10):
    return fetch_all(
        """
        SELECT se.*, u.email
        FROM security_events se
        LEFT JOIN users u ON u.id = se.user_id
        ORDER BY se.created_at DESC
        LIMIT %s
        """,
        (limit,),
    )
