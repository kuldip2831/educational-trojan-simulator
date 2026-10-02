import pytest

from app import create_app
from modules import audit_log
from modules.sandbox import SandboxError, resolve_safe_path
from modules.zero_trust import decide


def test_sandbox_path_traversal_rejection(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.sandbox.log_security_event", lambda *args, **kwargs: 1)
    with pytest.raises(SandboxError):
        resolve_safe_path("../outside.txt", tmp_path, user_id=1)


def test_zero_trust_allow_and_deny():
    student = {"id": 1, "role": "student"}
    assert decide(student, "RUN_SAFE_SIMULATION", "sandbox").allowed is True
    denied = decide(student, "ACCESS_INSTRUCTOR_PANEL", "instructor_dashboard")
    assert denied.allowed is False
    assert denied.reason.startswith("DENY")


def test_audit_chain_verification_detects_tampering(monkeypatch):
    ts1 = "2026-09-30T00:00:00+00:00"
    h1 = audit_log.calculate_hash(ts1, "user", "ACTION", "resource", "SUCCESS", audit_log.GENESIS_HASH)
    ts2 = "2026-09-30T00:01:00+00:00"
    h2 = audit_log.calculate_hash(ts2, "user", "NEXT", "resource", "SUCCESS", h1)
    monkeypatch.setattr(
        audit_log,
        "fetch_all",
        lambda query: [
            {
                "timestamp": ts1,
                "user_label": "user",
                "action": "ACTION",
                "resource": "resource",
                "status": "SUCCESS",
                "previous_hash": audit_log.GENESIS_HASH,
                "current_hash": h1,
            },
            {
                "timestamp": ts2,
                "user_label": "user",
                "action": "NEXT",
                "resource": "resource",
                "status": "TAMPERED",
                "previous_hash": h1,
                "current_hash": h2,
            },
        ],
    )
    assert audit_log.verify_audit_chain() is False


def test_unauthorized_instructor_access(monkeypatch):
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    monkeypatch.setattr(
        "modules.auth.get_user_by_id",
        lambda user_id: {"id": 1, "email": "student@example.com", "role": "student", "name": "Student"},
    )
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
        response = client.get("/security-dashboard")
        assert response.status_code == 302


def test_malicious_looking_input_is_escaped():
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    with app.app_context():
        rendered = app.jinja_env.from_string("{{ value }}").render(value="<script>alert(1)</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
