from app import create_app
from modules.auth import hash_password, verify_password


def test_password_hashing():
    password_hash = hash_password("StrongPass123")
    assert password_hash != "StrongPass123"
    assert verify_password(password_hash, "StrongPass123")
    assert not verify_password(password_hash, "WrongPass123")


def test_invalid_login(monkeypatch):
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    monkeypatch.setattr("app.fetch_one", lambda *args, **kwargs: {"count": 0})
    monkeypatch.setattr("app.get_user_by_email", lambda email: None)
    monkeypatch.setattr("app.execute", lambda *args, **kwargs: 1)

    with app.test_client() as client:
        response = client.post("/login", data={"email": "nobody@example.com", "password": "bad"})
        assert response.status_code == 200
        assert b"Invalid email or password" in response.data


def test_rbac_blocks_student_from_instructor_dashboard(monkeypatch):
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    student = {"id": 1, "email": "student@example.com", "role": "student", "name": "Student"}
    monkeypatch.setattr("modules.auth.get_user_by_id", lambda user_id: student)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "student"
        response = client.get("/instructor/dashboard")
        assert response.status_code == 302
        assert "/student/dashboard" in response.headers["Location"]


def test_successful_authentication_password_check():
    stored = hash_password("AnotherStrongPass123")
    assert verify_password(stored, "AnotherStrongPass123") is True
