import json

from modules import rollback, simulator
from modules.sandbox import ensure_sample_files, list_files, resolve_safe_path


USER = {"id": 7, "email": "student@example.com", "role": "student"}


def _patch_simulator_db(monkeypatch):
    monkeypatch.setattr(simulator, "_prepare", lambda user, action, target: {"id": 99, "status": "ACTIVE"})
    monkeypatch.setattr(simulator, "_log_activity", lambda *args, **kwargs: "NONE")


def test_safe_rename(tmp_path, monkeypatch):
    _patch_simulator_db(monkeypatch)
    ensure_sample_files(tmp_path)
    result = simulator.safe_rename(USER, "lecture_notes.txt", "renamed_notes.txt", root=tmp_path)
    assert result == "renamed_notes.txt"
    assert resolve_safe_path("renamed_notes.txt", tmp_path).exists()


def test_safe_copy(tmp_path, monkeypatch):
    _patch_simulator_db(monkeypatch)
    ensure_sample_files(tmp_path)
    result = simulator.safe_copy(USER, "lecture_notes.txt", "lecture_copy.txt", root=tmp_path)
    assert result == "lecture_copy.txt"
    assert resolve_safe_path("lecture_copy.txt", tmp_path).exists()


def test_simulated_delete_moves_to_quarantine(tmp_path, monkeypatch):
    _patch_simulator_db(monkeypatch)
    ensure_sample_files(tmp_path)
    simulator.simulated_delete(USER, "lecture_notes.txt", root=tmp_path)
    files = list_files(tmp_path)
    assert any(item["name"] == ".quarantine/lecture_notes.txt" for item in files)


def test_rollback_restores_snapshot(tmp_path, monkeypatch):
    ensure_sample_files(tmp_path)
    manifest = [{"name": "lecture_notes.txt", "content": "original\n"}]
    monkeypatch.setattr(rollback, "fetch_one", lambda *args, **kwargs: {"snapshot_json": json.dumps(manifest)})
    monkeypatch.setattr(rollback, "execute", lambda *args, **kwargs: 1)
    monkeypatch.setattr(rollback, "add_audit_entry", lambda *args, **kwargs: "hash")

    changed = resolve_safe_path("lecture_notes.txt", tmp_path)
    changed.write_text("changed\n", encoding="utf-8")
    ok, message = rollback.rollback_simulation(1, "student@example.com", root=tmp_path)

    assert ok is True
    assert "restored" in message.lower()
    assert changed.read_text(encoding="utf-8") == "original\n"


def test_kill_switch(monkeypatch):
    calls = []
    monkeypatch.setattr(simulator, "active_simulation", lambda user_id: {"id": 12, "status": "ACTIVE"})
    monkeypatch.setattr(simulator, "execute", lambda query, params=(): calls.append((query, params)) or 1)
    monkeypatch.setattr(simulator, "_log_activity", lambda *args, **kwargs: "NONE")
    ok, message = simulator.activate_kill_switch(USER)
    assert ok is True
    assert message == "SIMULATION STOPPED"
    assert calls
