import json
import secrets
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from config import Config
from database import execute, fetch_one
from modules.audit_log import add_audit_entry
from modules.detection import evaluate_event
from modules.rollback import create_snapshot
from modules.sandbox import QUARANTINE_DIR, SandboxError, resolve_safe_path
from modules.zero_trust import enforce


SAFE_ACTIONS = {
    "rename": "File Rename",
    "copy": "File Copy",
    "delete": "Simulated Delete",
    "resources": "Fake Resource Consumption",
    "persistence": "Simulated Persistence",
}


def _expires_at():
    return datetime.utcnow() + timedelta(hours=Config.SIMULATION_MAX_HOURS)


def start_simulation(user_id, simulation_type):
    sim_id = execute(
        """
        INSERT INTO simulations (user_id, simulation_type, status, expires_at)
        VALUES (%s, %s, 'ACTIVE', %s)
        """,
        (user_id, simulation_type, _expires_at()),
    )
    create_snapshot(sim_id)
    return sim_id


def active_simulation(user_id):
    return fetch_one(
        """
        SELECT * FROM simulations
        WHERE user_id = %s AND status = 'ACTIVE'
        ORDER BY id DESC LIMIT 1
        """,
        (user_id,),
    )


def is_simulation_usable(simulation):
    if not simulation or simulation["status"] != "ACTIVE" or simulation.get("kill_switch_active"):
        return False
    expires_at = simulation["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    return datetime.utcnow() <= expires_at


def _log_activity(user, action, target, status):
    detection = evaluate_event(user["id"], action, target, status)
    execute(
        """
        INSERT INTO activity_logs (user_id, action, target, status, detection_result)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (user["id"], action, target, status, detection),
    )
    add_audit_entry(user["email"], action, target, status)
    return detection


def _prepare(user, action, target):
    simulation = active_simulation(user["id"])
    usable = is_simulation_usable(simulation)
    decision = enforce(user, "RUN_SAFE_SIMULATION", target, True, usable)
    if not decision.allowed:
        _log_activity(user, action, target, "BLOCKED")
        raise PermissionError(decision.reason)
    return simulation


def safe_rename(user, source, new_name, root=None):
    _prepare(user, "SIMULATION_RENAME", source)
    if "/" in new_name or "\\" in new_name or ".." in new_name:
        raise SandboxError("New filename must stay inside the sandbox.")
    src = resolve_safe_path(source, root, user["id"])
    dst = resolve_safe_path(new_name, root, user["id"])
    src.rename(dst)
    _log_activity(user, "SIMULATION_RENAME", f"{source} -> {new_name}", "SUCCESS")
    return dst.name


def safe_copy(user, source, destination, root=None):
    _prepare(user, "SIMULATION_COPY", source)
    src = resolve_safe_path(source, root, user["id"])
    dst = resolve_safe_path(destination, root, user["id"])
    if dst.is_dir():
        dst = dst / src.name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    _log_activity(user, "SIMULATION_COPY", f"{source} -> {destination}", "SUCCESS")
    return dst.relative_to(Path(root or Config.SANDBOX_ROOT).resolve()).as_posix()


def simulated_delete(user, source, root=None):
    _prepare(user, "SIMULATION_DELETE", source)
    src = resolve_safe_path(source, root, user["id"])
    quarantine = resolve_safe_path(f"{QUARANTINE_DIR}/{src.name}", root, user["id"])
    quarantine.parent.mkdir(exist_ok=True)
    src.rename(quarantine)
    _log_activity(user, "SIMULATION_DELETE", source, "QUARANTINED")
    return quarantine.name


def fake_resource_consumption(user):
    _prepare(user, "SIMULATION_RESOURCES", "visual-only-resource-demo")
    values = {
        "cpu": _visual_percent(35, 88),
        "memory": _visual_percent(25, 76),
        "disk": _visual_percent(10, 45),
    }
    _log_activity(user, "SIMULATION_RESOURCES", json.dumps(values), "SUCCESS")
    return values


def _visual_percent(low, high):
    return low + secrets.randbelow(high - low + 1)


def simulated_persistence(user):
    sim = _prepare(user, "SIMULATED_PERSISTENCE", "database-only-config")
    payload = {
        "label": "SIMULATED PERSISTENCE - NO OPERATING SYSTEM CHANGES",
        "enabled": True,
        "stored_in": "simulations.persistence_json",
    }
    execute("UPDATE simulations SET persistence_json = %s WHERE id = %s", (json.dumps(payload), sim["id"]))
    _log_activity(user, "SIMULATED_PERSISTENCE", "database-only-config", "DETECTED")
    return payload


def activate_kill_switch(user):
    sim = active_simulation(user["id"])
    if not sim:
        return False, "No active simulation to stop."
    execute(
        "UPDATE simulations SET kill_switch_active = TRUE, status = 'STOPPED', completed_at = NOW() WHERE id = %s",
        (sim["id"],),
    )
    _log_activity(user, "KILL_SWITCH", f"simulation:{sim['id']}", "SIMULATION STOPPED")
    return True, "SIMULATION STOPPED"


def record_learning_result(user_id, simulation, threat_detected=False, rollback_completed=False):
    completed = True
    score = 40 + (30 if threat_detected else 0) + (30 if rollback_completed else 0)
    execute(
        """
        INSERT INTO learning_results
        (user_id, simulation, completed, threat_detected, rollback_completed, score)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (user_id, simulation, completed, threat_detected, rollback_completed, min(score, 100)),
    )
