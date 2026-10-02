import json

from database import execute, fetch_one
from modules.audit_log import add_audit_entry
from modules.sandbox import file_manifest, restore_manifest


def create_snapshot(simulation_id, root=None):
    manifest = file_manifest(root)
    execute(
        "UPDATE simulations SET snapshot_json = %s WHERE id = %s",
        (json.dumps(manifest), simulation_id),
    )
    return manifest


def rollback_simulation(simulation_id, user_label, root=None):
    sim = fetch_one("SELECT * FROM simulations WHERE id = %s", (simulation_id,))
    if not sim or not sim.get("snapshot_json"):
        return False, "No snapshot is available for rollback."
    manifest = json.loads(sim["snapshot_json"])
    restore_manifest(manifest, root)
    execute(
        """
        UPDATE simulations
        SET status = 'ROLLED BACK', persistence_json = NULL, kill_switch_active = FALSE,
            completed_at = NOW()
        WHERE id = %s
        """,
        (simulation_id,),
    )
    add_audit_entry(user_label, "ROLLBACK_SIMULATION", f"simulation:{simulation_id}", "ROLLED BACK")
    return True, "Sandbox restored from snapshot."
