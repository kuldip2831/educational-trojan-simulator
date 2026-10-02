from dataclasses import dataclass

from modules.detection import log_security_event


POLICIES = {
    "student": {
        "READ_SANDBOX",
        "CREATE_DUMMY_FILE",
        "RESET_SANDBOX",
        "RUN_SAFE_SIMULATION",
        "ROLLBACK_SIMULATION",
        "KILL_SWITCH",
        "VIEW_OWN_RESULTS",
    },
    "instructor": {
        "READ_SANDBOX",
        "CREATE_DUMMY_FILE",
        "RESET_SANDBOX",
        "RUN_SAFE_SIMULATION",
        "ROLLBACK_SIMULATION",
        "KILL_SWITCH",
        "VIEW_OWN_RESULTS",
        "ACCESS_INSTRUCTOR_PANEL",
        "VIEW_ALL_RESULTS",
        "VIEW_SECURITY_DASHBOARD",
        "VERIFY_AUDIT",
    },
}


@dataclass
class Decision:
    allowed: bool
    subject: str
    action: str
    resource: str
    reason: str

    @property
    def label(self):
        return "ALLOW" if self.allowed else "DENY"


def decide(user, action, resource, path_valid=True, simulation_active=True):
    role = (user or {}).get("role", "anonymous")
    subject = role.title() if role != "anonymous" else "User"
    allowed_actions = POLICIES.get(role, set())
    allowed = bool(user) and action in allowed_actions and path_valid and simulation_active
    if allowed:
        reason = f"ALLOW - {subject} - {action}"
    elif not user:
        reason = f"DENY - User - {action}: authentication required"
    elif not path_valid:
        reason = "DENY - User - ACCESS_OUTSIDE_SANDBOX"
    elif not simulation_active:
        reason = f"DENY - {subject} - {action}: simulation inactive or expired"
    else:
        reason = f"DENY - {subject} - {action}"
    return Decision(allowed, subject, action, str(resource), reason)


def enforce(user, action, resource, path_valid=True, simulation_active=True):
    decision = decide(user, action, resource, path_valid, simulation_active)
    if not decision.allowed:
        log_security_event(
            (user or {}).get("id"),
            "ZERO_TRUST_DENY",
            decision.reason,
            "HIGH" if not path_valid else "MEDIUM",
            decision.resource,
            "DENY",
        )
    return decision
