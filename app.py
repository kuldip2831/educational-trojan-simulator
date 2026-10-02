import base64
from io import BytesIO
from datetime import datetime, timezone

import pyotp
import qrcode
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from mysql.connector import IntegrityError

from config import Config
from database import execute, fetch_all, fetch_one, init_db
from modules.audit_log import verify_audit_chain
from modules.auth import (
    create_user,
    current_user,
    get_user_by_email,
    login_required,
    role_required,
    verify_password,
    verify_totp,
)
from modules.rollback import rollback_simulation
from modules.sandbox import SandboxError, create_dummy_file, ensure_sample_files, list_files, reset_sandbox
from modules.simulator import (
    SAFE_ACTIONS,
    activate_kill_switch,
    active_simulation,
    fake_resource_consumption,
    record_learning_result,
    safe_copy,
    safe_rename,
    simulated_delete,
    simulated_persistence,
    start_simulation,
)
from modules.zero_trust import decide, enforce


csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    csrf.init_app(app)

    @app.context_processor
    def inject_common():
        return {"current_user": current_user(), "year": datetime.now(timezone.utc).year}

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("index.html", error="Access denied."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("index.html", error="Page not found."), 404

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if len(name) < 2 or "@" not in email or len(password) < 8:
                flash("Use a valid name, email, and password of at least 8 characters.", "danger")
                return render_template("register.html")
            try:
                user_id, _secret = create_user(name, email, password)
            except IntegrityError:
                flash("An account with that email already exists.", "danger")
                return render_template("register.html")
            session.clear()
            session["pending_2fa_user_id"] = user_id
            session["2fa_enrollment"] = True
            flash("Account created. Scan the QR code and verify a 6-digit code to enable 2FA.", "success")
            return redirect(url_for("verify_2fa"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            ip_address = request.remote_addr or "local"
            recent_failures = fetch_one(
                """
                SELECT COUNT(*) AS count FROM login_attempts
                WHERE email = %s AND success = FALSE
                AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                """,
                (email,),
            )
            if recent_failures and recent_failures["count"] >= 5:
                flash("Too many failed login attempts. Wait a few minutes and try again.", "danger")
                return render_template("login.html")
            user = get_user_by_email(email)
            valid = user and verify_password(user["password_hash"], password)
            execute(
                "INSERT INTO login_attempts (email, ip_address, success) VALUES (%s, %s, %s)",
                (email, ip_address, bool(valid)),
            )
            if not valid:
                flash("Invalid email or password.", "danger")
                return render_template("login.html")
            session.clear()
            session["pending_2fa_user_id"] = user["id"]
            session["2fa_enrollment"] = not bool(user.get("two_factor_enabled"))
            return redirect(url_for("verify_2fa"))
        return render_template("login.html")

    @app.route("/verify-2fa", methods=["GET", "POST"])
    def verify_2fa():
        pending_id = session.get("pending_2fa_user_id")
        if not pending_id:
            return redirect(url_for("login"))
        user = fetch_one("SELECT * FROM users WHERE id = %s", (pending_id,))
        enrollment = session.get("2fa_enrollment") or not bool(user.get("two_factor_enabled"))
        if request.method == "POST":
            token = request.form.get("token", "").strip()
            if verify_totp(user["totp_secret"], token):
                if enrollment:
                    execute("UPDATE users SET two_factor_enabled = TRUE WHERE id = %s", (user["id"],))
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["email"] = user["email"]
                flash(
                    "Two-factor authentication enabled successfully." if enrollment else "2FA verified.",
                    "success",
                )
                target = "instructor_dashboard" if user["role"] == "instructor" else "student_dashboard"
                return redirect(url_for(target))
            flash("Invalid or expired 2FA code. Check your authenticator app and try again.", "danger")
        setup = build_2fa_setup(user) if enrollment else None
        return render_template("verify_2fa.html", enrollment=enrollment, setup=setup)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/student/dashboard")
    @login_required
    def student_dashboard():
        user = current_user()
        stats = {
            "total_simulations": scalar("SELECT COUNT(*) FROM simulations WHERE user_id = %s", (user["id"],)),
            "detections": scalar("SELECT COUNT(*) FROM security_events WHERE user_id = %s", (user["id"],)),
            "rollbacks": scalar(
                "SELECT COUNT(*) FROM simulations WHERE user_id = %s AND status = 'ROLLED BACK'",
                (user["id"],),
            ),
            "progress": scalar(
                "SELECT COALESCE(ROUND(AVG(score)), 0) FROM learning_results WHERE user_id = %s",
                (user["id"],),
            ),
        }
        recent = fetch_all(
            "SELECT * FROM activity_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT 8",
            (user["id"],),
        )
        sim = active_simulation(user["id"])
        return render_template("student_dashboard.html", stats=stats, recent=recent, active_sim=sim)

    @app.route("/instructor/dashboard")
    @login_required
    @role_required("instructor")
    def instructor_dashboard():
        user = current_user()
        decision = enforce(user, "ACCESS_INSTRUCTOR_PANEL", "instructor_dashboard")
        if not decision.allowed:
            flash("Access denied.", "danger")
            return redirect(url_for("student_dashboard"))
        stats = {
            "students": scalar("SELECT COUNT(*) FROM users WHERE role = 'student'"),
            "simulations": scalar("SELECT COUNT(*) FROM simulations"),
            "detections": scalar("SELECT COUNT(*) FROM security_events"),
            "blocked": scalar("SELECT COUNT(*) FROM security_events WHERE decision = 'DENY'"),
            "quarantined": len([f for f in list_files() if f["quarantined"]]),
            "audit_verified": verify_audit_chain(),
        }
        events = fetch_all(
            """
            SELECT se.*, u.email FROM security_events se
            LEFT JOIN users u ON u.id = se.user_id
            ORDER BY se.created_at DESC LIMIT 8
            """
        )
        results = learning_rows()
        return render_template("instructor_dashboard.html", stats=stats, events=events, results=results)

    @app.route("/simulation", methods=["GET", "POST"])
    @login_required
    def simulation():
        ensure_sample_files()
        user = current_user()
        resource_values = None
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "start":
                    sim_type = request.form.get("simulation_type", "general")
                    start_simulation(user["id"], sim_type)
                    flash("Simulation session started. It expires automatically after 24 hours.", "success")
                elif action == "rename":
                    safe_rename(user, request.form.get("source", ""), request.form.get("new_name", ""))
                    record_learning_result(user["id"], "File Rename", False, False)
                    flash("Dummy file renamed inside sandbox.", "success")
                elif action == "copy":
                    safe_copy(user, request.form.get("source", ""), request.form.get("destination", ""))
                    record_learning_result(user["id"], "File Copy", False, False)
                    flash("Dummy file copied inside sandbox.", "success")
                elif action == "delete":
                    simulated_delete(user, request.form.get("source", ""))
                    record_learning_result(user["id"], "Simulated Delete", True, False)
                    flash("Dummy file moved to internal quarantine.", "warning")
                elif action == "resources":
                    resource_values = fake_resource_consumption(user)
                    flash("Safe visual resource simulation generated.", "info")
                elif action == "persistence":
                    simulated_persistence(user)
                    record_learning_result(user["id"], "Simulated Persistence", True, False)
                    flash("Simulated persistence recorded in database only.", "warning")
                elif action == "rollback":
                    sim = active_simulation(user["id"])
                    ok, message = (
                        rollback_simulation(sim["id"], user["email"]) if sim else (False, "No active simulation.")
                    )
                    if ok:
                        record_learning_result(user["id"], "Rollback", True, True)
                    flash(message, "success" if ok else "danger")
                elif action == "kill":
                    ok, message = activate_kill_switch(user)
                    flash(message, "danger" if ok else "warning")
            except (SandboxError, PermissionError, FileNotFoundError) as exc:
                flash(str(exc), "danger")
        files = list_files()
        sim = active_simulation(user["id"])
        return render_template(
            "simulation.html",
            files=files,
            actions=SAFE_ACTIONS,
            active_sim=sim,
            resource_values=resource_values,
        )

    @app.route("/sandbox-files", methods=["GET", "POST"])
    @login_required
    def sandbox_files():
        ensure_sample_files()
        user = current_user()
        if request.method == "POST":
            action = request.form.get("action")
            try:
                if action == "create":
                    decision = enforce(user, "CREATE_DUMMY_FILE", "sandbox")
                    if not decision.allowed:
                        raise PermissionError(decision.reason)
                    create_dummy_file(
                        request.form.get("filename", ""),
                        request.form.get("content", ""),
                        user_id=user["id"],
                    )
                    flash("Dummy text file created.", "success")
                elif action == "reset":
                    decision = enforce(user, "RESET_SANDBOX", "sandbox")
                    if not decision.allowed:
                        raise PermissionError(decision.reason)
                    reset_sandbox()
                    flash("Dummy sandbox reset.", "warning")
            except (SandboxError, PermissionError) as exc:
                flash(str(exc), "danger")
        return render_template("sandbox_files.html", files=list_files())

    @app.route("/activity-logs")
    @login_required
    def activity_logs():
        user = current_user()
        status = request.args.get("status", "")
        if user["role"] == "instructor":
            query = """
                SELECT al.*, u.email FROM activity_logs al
                LEFT JOIN users u ON u.id = al.user_id
            """
            params = []
        else:
            query = """
                SELECT al.*, u.email FROM activity_logs al
                LEFT JOIN users u ON u.id = al.user_id
                WHERE al.user_id = %s
            """
            params = [user["id"]]
        if status:
            query += " AND al.status = %s" if "WHERE" in query else " WHERE al.status = %s"
            params.append(status)
        query += " ORDER BY al.created_at DESC LIMIT 100"
        return render_template("activity_logs.html", logs=fetch_all(query, tuple(params)), status=status)

    @app.route("/security-dashboard", methods=["GET", "POST"])
    @login_required
    @role_required("instructor")
    def security_dashboard():
        user = current_user()
        enforce(user, "VIEW_SECURITY_DASHBOARD", "security_dashboard")
        audit_status = "AUDIT LOG INTEGRITY: VERIFIED" if verify_audit_chain() else "AUDIT LOG INTEGRITY: FAILED"
        if request.method == "POST" and request.form.get("action") == "verify_audit":
            flash(audit_status, "success" if "VERIFIED" in audit_status else "danger")
        decisions = [
            decide(user, "VIEW_SECURITY_DASHBOARD", "security_dashboard").reason,
            decide({"id": user["id"], "role": "student"}, "ACCESS_INSTRUCTOR_PANEL", "instructor_dashboard").reason,
            decide(user, "RUN_SAFE_SIMULATION", "sandbox").reason,
        ]
        stats = {
            "events": scalar("SELECT COUNT(*) FROM security_events"),
            "detections": scalar("SELECT COUNT(*) FROM security_events WHERE decision = 'DETECTED'"),
            "blocked": scalar("SELECT COUNT(*) FROM security_events WHERE decision = 'DENY'"),
            "quarantined": len([f for f in list_files() if f["quarantined"]]),
        }
        events = fetch_all(
            """
            SELECT se.*, u.email FROM security_events se
            LEFT JOIN users u ON u.id = se.user_id
            ORDER BY se.created_at DESC LIMIT 30
            """
        )
        return render_template(
            "security_dashboard.html",
            audit_status=audit_status,
            decisions=decisions,
            stats=stats,
            events=events,
        )

    @app.route("/attack-mapping")
    @login_required
    def attack_mapping():
        return render_template("attack_mapping.html", mappings=mitre_mappings())

    @app.route("/learning-results")
    @login_required
    def learning_results():
        user = current_user()
        rows = learning_rows(user["id"] if user["role"] == "student" else None)
        return render_template("learning_results.html", results=rows)

    @app.route("/profile")
    @login_required
    def profile():
        user = current_user()
        recent_login = fetch_one(
            """
            SELECT created_at FROM login_attempts
            WHERE email = %s AND success = TRUE
            ORDER BY created_at DESC LIMIT 1
            """,
            (user["email"],),
        )
        return render_template("profile.html", user=user, recent_login=recent_login)

    return app


def scalar(query, params=()):
    row = fetch_one(query, params)
    if not row:
        return 0
    return list(row.values())[0] or 0


def build_2fa_setup(user):
    issuer = "Educational Trojan Simulator"
    provisioning_uri = pyotp.TOTP(user["totp_secret"]).provisioning_uri(
        name=user["email"],
        issuer_name=issuer,
    )
    qr = qrcode.QRCode(version=None, box_size=8, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="#031014", back_color="#ffffff")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    secret = user["totp_secret"]
    grouped_secret = " ".join(secret[index:index + 4] for index in range(0, len(secret), 4))
    return {
        "issuer": issuer,
        "account": user["email"],
        "secret": secret,
        "grouped_secret": grouped_secret,
        "qr_base64": qr_base64,
    }


def learning_rows(user_id=None):
    if user_id:
        return fetch_all(
            """
            SELECT lr.*, u.name, u.email FROM learning_results lr
            JOIN users u ON u.id = lr.user_id
            WHERE lr.user_id = %s
            ORDER BY lr.created_at DESC
            """,
            (user_id,),
        )
    return fetch_all(
        """
        SELECT lr.*, u.name, u.email FROM learning_results lr
        JOIN users u ON u.id = lr.user_id
        ORDER BY lr.created_at DESC LIMIT 100
        """
    )


def mitre_mappings():
    return [
        {
            "id": "T1036 Masquerading",
            "behavior": "Safe file rename of dummy text files",
            "explanation": "Demonstrates how renamed artefacts can confuse defenders without hiding real payloads.",
            "detection": "Audit file rename actions and compare snapshot manifests.",
            "mitigation": "Use change monitoring and least-privilege file controls.",
            "status": "Educational simulation only",
        },
        {
            "id": "T1105 Ingress Tool Transfer",
            "behavior": "Copy dummy files inside sandbox only",
            "explanation": "Models artefact movement without network transfer or payload download.",
            "detection": "Detect rapid copy sequences and unexpected duplicate artefacts.",
            "mitigation": "Restrict write locations and monitor file operations.",
            "status": "No external communication",
        },
        {
            "id": "T1070 Indicator Removal",
            "behavior": "Simulated delete by quarantine move",
            "explanation": "Shows the defensive value of reversible quarantine instead of destructive deletion.",
            "detection": "Flag quarantine and delete-like operations.",
            "mitigation": "Use backups, snapshots, and immutable logs.",
            "status": "No permanent destruction",
        },
        {
            "id": "T1053 Scheduled Task/Job",
            "behavior": "Database-only simulated persistence",
            "explanation": "Represents the concept of persistence without touching OS startup services.",
            "detection": "Alert on simulated persistence configuration records.",
            "mitigation": "Review startup controls and apply zero trust approval.",
            "status": "No OS changes",
        },
        {
            "id": "T1496 Resource Hijacking",
            "behavior": "Visual fake CPU/RAM usage bars",
            "explanation": "Demonstrates resource anomaly concepts using generated values only.",
            "detection": "Alert when visual simulated usage crosses training thresholds.",
            "mitigation": "Set resource monitoring baselines.",
            "status": "No real resource exhaustion",
        },
    ]


app = create_app()


if __name__ == "__main__":
    init_db()
    ensure_sample_files()
    app.run(debug=Config.DEBUG)
