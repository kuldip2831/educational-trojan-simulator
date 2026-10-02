# Educational Trojan Horse Simulation

A safe, sandboxed university cybersecurity project for demonstrating Trojan-like behavior, detection, quarantine, rollback, Zero Trust decisions, and tamper-evident audit logging.

This project does **not** implement real malware. It does not perform credential theft, keylogging, ransomware, destructive file operations, privilege escalation, real persistence, stealth, evasion, propagation, remote command execution, or command-and-control communication. All demonstrations operate on dummy text files inside `sandbox/dummy_files/`.

## Features

- Flask web application with sessions, CSRF protection, RBAC, password hashing, and TOTP 2FA.
- Student and instructor dashboards with database-backed statistics.
- Safe simulations: rename, copy, quarantine-delete, fake resource usage, and database-only simulated persistence.
- Strict canonical-path sandbox validation before every dummy-file operation.
- Snapshot and rollback for reversible demonstrations.
- Kill switch that stops only this simulator's active simulation session.
- 24-hour simulation-session expiry without OS scheduled tasks.
- Zero Trust flow: deny by default, verify, authorize, execute, log.
- Tamper-evident audit trail using SHA-256 hash chaining.
- Defence mode events for path traversal, rapid operations, denied operations, simulated deletion, and simulated persistence.
- MITRE ATT&CK concept mapping for safe simulated behaviors only.
- Pytest coverage for authentication, simulator operations, rollback, kill switch, sandbox rejection, Zero Trust, audit integrity, RBAC, and XSS escaping.

## Architecture Overview

`app.py` defines Flask routes and page controllers. `database.py` initializes the MySQL database and tables. `modules/` contains the security and simulator logic:

- `auth.py`: password hashing, registration helpers, 2FA verification, RBAC decorators.
- `sandbox.py`: strict sandbox path validation and dummy-file management.
- `simulator.py`: safe behavior simulations and kill switch.
- `rollback.py`: snapshot manifest restoration.
- `zero_trust.py`: explicit allow/deny policy decisions.
- `audit_log.py`: hash-chained audit records and integrity verification.
- `detection.py`: safe defence-mode event generation.

## Directory Structure

```text
educational_trojan_simulator/
├── app.py
├── database.py
├── config.py
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── README.md
├── templates/
├── static/
├── modules/
├── sandbox/dummy_files/
├── tests/
├── docs/screenshots/
└── ci-cd/security-pipeline.yml
```

Small supporting templates such as `base.html`, `_file_select.html`, and `_logs_table.html` are included to avoid duplicated markup.

## Prerequisites

- Python 3.10 or newer
- MySQL Server running locally
- PyCharm or a terminal

## MySQL Setup

The app creates the database and tables automatically when `python app.py` starts, using values from `.env`.

Local development defaults:

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=trojan_simulator
DB_USER=root
DB_PASSWORD=root
```

If your MySQL root password differs, update `.env`. Do not commit `.env`; it is ignored by Git.

## Environment Configuration

Copy the example if needed:

```powershell
Copy-Item .env.example .env
```

Then edit `.env` and set `FLASK_SECRET_KEY` and your local database password.

## PyCharm Setup

1. Open this folder in PyCharm.
2. Select or create a virtual environment.
3. Install dependencies from `requirements.txt`.
4. Run `app.py`.
5. Open `http://127.0.0.1:5000`.

## Installation

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Run tests:

```powershell
pytest
```

## Database Tables Created

- `users`
- `simulations`
- `activity_logs`
- `security_events`
- `learning_results`
- `audit_chain`
- `login_attempts`

All application SQL uses parameterised queries.

## Creating an Instructor

Normal registration always creates a `student`.

For a local demo, register an account first, then promote it in MySQL:

```sql
UPDATE users SET role = 'instructor' WHERE email = 'teacher@example.com';
```

This keeps instructor creation outside public registration and makes the demo flow explicit.

## 2FA Instructions

After registration, the app displays a TOTP secret and provisioning URI. Add the secret to an authenticator app, then log in with:

1. Email and password
2. Current 6-digit authenticator code

For local demos, you can also generate a current code in a Python shell if you know the demo secret:

```python
import pyotp
print(pyotp.TOTP("YOUR_SECRET").now())
```

## Running the Safe Simulation

1. Log in.
2. Open `Simulation`.
3. Click `Start Session`.
4. Run a safe operation:
   - Rename a dummy file.
   - Copy a dummy file inside the sandbox.
   - Move a dummy file to quarantine.
   - Generate fake resource usage values.
   - Create the database-only simulated persistence record.

Every file operation is restricted to `sandbox/dummy_files/`.

## Testing Rollback

1. Start a simulation session.
2. Rename, copy, or quarantine a dummy file.
3. Click `Rollback`.
4. The snapshot manifest restores the dummy environment and clears simulated persistence state.

## Demonstrating Zero Trust

Open `Security Dashboard` as an instructor to see example decisions:

- `ALLOW - Instructor - VIEW_SECURITY_DASHBOARD`
- `DENY - Student - ACCESS_INSTRUCTOR_PANEL`
- `ALLOW - Instructor - RUN_SAFE_SIMULATION`

Sandbox path traversal attempts are denied and recorded as security events.

## Verifying the Audit Hash Chain

As an instructor:

1. Open `Security Dashboard`.
2. Click `Verify Audit Integrity`.
3. A valid chain displays `AUDIT LOG INTEGRITY: VERIFIED`.

If audit rows are modified outside the application during a controlled test, verification returns `AUDIT LOG INTEGRITY: FAILED`.

## Kill Switch

The Kill Switch sets the active simulation status to `STOPPED`, prevents further simulation operations for that session, records the action, and displays `SIMULATION STOPPED`. It does not terminate the OS, Python processes, or unrelated applications.

## 24-Hour Auto-Disable

Each simulation session stores an `expires_at` timestamp. Before simulated operations run, the simulator checks whether the active session is usable. Expired or stopped sessions are denied by Zero Trust.

## Security Testing Commands

```powershell
pytest
flake8 . --exclude .venv --max-line-length=120
bandit -r . -x .venv,tests
semgrep --config p/python .
```

Secret scanning can be run with Gitleaks if installed:

```powershell
gitleaks detect --source .
```

Do not commit `.env` or real credentials.

## DevSecOps Pipeline

`ci-cd/security-pipeline.yml` contains a GitHub Actions pipeline concept:

Checkout → Python Setup → Install Dependencies → Lint → Bandit → Semgrep → Pytest → Dependency Check → Gitleaks / Secret Check → Security Result

It uses CI environment variables and does not require committing `.env`.

## OWASP Demonstration Support

- Injection: SQL operations use parameterised queries.
- Broken Access Control: students are denied instructor routes by RBAC and Zero Trust policy.
- XSS: Jinja autoescaping and server-side validation safely render malicious-looking input.

## Limitations

- This is a local educational simulator, not an antivirus or EDR product.
- The default `.env` is for local development only; change secrets before any shared deployment.
- The CI file is placed under `ci-cd/` as requested. To activate it on GitHub, copy it to `.github/workflows/security-pipeline.yml`.
- The app assumes the configured MySQL user can create the local demo database.

