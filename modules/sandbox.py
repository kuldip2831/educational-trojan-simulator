import shutil
from pathlib import Path

from config import Config
from modules.detection import log_security_event


QUARANTINE_DIR = ".quarantine"
SAMPLE_FILES = {
    "lecture_notes.txt": "Dummy cybersecurity lecture notes for safe simulation.\n",
    "assignment_draft.txt": "Dummy assignment draft. Safe to rename, copy, and quarantine.\n",
    "lab_report.txt": "Dummy lab report used only inside the sandbox.\n",
}


class SandboxError(ValueError):
    pass


def sandbox_root(root=None):
    root_path = Path(root) if root else Config.SANDBOX_ROOT
    root_path.mkdir(parents=True, exist_ok=True)
    (root_path / QUARANTINE_DIR).mkdir(exist_ok=True)
    return root_path.resolve()


def ensure_sample_files(root=None):
    root_path = sandbox_root(root)
    for name, content in SAMPLE_FILES.items():
        target = root_path / name
        if not target.exists():
            target.write_text(content, encoding="utf-8")
    return list_files(root_path)


def resolve_safe_path(requested_path, root=None, user_id=None):
    root_path = sandbox_root(root)
    candidate = (root_path / requested_path).resolve()
    if candidate != root_path and root_path not in candidate.parents:
        log_security_event(
            user_id,
            "PATH_TRAVERSAL_ATTEMPT",
            f"Rejected path outside sandbox: {requested_path}",
            "HIGH",
            str(requested_path),
            "DENY",
        )
        raise SandboxError("Requested path is outside the approved sandbox.")
    return candidate


def list_files(root=None):
    root_path = sandbox_root(root)
    files = []
    for path in sorted(root_path.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root_path).as_posix()
            files.append(
                {
                    "name": rel,
                    "size": path.stat().st_size,
                    "modified": path.stat().st_mtime,
                    "quarantined": rel.startswith(f"{QUARANTINE_DIR}/"),
                    "status": "QUARANTINED" if rel.startswith(f"{QUARANTINE_DIR}/") else "ACTIVE",
                }
            )
    return files


def create_dummy_file(filename, content="", root=None, user_id=None):
    if not filename.endswith(".txt") or "/" in filename or "\\" in filename or ".." in filename:
        raise SandboxError("Only simple .txt filenames are allowed.")
    target = resolve_safe_path(filename, root, user_id)
    target.write_text(content[:2000] or "New safe dummy file.\n", encoding="utf-8")
    return target.name


def reset_sandbox(root=None):
    root_path = sandbox_root(root)
    for child in root_path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    return ensure_sample_files(root_path)


def file_manifest(root=None):
    root_path = sandbox_root(root)
    manifest = []
    for info in list_files(root_path):
        path = resolve_safe_path(info["name"], root_path)
        manifest.append({"name": info["name"], "content": path.read_text(encoding="utf-8")})
    return manifest


def restore_manifest(manifest, root=None):
    root_path = sandbox_root(root)
    for child in root_path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    (root_path / QUARANTINE_DIR).mkdir(exist_ok=True)
    for entry in manifest:
        target = resolve_safe_path(entry["name"], root_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(entry["content"], encoding="utf-8")
    ensure_sample_files(root_path)
