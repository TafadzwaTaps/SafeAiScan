import os
import subprocess
import tempfile
import shutil

MAX_FILES = 2000
MAX_SIZE_MB = 50


# =========================================================
# SAFE CLONE
# =========================================================
def safe_clone(repo_url: str):
    temp_dir = tempfile.mkdtemp(prefix="scan_")

    subprocess.run([
        "git", "clone",
        "--depth", "1",
        "--single-branch",
        repo_url,
        temp_dir
    ], check=True, timeout=60)

    return temp_dir


# =========================================================
# SAFETY CHECK
# =========================================================
def validate_repo(path):
    total_files = 0
    total_size = 0

    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)

            if os.path.islink(fp):
                continue

            total_files += 1
            total_size += os.path.getsize(fp)

            if total_files > MAX_FILES:
                raise Exception("Repo too large")

            if total_size > MAX_SIZE_MB * 1024 * 1024:
                raise Exception("Repo too big")


# =========================================================
# BANDIT (Python SAST)
# =========================================================
def run_bandit(path):
    result = subprocess.run(
        ["bandit", "-r", path, "-f", "json"],
        capture_output=True,
        text=True
    )
    return result.stdout


# =========================================================
# SEMGREP (Multi-language SAST)
# =========================================================
def run_semgrep(path):
    result = subprocess.run(
        ["semgrep", "--config=auto", path, "--json"],
        capture_output=True,
        text=True
    )
    return result.stdout


# =========================================================
# TRIVY (CVE scan)
# =========================================================
def run_trivy(path):
    result = subprocess.run(
        ["trivy", "fs", "--format", "json", path],
        capture_output=True,
        text=True
    )
    return result.stdout


# =========================================================
# FULL PIPELINE
# =========================================================
def full_scan(path):
    return {
        "bandit": run_bandit(path),
        "semgrep": run_semgrep(path),
        "trivy": run_trivy(path)
    }