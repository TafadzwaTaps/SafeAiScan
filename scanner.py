import os
import subprocess
import tempfile
import shutil
import json
from urllib.parse import urlparse

MAX_FILES = 2000
MAX_SIZE_MB = 50
ALLOWED_HOSTS = ["github.com"]


# =========================================================
# REPO URL VALIDATION (SECURITY CRITICAL)
# =========================================================
def validate_repo_url(repo_url: str):
    parsed = urlparse(repo_url)

    if parsed.scheme != "https":
        raise Exception("Only HTTPS repos allowed")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise Exception("Only GitHub repos allowed")

    if ".." in repo_url or ";" in repo_url:
        raise Exception("Invalid repo URL")

    return True


# =========================================================
# SAFE CLONE
# =========================================================
def safe_clone(repo_url: str):
    validate_repo_url(repo_url)

    temp_dir = tempfile.mkdtemp(prefix="scan_")

    try:
        subprocess.run(
            [
                "git", "clone",
                "--depth", "1",
                "--single-branch",
                "--no-tags",
                repo_url,
                temp_dir
            ],
            check=True,
            timeout=60
        )

        return temp_dir

    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception("Git clone timeout")

    except subprocess.CalledProcessError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception("Git clone failed")


# =========================================================
# SAFETY CHECK (SIZE + FILE LIMIT)
# =========================================================
def validate_repo(path):
    total_files = 0
    total_size = 0

    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)

            if os.path.islink(fp):
                continue

            try:
                size = os.path.getsize(fp)
            except:
                continue

            total_files += 1
            total_size += size

            if total_files > MAX_FILES:
                raise Exception("Repo too large (file count exceeded)")

            if total_size > MAX_SIZE_MB * 1024 * 1024:
                raise Exception("Repo too large (size exceeded)")

    return True


# =========================================================
# SAFE SUBPROCESS WRAPPER
# =========================================================
def run_command(cmd, timeout=120):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip(),
                "output": result.stdout.strip()
            }

        try:
            return json.loads(result.stdout)
        except:
            return {
                "raw": result.stdout[:1000]
            }

    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout"}

    except Exception as e:
        return {"error": str(e)}


# =========================================================
# BANDIT (Python SAST)
# =========================================================
def run_bandit(path):
    return run_command([
        "bandit", "-r", path, "-f", "json"
    ])


# =========================================================
# SEMGREP (Multi-language SAST)
# =========================================================
def run_semgrep(path):
    return run_command([
        "semgrep",
        "--config=auto",
        path,
        "--json"
    ])


# =========================================================
# TRIVY (CVE scan)
# =========================================================
def run_trivy(path):
    return run_command([
        "trivy",
        "fs",
        "--format", "json",
        "--quiet",
        path
    ], timeout=180)


# =========================================================
# FULL PIPELINE
# =========================================================
def full_scan(path):
    results = {
        "bandit": None,
        "semgrep": None,
        "trivy": None
    }

    # Run scanners safely (one by one)
    results["bandit"] = run_bandit(path)
    results["semgrep"] = run_semgrep(path)
    results["trivy"] = run_trivy(path)

    return results