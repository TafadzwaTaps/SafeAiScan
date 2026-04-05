import os
import subprocess
import tempfile
import shutil
import json
from urllib.parse import urlparse

MAX_FILES = 2000
MAX_SIZE_MB = 50
ALLOWED_HOSTS = ["github.com"]


# =========================
# CVE ENRICHMENT (MOCK SAFE LAYER)
# =========================
def enrich_cve(vuln):
    vuln_text = (vuln.get("title") or "").lower()

    # lightweight mapping (replace later with real CVE API)
    if "sql injection" in vuln_text:
        vuln["cve"] = "CVE-2021-44228"
        vuln["cvss"] = 9.8

    elif "xss" in vuln_text:
        vuln["cve"] = "CVE-2020-11023"
        vuln["cvss"] = 7.5

    else:
        vuln["cve"] = vuln.get("cve", "N/A")
        vuln["cvss"] = vuln.get("cvss", 5.0)

    return vuln


# =========================
# NORMALIZER (SNYK STYLE FORMAT)
# =========================
def normalize_findings(raw, source):
    findings = []

    try:
        issues = raw.get("results") or raw.get("issues") or []

        for i in issues:
            findings.append(enrich_cve({
                "title": i.get("message") or i.get("check_id") or "Issue",
                "description": i.get("extra", {}).get("message", ""),
                "severity": (i.get("severity") or "LOW").lower(),
                "file": i.get("path"),
                "line": i.get("start", {}).get("line"),
                "fix": i.get("fix") or "No auto-fix available",
                "source": source
            }))
    except:
        pass

    return findings


# =========================
# VALIDATION
# =========================
def validate_repo_url(repo_url: str):
    parsed = urlparse(repo_url)

    if parsed.scheme != "https":
        raise Exception("Only HTTPS repos allowed")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise Exception("Only GitHub repos allowed")

    return True


# =========================
# SAFE CLONE
# =========================
def safe_clone(repo_url: str):
    validate_repo_url(repo_url)

    temp_dir = tempfile.mkdtemp(prefix="scan_")

    subprocess.run([
        "git", "clone",
        "--depth", "1",
        repo_url,
        temp_dir
    ], check=True, timeout=60)

    return temp_dir


# =========================
# SIZE VALIDATION
# =========================
def validate_repo(path):
    files = 0
    size = 0

    for root, _, fs in os.walk(path):
        for f in fs:
            fp = os.path.join(root, f)
            if os.path.islink(fp):
                continue

            try:
                size += os.path.getsize(fp)
                files += 1
            except:
                continue

            if files > MAX_FILES:
                raise Exception("Too many files")

            if size > MAX_SIZE_MB * 1024 * 1024:
                raise Exception("Repo too large")

    return True


# =========================
# RUN WRAPPER
# =========================
def run_command(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode != 0:
            return {"error": result.stderr}

        try:
            return json.loads(result.stdout)
        except:
            return {"raw": result.stdout}

    except Exception as e:
        return {"error": str(e)}


# =========================
# SCANNERS
# =========================
def run_bandit(path):
    return run_command(["bandit", "-r", path, "-f", "json"])


def run_semgrep(path):
    return run_command(["semgrep", "--config=auto", path, "--json"])


def run_trivy(path):
    return run_command(["trivy", "fs", "--format", "json", path], timeout=180)


# =========================
# FULL SCAN (NORMALIZED OUTPUT)
# =========================
def full_scan(path):
    bandit = normalize_findings(run_bandit(path), "bandit")
    semgrep = normalize_findings(run_semgrep(path), "semgrep")
    trivy = normalize_findings(run_trivy(path), "trivy")

    return {
        "findings": bandit + semgrep + trivy
    }