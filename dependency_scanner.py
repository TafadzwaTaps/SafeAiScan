"""
dependency_scanner.py — Dependency Vulnerability Scanner
===========================================================
Additive module. Scans manifest files (requirements.txt, package.json,
package-lock.json, Pipfile, poetry.lock) for outdated or known-vulnerable
package versions using a built-in advisory table.

No network calls — fully offline, deterministic, fast. This keeps repo
scans within the existing time budget and avoids external API rate limits.

Public API:
  scan_dependencies(base_dir)  → list of dependency Finding dicts
  count_dependencies(base_dir) → total dependency count across all manifests
"""

import os
import re
import json
import logging

logger = logging.getLogger("safeaiscan.dependency_scanner")


# ══════════════════════════════════════════════════════════════
#  KNOWN-VULNERABLE PACKAGE TABLE
#  Format: package_name (lowercase) -> list of (max_vulnerable_version, severity, cve, description)
#  "max_vulnerable_version" means: any version <= this is considered vulnerable.
#  This is a curated subset covering high-impact, widely-known CVEs —
#  not a full NVD mirror, but enough to demonstrate real dependency risk
#  without a network dependency.
# ══════════════════════════════════════════════════════════════

def _v(s: str) -> tuple:
    """Parse a version string into a tuple of ints for comparison. Best-effort."""
    parts = re.findall(r'\d+', s)
    return tuple(int(p) for p in parts) if parts else (0,)


_VULN_DB: dict = {
    # Python — requirements.txt / Pipfile / poetry.lock
    "django": [
        ("2.2.27",  "CRITICAL", "CVE-2022-28346", "SQL injection via QuerySet.annotate(), aggregate(), and extra() on PostgreSQL."),
        ("3.2.12",  "HIGH",     "CVE-2022-28347", "SQL injection via QuerySet.explain() on PostgreSQL/SQLite/Oracle."),
        ("4.0.3",   "HIGH",     "CVE-2022-34265", "SQL injection via Trunc() and Extract() with crafted kind/lookup_name."),
    ],
    "flask": [
        ("0.12.2", "HIGH", "CVE-2018-1000656", "Denial of service via crafted JSON in request."),
    ],
    "requests": [
        ("2.19.1", "MEDIUM", "CVE-2018-18074", "Authorization header leaked on cross-domain redirects."),
        ("2.31.0", "MEDIUM", "CVE-2024-35195", "Session verify=False persists across requests after redirect."),
    ],
    "urllib3": [
        ("1.26.17", "HIGH", "CVE-2023-45803", "Cookie header not stripped on cross-origin redirect."),
        ("2.0.6",   "HIGH", "CVE-2023-43804", "Cookie header leaked via redirect to different origin."),
    ],
    "pyyaml": [
        ("5.3.1", "CRITICAL", "CVE-2020-1747", "yaml.load() allows arbitrary code execution via crafted YAML."),
        ("5.4",   "HIGH",     "CVE-2020-14343", "Full execution via yaml.full_load on untrusted input."),
    ],
    "jinja2": [
        ("2.11.2", "HIGH", "CVE-2020-28493", "ReDoS via crafted email address in urlize filter."),
        ("3.1.2",  "MEDIUM", "CVE-2024-22195", "XSS via xmlattr filter with crafted keys."),
    ],
    "cryptography": [
        ("3.3.1", "HIGH", "CVE-2020-36242", "Bleichenbacher timing oracle attack on RSA decryption."),
        ("41.0.2", "MEDIUM", "CVE-2023-38325", "Memory exhaustion via crafted PKCS7 / X509."),
    ],
    "pillow": [
        ("9.0.0",  "CRITICAL", "CVE-2022-22817", "Arbitrary code execution via ImageMath.eval()."),
        ("9.3.0",  "HIGH",     "CVE-2022-45198", "DoS via crafted FLI file leading to large memory allocation."),
        ("10.0.0", "HIGH",     "CVE-2023-44271", "Heap buffer overflow in path drawing."),
    ],
    "fastapi": [
        ("0.65.2", "MEDIUM", "CVE-2021-32677", "ReDoS in regex used for CORS handling."),
    ],
    "sqlalchemy": [
        ("1.3.24", "HIGH", "CVE-2019-7164", "SQL injection via crafted order_by clause."),
    ],
    "paramiko": [
        ("2.10.1", "CRITICAL", "CVE-2022-24302", "Race condition allows privilege escalation via agent forwarding."),
    ],
    "lxml": [
        ("4.6.5", "HIGH", "CVE-2022-2309", "NULL pointer dereference via crafted XML."),
    ],
    "pyjwt": [
        ("1.7.1", "CRITICAL", "CVE-2022-29217", "Algorithm confusion allows forged tokens via 'none' or mismatched alg."),
    ],
    "werkzeug": [
        ("2.2.3", "HIGH", "CVE-2023-25577", "Multipart form data DoS via large file uploads."),
        ("2.3.7", "MEDIUM", "CVE-2023-46136", "Resource exhaustion via crafted multipart boundaries."),
    ],
    "aiohttp": [
        ("3.9.0", "HIGH", "CVE-2023-49081", "HTTP request smuggling via inconsistent chunked encoding parsing."),
    ],

    # JavaScript / Node — package.json / package-lock.json
    "lodash": [
        ("4.17.20", "HIGH", "CVE-2020-8203", "Prototype pollution via zipObjectDeep."),
        ("4.17.21", "CRITICAL", "CVE-2021-23337", "Command injection via template function."),
    ],
    "express": [
        ("4.17.2", "MEDIUM", "CVE-2022-24999", "DoS via crafted query string parsing (qs dependency)."),
    ],
    "axios": [
        ("0.21.1", "HIGH", "CVE-2021-3749", "ReDoS via crafted trim regex."),
        ("1.5.1",  "MEDIUM", "CVE-2023-45857", "Cross-site request forgery via baseURL absolute URL bypass."),
    ],
    "minimist": [
        ("1.2.5", "CRITICAL", "CVE-2021-44906", "Prototype pollution via crafted argument keys."),
    ],
    "node-fetch": [
        ("2.6.6", "MEDIUM", "CVE-2022-0235", "Information exposure via redirect to different protocol."),
    ],
    "moment": [
        ("2.29.3", "HIGH", "CVE-2022-24785", "Path traversal via crafted locale string."),
    ],
    "jsonwebtoken": [
        ("8.5.1", "CRITICAL", "CVE-2022-23529", "Arbitrary code execution via crafted secret/key argument."),
        ("9.0.0", "HIGH",     "CVE-2022-23540", "Algorithm confusion allows signature forgery."),
    ],
    "next": [
        ("12.1.0", "HIGH", "CVE-2022-21703", "Server-side request forgery in image optimisation."),
        ("13.4.1", "MEDIUM", "CVE-2023-46298", "DoS via crafted cache-control headers."),
    ],
    "ws": [
        ("7.4.6", "HIGH", "CVE-2021-32640", "DoS via crafted Sec-WebSocket-Extensions header."),
    ],
    "semver": [
        ("7.5.1", "HIGH", "CVE-2022-25883", "ReDoS via crafted version range string."),
    ],
    "tar": [
        ("6.1.11", "HIGH", "CVE-2021-37713", "Path traversal allows writing outside extraction directory."),
    ],
    "follow-redirects": [
        ("1.15.3", "MEDIUM", "CVE-2023-26159", "Improper handling of absolute URL in redirect."),
    ],
    "json5": [
        ("1.0.1", "HIGH", "CVE-2022-46175", "Prototype pollution via crafted JSON5 input."),
    ],
}

# Outdated-but-not-CVE table: packages flagged as "should upgrade" even
# without a specific known CVE, because the major version is end-of-life
# or significantly behind current.
_EOL_VERSIONS: dict = {
    "django":  (2, 2),     # Django 2.x is EOL
    "flask":   (1, 1),     # Flask 1.x is old
    "react":   (16, 0),    # React 16 — consider 18+
    "vue":     (2, 0),     # Vue 2 EOL Dec 2023
    "angular": (10, 0),
    "node":    (14, 0),    # Node 14 EOL
    "python":  (3, 8),     # informational
}


# ══════════════════════════════════════════════════════════════
#  MANIFEST PARSERS
# ══════════════════════════════════════════════════════════════

def _parse_requirements_txt(path: str) -> dict:
    """Parse requirements.txt — returns {package_name_lower: version_str}."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Match: package==1.2.3 / package>=1.2.3 / package~=1.2
                m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([=<>~!]{1,2})\s*([0-9][A-Za-z0-9.\-]*)', line)
                if m:
                    name, _op, ver = m.groups()
                    deps[name.lower().replace("_", "-")] = ver
                else:
                    # Package with no version pin
                    m2 = re.match(r'^([A-Za-z0-9_.\-]+)', line)
                    if m2:
                        deps[m2.group(1).lower().replace("_", "-")] = ""
    except Exception as e:
        logger.debug(f"_parse_requirements_txt({path}): {e}")
    return deps


def _parse_package_json(path: str) -> dict:
    """Parse package.json dependencies + devDependencies."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                # Strip ^ ~ >= etc.
                clean = re.sub(r'^[\^~>=<\s]+', '', str(ver))
                deps[name.lower()] = clean
    except Exception as e:
        logger.debug(f"_parse_package_json({path}): {e}")
    return deps


def _parse_package_lock_json(path: str) -> dict:
    """Parse package-lock.json (v1, v2, v3 formats) for resolved versions."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        # v2/v3: "packages" key with "node_modules/x" entries
        packages = data.get("packages")
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path or "node_modules/" not in pkg_path:
                    continue
                name = pkg_path.split("node_modules/")[-1]
                ver  = info.get("version", "")
                if name and ver:
                    deps[name.lower()] = ver
        else:
            # v1: "dependencies" key, recursive
            def _walk(d):
                for name, info in (d or {}).items():
                    ver = info.get("version", "")
                    if ver:
                        deps[name.lower()] = ver
                    if "dependencies" in info:
                        _walk(info["dependencies"])
            _walk(data.get("dependencies", {}))
    except Exception as e:
        logger.debug(f"_parse_package_lock_json({path}): {e}")
    return deps


def _parse_pipfile_lock(path: str) -> dict:
    """Parse Pipfile.lock for default + develop packages."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        for section in ("default", "develop"):
            for name, info in (data.get(section) or {}).items():
                ver = (info.get("version") or "").lstrip("=")
                if ver:
                    deps[name.lower()] = ver
    except Exception as e:
        logger.debug(f"_parse_pipfile_lock({path}): {e}")
    return deps


def _parse_pipfile(path: str) -> dict:
    """Parse a Pipfile (TOML-ish) — best-effort regex, no toml dependency."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        # crude: lines like   requests = "==2.25.1"  or  requests = "*"
        for section_name in ("packages", "dev-packages"):
            m = re.search(rf'\[{section_name}\](.*?)(\n\[|\Z)', text, re.S)
            if not m:
                continue
            block = m.group(1)
            for line in block.splitlines():
                line = line.strip()
                m2 = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', line)
                if m2:
                    name, ver = m2.groups()
                    ver = ver.lstrip("=~^<>")
                    deps[name.lower().replace("_", "-")] = ver if ver != "*" else ""
    except Exception as e:
        logger.debug(f"_parse_pipfile({path}): {e}")
    return deps


def _parse_poetry_lock(path: str) -> dict:
    """Parse poetry.lock for [[package]] entries — best-effort regex."""
    deps = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        # Each package block: name = "x" \n version = "y"
        for block in re.split(r'\[\[package\]\]', text)[1:]:
            name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            ver_m  = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
            if name_m and ver_m:
                deps[name_m.group(1).lower()] = ver_m.group(1)
    except Exception as e:
        logger.debug(f"_parse_poetry_lock({path}): {e}")
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt":    _parse_requirements_txt,
    "package.json":        _parse_package_json,
    "package-lock.json":   _parse_package_lock_json,
    "Pipfile.lock":        _parse_pipfile_lock,
    "Pipfile":             _parse_pipfile,
    "poetry.lock":         _parse_poetry_lock,
}


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY MATCHING
# ══════════════════════════════════════════════════════════════

def _check_package(name: str, version: str) -> list[dict]:
    """
    Check a single (name, version) pair against the vulnerability DB
    and EOL table. Returns a list of finding dicts (may be empty).
    """
    findings = []
    name_l = name.lower()

    # ── Known-CVE check ────────────────────────────────────────
    if name_l in _VULN_DB and version:
        cur = _v(version)
        for max_vuln, severity, cve, desc in _VULN_DB[name_l]:
            if cur and cur <= _v(max_vuln):
                findings.append({
                    "title":       "Vulnerable Dependency",
                    "type":        "Vulnerable Dependency",
                    "category":    "Dependency Vulnerability",
                    "package":     name,
                    "version":     version,
                    "severity":    severity,
                    "description": f"{desc} Affects versions <= {max_vuln}.",
                    "fix":         f"Upgrade {name} to a version newer than {max_vuln}.",
                    "cve":         cve,
                    "match":       f"{name}=={version}",
                })
                break  # one finding per package is enough for the dashboard

    # ── EOL / outdated major version check ─────────────────────
    if name_l in _EOL_VERSIONS and version:
        cur = _v(version)
        eol = _EOL_VERSIONS[name_l]
        if cur and cur[:len(eol)] <= eol:
            # Don't duplicate if we already flagged a CVE for this package
            if not any(f["package"] == name for f in findings):
                findings.append({
                    "title":       "Outdated Dependency",
                    "type":        "Outdated Dependency",
                    "category":    "Dependency Vulnerability",
                    "package":     name,
                    "version":     version,
                    "severity":    "LOW",
                    "description": f"{name} {version} is an end-of-life or significantly outdated major version.",
                    "fix":         f"Upgrade {name} to a currently supported major version.",
                    "cve":         "N/A",
                    "match":       f"{name}=={version}",
                })

    return findings


# ══════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════

# Files to look for, in priority order (lockfiles preferred — exact versions)
_MANIFEST_PRIORITY = [
    "package-lock.json", "poetry.lock", "Pipfile.lock",
    "requirements.txt", "package.json", "Pipfile",
]


def _find_manifests(base_dir: str) -> list[str]:
    """Walk base_dir and return paths to all recognised manifest files."""
    found = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if fname in _MANIFEST_PARSERS:
                found.append(os.path.join(root, fname))
    return found


def scan_dependencies(base_dir: str) -> list[dict]:
    """
    Scan all recognised manifest files under base_dir for known-vulnerable
    or outdated dependencies.

    Returns:
        List of finding dicts, each with keys:
          title, type, category, package, version, severity,
          description, fix, cve, match

    Safe to call on any directory — returns [] if no manifests found
    or all parsers fail. Never raises.
    """
    findings = []
    seen_packages = set()

    manifests = _find_manifests(base_dir)
    if not manifests:
        return []

    # Prefer lockfiles (exact versions) over manifest files (version ranges)
    manifests.sort(key=lambda p: _MANIFEST_PRIORITY.index(os.path.basename(p))
                    if os.path.basename(p) in _MANIFEST_PRIORITY else 99)

    for path in manifests:
        fname  = os.path.basename(path)
        parser = _MANIFEST_PARSERS.get(fname)
        if not parser:
            continue
        try:
            deps = parser(path)
        except Exception as e:
            logger.debug(f"Manifest parse failed {path}: {e}")
            continue

        for name, version in deps.items():
            if name in seen_packages:
                continue
            seen_packages.add(name)
            findings.extend(_check_package(name, version))

    return findings


def count_dependencies(base_dir: str) -> int:
    """
    Count the total number of unique dependencies declared across all
    recognised manifest files under base_dir. Used for the repository
    health "dependency_count" field.
    """
    seen = set()
    for path in _find_manifests(base_dir):
        fname  = os.path.basename(path)
        parser = _MANIFEST_PARSERS.get(fname)
        if not parser:
            continue
        try:
            deps = parser(path)
            seen.update(deps.keys())
        except Exception as e:
            logger.debug(f"count_dependencies parse failed {path}: {e}")
    return len(seen)
