"""
scanner.py — Secrets Detection Engine
=======================================
Pure Python, zero external CLI tools required.
Scans directories and ZIP archives for hardcoded secrets using compiled regex.

Public API used by app.py and tasks.py:
  scan_zip(path)        → scan an extracted ZIP, return result dict
  scan_directory(path)  → walk a directory, return list of Finding dicts
  scan_repo(url)        → clone GitHub repo, scan, clean up, return result dict
  validate_repo_url(url)→ raise ValueError on invalid/unsafe URL
  build_result(findings, source, is_pro) → assemble final response dict
"""

import os
import re
import json
import zipfile
import tempfile
import shutil
import subprocess
import logging
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

logger = logging.getLogger("secretscan.scanner")

# ──────────────────────────────────────────────────────────────
#  LIMITS
# ──────────────────────────────────────────────────────────────
MAX_FILES       = 1_000      # abort ZIP/repo if it contains more files
MAX_ZIP_MB      = 50         # reject ZIPs larger than this uncompressed
MAX_REPO_MB     = 50         # reject repos larger than this total
MAX_FILE_BYTES  = 512_000    # skip individual files larger than 512 KB
MAX_LINE_LEN    = 2_000      # skip lines longer than this (minified code)
FREE_FINDINGS   = 5          # max findings shown to free-tier users

ALLOWED_HOSTS   = {"github.com"}

# File extensions worth scanning. Binary, image, and video files are skipped.
SCANNABLE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".cfg", ".ini", ".conf", ".config",
    ".yaml", ".yml", ".toml", ".json", ".xml",
    ".sh", ".bash", ".zsh", ".fish",
    ".rb", ".php", ".java", ".go", ".rs", ".cs",
    ".tf", ".tfvars", ".properties",
    ".pem", ".key", ".crt",
    ".txt", ".md", ".html", ".htaccess",
    "",          # files with no extension (Makefile, Dockerfile, etc.)
}

# Directories that are never worth scanning
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "vendor", "target",
    ".mypy_cache", ".pytest_cache", ".tox", "coverage",
}


# ──────────────────────────────────────────────────────────────
#  SECRET PATTERN DEFINITIONS
#  Each entry: (label, compiled_regex, severity, description, fix)
# ──────────────────────────────────────────────────────────────

@dataclass
class _Pattern:
    label:       str
    regex:       re.Pattern
    severity:    str   # HIGH | MEDIUM | LOW | CRITICAL
    description: str
    fix:         str
    category:    str = ""   # NEW: optional category, e.g. "Secrets Exposure"


# Patterns are evaluated in order. HIGH severity patterns come first.
_PATTERNS: list[_Pattern] = [

    # ── HIGH: Cloud & AI service keys ──────────────────────────

    _Pattern("OpenAI API Key",
        re.compile(r'\bsk-[A-Za-z0-9]{20,60}\b'),
        "HIGH",
        "Hardcoded OpenAI API key. Attackers can run API calls billed to your account.",
        "Revoke at platform.openai.com and store in OPENAI_API_KEY env var."),

    _Pattern("OpenAI Project Key",
        re.compile(r'\bsk-proj-[A-Za-z0-9\-_]{20,80}\b'),
        "HIGH",
        "Hardcoded OpenAI project key detected.",
        "Revoke at platform.openai.com and use os.getenv('OPENAI_API_KEY')."),

    _Pattern("Anthropic API Key",
        re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{40,}\b'),
        "HIGH",
        "Hardcoded Anthropic (Claude) API key.",
        "Rotate at console.anthropic.com. Store as ANTHROPIC_API_KEY env var."),

    _Pattern("HuggingFace Token",
        re.compile(r'\bhf_[A-Za-z0-9]{34,}\b'),
        "HIGH",
        "HuggingFace API token gives access to private models and datasets.",
        "Revoke at huggingface.co/settings/tokens. Use HUGGINGFACE_TOKEN env var."),

    _Pattern("Google API Key",
        re.compile(r'\bAIza[A-Za-z0-9\-_]{35}\b'),
        "HIGH",
        "Google API key detected. May allow access to Maps, Cloud, or Firebase.",
        "Restrict or rotate in Google Cloud Console. Use GOOGLE_API_KEY env var."),

    _Pattern("Google Service Account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "HIGH",
        "Google service account JSON found in source code.",
        "Remove immediately. Use Workload Identity or mount at runtime via Secret Manager."),

    # ── HIGH: GitHub tokens ────────────────────────────────────

    _Pattern("GitHub PAT (Classic)",
        re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
        "HIGH",
        "GitHub classic Personal Access Token. Grants repo/org access depending on scope.",
        "Revoke at github.com/settings/tokens. Use GITHUB_TOKEN env var or Actions secrets."),

    _Pattern("GitHub PAT (Fine-Grained)",
        re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b'),
        "HIGH",
        "GitHub fine-grained PAT detected.",
        "Revoke at github.com/settings/tokens. Store as a repository secret."),

    _Pattern("GitHub OAuth Token",
        re.compile(r'\bgho_[A-Za-z0-9]{36}\b'),
        "HIGH",
        "GitHub OAuth access token detected.",
        "Revoke via the OAuth app settings. Never commit OAuth tokens."),

    # ── HIGH: AWS ──────────────────────────────────────────────

    _Pattern("AWS Access Key ID",
        re.compile(r'\b(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b'),
        "HIGH",
        "AWS Access Key ID. Combined with the secret, this allows full AWS API access.",
        "Deactivate in IAM console immediately. Use IAM roles or AWS Secrets Manager."),

    _Pattern("AWS Secret Access Key",
        re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'),
        "HIGH",
        "AWS Secret Access Key assignment detected.",
        "Rotate in IAM. Use environment variables or EC2 instance profiles."),

    # ── HIGH: Payment & messaging ──────────────────────────────

    _Pattern("Stripe Secret Key",
        re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{24,}\b'),
        "HIGH",
        "Stripe secret API key. Allows full charge/refund access to your Stripe account.",
        "Roll the key in the Stripe dashboard. Store as STRIPE_SECRET_KEY env var."),

    _Pattern("Stripe Webhook Secret",
        re.compile(r'\bwhsec_[A-Za-z0-9]{32,}\b'),
        "HIGH",
        "Stripe webhook signing secret detected.",
        "Regenerate in Stripe dashboard → Webhooks. Store as STRIPE_WEBHOOK_SECRET env var."),

    _Pattern("Slack Bot Token",
        re.compile(r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b'),
        "HIGH",
        "Slack bot token. Can post messages, read channels, and access workspace data.",
        "Revoke at api.slack.com/apps. Store as SLACK_BOT_TOKEN env var."),

    _Pattern("SendGrid API Key",
        re.compile(r'\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b'),
        "HIGH",
        "SendGrid API key allows sending emails from your account.",
        "Revoke at app.sendgrid.com/settings/api_keys. Store as SENDGRID_API_KEY env var."),

    _Pattern("Twilio Auth Token",
        re.compile(r'(?i)twilio.{0,20}auth_?token.{0,10}[=:]\s*["\']?([a-f0-9]{32})["\']?'),
        "HIGH",
        "Twilio auth token allows full API access to your Twilio account.",
        "Rotate at console.twilio.com. Store as TWILIO_AUTH_TOKEN env var."),

    _Pattern("PayPal Secret / Client Secret",
        re.compile(r'(?i)(paypal.{0,20}(secret|client_secret)|PAYPAL_SECRET)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}["\']?'),
        "HIGH",
        "PayPal client secret or API credential found in source code.",
        "Rotate in PayPal Developer Dashboard. Store as PAYPAL_CLIENT_SECRET env var."),

    # ── HIGH: Infra & cryptography ────────────────────────────

    _Pattern("Private Key (PEM Block)",
        re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "HIGH",
        "Private key material embedded in source code — critical exposure.",
        "Remove immediately. Store private keys as files outside the repo or in a secrets manager."),

    _Pattern("JWT Secret Hardcoded",
        re.compile(
            r'(?i)(jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*["\']'
            r'(?!your|example|changeme|placeholder|secret|xxx)[A-Za-z0-9!@#$%^&*\-_+=]{12,}["\']'
        ),
        "HIGH",
        "JWT signing secret hardcoded in source. Allows forging tokens.",
        "Generate a strong random secret. Store as SECRET_KEY env var."),

    _Pattern("Database Connection String",
        re.compile(
            r'(?i)(postgres|mysql|mongodb|redis|mssql|sqlite)://'
            r'[^:@\s]+:[^@\s]+@[^\s\'"]{5,}'
        ),
        "HIGH",
        "Database connection string with embedded credentials found.",
        "Move to DATABASE_URL env var. Never commit credentials to source control."),

    _Pattern("Supabase Service Role Key",
        re.compile(
            r'(?i)supabase.{0,30}(service_role|anon).{0,10}[=:]\s*["\']eyJ[A-Za-z0-9\-_=.]+["\']'
        ),
        "HIGH",
        "Supabase service role key found. Bypasses Row Level Security — treat as root credential.",
        "Store as SUPABASE_KEY env var. Never expose the service role key in frontend code."),

    # ── CRITICAL: .env files and named environment secrets ────
    #  ENTERPRISE SECRET DETECTION ENGINE — Phase 1
    #  Detects specific high-value env var names regardless of value shape.

    _Pattern(".env File Included",
        re.compile(r''),   # matched on filename, not content — handled separately
        "CRITICAL",
        ".env file found in the upload or repository. Environment files often "
        "contain live production credentials and should never be committed.",
        "Add .env, .env.local, .env.production, etc. to .gitignore. "
        "Commit only .env.example with placeholder values.",
        category="Secrets Exposure"),

    _Pattern("OPENAI_API_KEY Assignment",
        re.compile(r'(?i)\bOPENAI_API_KEY\s*[=:]\s*["\']?(sk-[A-Za-z0-9\-_]{10,})["\']?'),
        "CRITICAL",
        "OPENAI_API_KEY found with a live-looking value in source or env file.",
        "Revoke at platform.openai.com/api-keys. Inject via deployment secrets, never commit.",
        category="Secrets Exposure"),

    _Pattern("SUPABASE_SERVICE_ROLE_KEY Assignment",
        re.compile(r'(?i)\bSUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_.=]{10,})["\']?'),
        "CRITICAL",
        "SUPABASE_SERVICE_ROLE_KEY found. This key bypasses Row Level Security entirely "
        "and is equivalent to a root database credential.",
        "Rotate immediately in Supabase project settings → API. Never expose to the frontend.",
        category="Secrets Exposure"),

    _Pattern("SUPABASE_ANON_KEY Assignment",
        re.compile(r'(?i)\bSUPABASE_ANON_KEY\s*[=:]\s*["\']?(eyJ[A-Za-z0-9\-_.=]{10,})["\']?'),
        "MEDIUM",
        "SUPABASE_ANON_KEY found in source. This key is meant to be public but its "
        "presence here may indicate a misconfigured .env file leak.",
        "Verify Row Level Security policies are correctly enforced; this key alone "
        "should not grant unintended access.",
        category="Secrets Exposure"),

    _Pattern("JWT_SECRET Assignment",
        re.compile(r'(?i)\bJWT_SECRET\s*[=:]\s*["\']'
                   r'(?!your|example|changeme|placeholder|xxx)([A-Za-z0-9!@#$%^&*\-_+=]{8,})["\']'),
        "CRITICAL",
        "JWT_SECRET found with a live-looking value. Anyone with this value can forge "
        "valid authentication tokens for any user.",
        "Generate a new strong random secret (32+ bytes). Store only in deployment secrets.",
        category="Secrets Exposure"),

    _Pattern("SECRET_KEY Assignment",
        re.compile(r'(?i)\bSECRET_KEY\s*[=:]\s*["\']'
                   r'(?!your|example|changeme|placeholder|xxx)([A-Za-z0-9!@#$%^&*\-_+=]{8,})["\']'),
        "CRITICAL",
        "SECRET_KEY found with a live-looking value. This key signs sessions/tokens — "
        "exposure allows session forgery and cookie tampering.",
        "Rotate the secret and store it only in deployment environment variables.",
        category="Secrets Exposure"),

    _Pattern("DATABASE_URL Assignment",
        re.compile(r'(?i)\bDATABASE_URL\s*[=:]\s*["\']?'
                   r'(postgres|mysql|mongodb|redis|mssql)://[^\s\'"]{10,}["\']?'),
        "CRITICAL",
        "DATABASE_URL found with embedded connection details — likely includes "
        "a username and password for your production database.",
        "Move to deployment secrets. Rotate database credentials if this was committed.",
        category="Secrets Exposure"),

    _Pattern("PAYPAL_CLIENT_SECRET Assignment",
        re.compile(r'(?i)\bPAYPAL_(CLIENT_SECRET|SECRET)\s*[=:]\s*["\']'
                   r'(?!your|example|changeme|placeholder|xxx)([A-Za-z0-9\-_]{10,})["\']'),
        "CRITICAL",
        "PayPal client secret found with a live-looking value. Allows full API access "
        "to your PayPal app, including payment operations.",
        "Rotate in PayPal Developer Dashboard immediately. Store only in deployment secrets.",
        category="Secrets Exposure"),

    _Pattern("AWS_ACCESS_KEY_ID Assignment",
        re.compile(r'(?i)\bAWS_ACCESS_KEY_ID\s*[=:]\s*["\']?((AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16})["\']?'),
        "CRITICAL",
        "AWS_ACCESS_KEY_ID found with a live-looking value.",
        "Deactivate in IAM console immediately. Use IAM roles or short-lived STS credentials.",
        category="Secrets Exposure"),

    _Pattern("AWS_SECRET_ACCESS_KEY Assignment",
        re.compile(r'(?i)\bAWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'),
        "CRITICAL",
        "AWS_SECRET_ACCESS_KEY found with a live-looking value. Combined with the "
        "access key ID, this grants full programmatic AWS access.",
        "Rotate in IAM immediately. Use environment-injected credentials or instance profiles.",
        category="Secrets Exposure"),

    _Pattern("GITHUB_TOKEN Assignment",
        re.compile(r'(?i)\bGITHUB_TOKEN\s*[=:]\s*["\']?((ghp|gho|github_pat)_[A-Za-z0-9_]{20,})["\']?'),
        "CRITICAL",
        "GITHUB_TOKEN found with a live-looking value — grants repository or org access "
        "depending on token scope.",
        "Revoke at github.com/settings/tokens. Use repository/organization secrets in CI.",
        category="Secrets Exposure"),

    _Pattern("HF_API_KEY Assignment",
        re.compile(r'(?i)\bHF_API_KEY\s*[=:]\s*["\']?(hf_[A-Za-z0-9]{20,})["\']?'),
        "HIGH",
        "HF_API_KEY (Hugging Face) found with a live-looking value.",
        "Revoke at huggingface.co/settings/tokens. Store only in deployment secrets.",
        category="Secrets Exposure"),

    # ── HIGH: Bearer tokens, generic JWTs, SSH keys ────────────

    _Pattern("Bearer Token Hardcoded",
        re.compile(r'(?i)Authorization["\']?\s*[:=]\s*["\']Bearer\s+[A-Za-z0-9\-_.=]{16,}["\']'),
        "HIGH",
        "A Bearer authentication token is hardcoded in source code.",
        "Move the token to an environment variable and inject it at request time.",
        category="Secrets Exposure"),

    _Pattern("JWT Token Hardcoded",
        re.compile(r'\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b'),
        "HIGH",
        "A JWT (JSON Web Token) is hardcoded in source code. Even expired tokens can "
        "leak information about claims, audiences, and signing algorithms.",
        "Remove hardcoded tokens. Generate tokens dynamically at runtime and never commit them.",
        category="Secrets Exposure"),

    _Pattern("SSH Private Key",
        re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "CRITICAL",
        "An OpenSSH private key is embedded in source code — grants direct server/SSH access.",
        "Remove immediately and rotate the corresponding public key on all servers. "
        "Store private keys outside the repo, in a secrets manager.",
        category="Secrets Exposure"),

    _Pattern("RSA Private Key",
        re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "CRITICAL",
        "An RSA private key is embedded in source code.",
        "Remove immediately and rotate the key pair. Store private keys in a secrets manager.",
        category="Secrets Exposure"),

    # ── MEDIUM: Suspicious assignments ────────────────────────

    _Pattern("Hardcoded Password",
        re.compile(
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']'
            r'(?!your|example|changeme|placeholder|\s*$)[^\s"\']{6,}["\']'
        ),
        "MEDIUM",
        "Hardcoded password string detected.",
        "Replace with an env var lookup: os.getenv('DB_PASSWORD')."),

    _Pattern("Generic API Key Assignment",
        re.compile(
            r'(?i)(api[_-]?key|apikey|access[_-]?key|auth[_-]?token|bearer[_-]?token)'
            r'\s*[=:]\s*["\'](?!your|example|test|demo|placeholder|xxx)[A-Za-z0-9\-_.]{16,}["\']'
        ),
        "MEDIUM",
        "Possible API key or token hardcoded in source.",
        "Move to an environment variable and load at runtime with os.getenv()."),

    _Pattern("Secret in URL Query String",
        re.compile(
            r'https?://[^\s\'"]{0,60}[?&]'
            r'(key|token|secret|api_key|apikey)=[A-Za-z0-9\-_]{8,}'
        ),
        "MEDIUM",
        "Secret or token embedded in a URL — URLs are often logged by servers and proxies.",
        "Pass credentials in Authorization headers, not URL query parameters."),

    # ── LOW: Code quality / hygiene ────────────────────────────

    _Pattern(".env File Included",
        re.compile(r''),   # matched on filename, not content — handled separately
        "MEDIUM",
        ".env file found in the upload or repository.",
        "Add .env to .gitignore. Commit only .env.example with placeholder values."),

    _Pattern("TODO with Credentials",
        re.compile(r'(?i)#\s*TODO.{0,30}(password|secret|key|token|credential)'),
        "LOW",
        "TODO comment referencing credentials — may indicate insecure work in progress.",
        "Review and ensure credentials are never committed as part of this work."),

    _Pattern("Weak Hash Algorithm",
        re.compile(r'(?i)\b(md5|sha1)\s*\('),
        "LOW",
        "MD5 or SHA-1 is cryptographically broken for security-sensitive use.",
        "Use hashlib.sha256() or better. For passwords use bcrypt or argon2."),
]

# Separate lookup for filename-based patterns (no content scan needed)
_FILENAME_PATTERNS: dict[str, _Pattern] = {
    p.label: p for p in _PATTERNS if p.label == ".env File Included"
}

# Content-scan patterns only (skip filename-only entries)
_CONTENT_PATTERNS = [p for p in _PATTERNS if p.label != ".env File Included"]


# ──────────────────────────────────────────────────────────────
#  FINDING DATA CLASS
# ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    type:        str
    file:        str
    line:        int
    severity:    str
    description: str
    fix:         str
    match:       str = ""   # redacted snippet
    category:    str = ""   # NEW: e.g. "Secrets Exposure", "Dependency Vulnerability"

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────

def _redact(text: str) -> str:
    """Show only the first 6 chars of a secret match to prevent leaking it."""
    if len(text) <= 6:
        return "***"
    return f"{text[:6]}{'*' * min(8, len(text) - 6)}  (redacted)"


def _scannable(path: str) -> bool:
    """Return True if a file should be scanned (right extension, right size)."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in SCANNABLE_EXTS:
        return False
    try:
        return os.path.getsize(path) <= MAX_FILE_BYTES
    except OSError:
        return False


# ──────────────────────────────────────────────────────────────
#  CORE SCAN FUNCTIONS
# ──────────────────────────────────────────────────────────────

def _scan_file(abs_path: str, rel_path: str) -> list[Finding]:
    """
    Scan a single file for all secret patterns.
    Returns a list of Finding objects (may be empty).
    """
    findings: list[Finding] = []
    seen: set[str] = set()  # dedup identical matches within one file

    # ── Filename-based check ──────────────────────────────────
    basename = os.path.basename(abs_path)
    if basename == ".env" or (basename.startswith(".env.") and basename != ".env.example"):
        pat = _FILENAME_PATTERNS[".env File Included"]
        findings.append(Finding(
            type=pat.label, file=rel_path, line=0,
            severity=pat.severity, description=pat.description,
            fix=pat.fix, match=basename, category=pat.category,
        ))

    # ── Content-based scan ────────────────────────────────────
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, PermissionError) as exc:
        logger.warning(f"Cannot read {abs_path}: {exc}")
        return findings

    for lineno, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LEN:
            continue   # skip minified / generated lines

        for pat in _CONTENT_PATTERNS:
            for match in pat.regex.finditer(line):
                key = f"{pat.label}:{match.group(0)}"
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    type        = pat.label,
                    file        = rel_path,
                    line        = lineno,
                    severity    = pat.severity,
                    description = pat.description,
                    fix         = pat.fix,
                    match       = _redact(match.group(0)),
                    category    = pat.category,
                ))

    return findings


def scan_directory(base_dir: str) -> list[Finding]:
    """
    Walk an entire directory tree and scan every eligible file.
    Returns a list of Finding objects sorted HIGH → MEDIUM → LOW.
    """
    all_findings: list[Finding] = []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for root, dirs, files in os.walk(base_dir):
        # Prune ignored dirs so os.walk never descends into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, base_dir)

            if not _scannable(abs_path):
                continue

            all_findings.extend(_scan_file(abs_path, rel_path))

    all_findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line))
    return all_findings


# ──────────────────────────────────────────────────────────────
#  RISK SCORING
# ──────────────────────────────────────────────────────────────

def _risk_level(findings: list[Finding]) -> str:
    """Derive a top-level risk label from the findings list."""
    if not findings:
        return "NONE"
    severities = {f.severity for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────
#  RESULT BUILDER
# ──────────────────────────────────────────────────────────────

def build_result(findings: list[Finding], source: str, is_pro: bool,
                  dependency_findings: list | None = None,
                  dependency_count: int = 0) -> dict:
    """
    Assemble the final API response dict.

    Free users: see only the first FREE_FINDINGS findings + a truncation notice.
    Pro users:  see everything.

    Args:
        findings:            All Finding objects from the secret scan.
        source:              Human-readable label ("zip_upload" or a repo URL).
        is_pro:              Whether the requesting user has a Pro account.
        dependency_findings: NEW (Phase 1) — optional list of dependency
                              vulnerability dicts from dependency_scanner.py.
                              Backward compatible: defaults to None.
        dependency_count:    NEW (Phase 1) — total dependency count for the
                              repository health card. Defaults to 0.

    Returns a dict matching the documented output schema, PLUS new
    Phase 1 fields: security_score, repo_health, and (for findings)
    owasp/nist/auto_fix enrichment when security_engine is available.
    """
    risk       = _risk_level(findings)
    total      = len(findings)
    counts     = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    finding_dicts = [f.to_dict() for f in findings]

    # ── Phase 1: compliance + auto-fix enrichment (additive) ───
    # Imported lazily to avoid a hard dependency if security_engine.py
    # is not present in older deployments — falls back gracefully.
    try:
        from security_engine import enrich_findings_full, compute_security_score, compute_repo_health
        finding_dicts = enrich_findings_full(finding_dicts)
        score_info    = compute_security_score(finding_dicts + (dependency_findings or []))
        repo_health   = compute_repo_health(finding_dicts, dependency_findings, dependency_count)
    except Exception as _exc:  # pragma: no cover — defensive fallback
        logger.debug(f"security_engine enrichment unavailable: {_exc}")
        score_info  = {"security_score": max(0, 100 - total * 10), "risk_level": "Moderate"}
        repo_health = None

    if is_pro:
        visible   = finding_dicts
        truncated = False
    else:
        visible   = finding_dicts[:FREE_FINDINGS]
        truncated = total > FREE_FINDINGS

    result = {
        "risk_level":     risk,
        "total_secrets":  total,
        "summary": {
            "critical": counts["CRITICAL"],
            "high":     counts["HIGH"],
            "medium":   counts["MEDIUM"],
            "low":      counts["LOW"],
        },
        "source":    source,
        "findings":  visible,
        "truncated": truncated,      # True when free user has more results hidden
        "upgrade_message": (
            f"Upgrade to Pro to see all {total} findings and download the PDF report."
            if truncated else ""
        ),
        # ── Phase 1 additions ──────────────────────────────────
        "security_score": score_info["security_score"],
        "score_risk_level": score_info["risk_level"],   # "Excellent"/"Good"/"Moderate"/"High Risk"/"Critical"
    }

    if dependency_findings is not None or dependency_count:
        dep_dicts = [d if isinstance(d, dict) else d.to_dict() for d in (dependency_findings or [])]
        result["dependency_findings"] = dep_dicts if is_pro else dep_dicts[:FREE_FINDINGS]
        result["dependency_count"]    = dependency_count

    if repo_health is not None:
        result["repo_health"] = repo_health

    return result


# ──────────────────────────────────────────────────────────────
#  ZIP INPUT HANDLER
# ──────────────────────────────────────────────────────────────

def scan_zip(zip_path: str, is_pro: bool = True) -> dict:
    """
    Extract a ZIP archive to a temp directory, scan it, and clean up.

    Raises:
        ValueError: on invalid/unsafe ZIP.

    Returns:
        Result dict from build_result().
    """
    if not zipfile.is_zipfile(zip_path):
        raise ValueError("Uploaded file is not a valid ZIP archive.")

    extract_dir = tempfile.mkdtemp(prefix="ss_zip_")
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.infolist()

            if len(members) > MAX_FILES:
                raise ValueError(f"ZIP contains too many files ({len(members):,}). Limit is {MAX_FILES:,}.")

            total_bytes = sum(m.file_size for m in members)
            if total_bytes > MAX_ZIP_MB * 1024 * 1024:
                raise ValueError(f"ZIP uncompressed size exceeds {MAX_ZIP_MB} MB limit.")

            # ZIP-slip protection: reject path-traversal entries
            real_extract = os.path.realpath(extract_dir)
            for member in members:
                dest = os.path.realpath(os.path.join(extract_dir, member.filename))
                if not dest.startswith(real_extract):
                    raise ValueError(f"Unsafe path in ZIP (path traversal): {member.filename}")

            zf.extractall(extract_dir)

        findings = scan_directory(extract_dir)

        dependency_findings = None
        dependency_count    = 0
        try:
            from dependency_scanner import scan_dependencies, count_dependencies
            dependency_findings = scan_dependencies(extract_dir)
            dependency_count    = count_dependencies(extract_dir)
        except Exception as _exc:  # pragma: no cover — defensive fallback
            logger.debug(f"dependency_scanner unavailable: {_exc}")

        return build_result(
            findings, "zip_upload", is_pro,
            dependency_findings=dependency_findings,
            dependency_count=dependency_count,
        )

    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────
#  REPO INPUT HANDLER
# ──────────────────────────────────────────────────────────────

def validate_repo_url(url: str) -> None:
    """
    Validate that a URL is a safe GitHub HTTPS URL.
    Raises ValueError with a user-facing message on failure.
    """
    try:
        parsed = urlparse(url.strip())
    except Exception:
        raise ValueError("Invalid URL format.")

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS repository URLs are accepted.")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Only GitHub (github.com) repositories are supported.")

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(
            "URL must point to a specific repository: https://github.com/owner/repo"
        )


def safe_clone(repo_url: str) -> str:
    """
    Shallow-clone a GitHub repository into a fresh temp directory.

    Returns:
        Path to the cloned directory.

    Raises:
        RuntimeError: if git is missing or the clone fails.
    """
    validate_repo_url(repo_url)
    clone_dir = tempfile.mkdtemp(prefix="ss_repo_")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", repo_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError("Repository clone timed out after 90 seconds.")
    except FileNotFoundError:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError("git is not installed on this server.")

    if result.returncode != 0:
        shutil.rmtree(clone_dir, ignore_errors=True)
        # Return only the last line of stderr to avoid leaking internal paths
        err = result.stderr.strip().splitlines()[-1][:200] if result.stderr.strip() else "Unknown error"
        raise RuntimeError(f"Clone failed: {err}")

    return clone_dir


def validate_repo_size(path: str) -> None:
    """Enforce file count and total size limits on a cloned repo."""
    file_count  = 0
    total_bytes = 0

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fp = os.path.join(root, fname)
            if os.path.islink(fp):
                continue
            try:
                total_bytes += os.path.getsize(fp)
                file_count  += 1
            except OSError:
                continue

            if file_count > MAX_FILES:
                raise ValueError(f"Repository exceeds {MAX_FILES:,} file limit.")
            if total_bytes > MAX_REPO_MB * 1024 * 1024:
                raise ValueError(f"Repository exceeds {MAX_REPO_MB} MB size limit.")


def scan_repo(repo_url: str, is_pro: bool = True) -> dict:
    """
    Clone a GitHub repo, validate size, scan for secrets, clean up, return result.

    Phase 1: also runs the dependency vulnerability scanner over any
    requirements.txt / package.json / lockfiles found in the repo, and
    includes the results + dependency count in the returned dict via
    build_result()'s new optional parameters. Falls back gracefully
    (no dependency data) if dependency_scanner.py is unavailable.

    Returns:
        Result dict from build_result().
    """
    clone_dir = safe_clone(repo_url)
    try:
        validate_repo_size(clone_dir)
        findings = scan_directory(clone_dir)

        dependency_findings = None
        dependency_count    = 0
        try:
            from dependency_scanner import scan_dependencies, count_dependencies
            dependency_findings = scan_dependencies(clone_dir)
            dependency_count    = count_dependencies(clone_dir)
        except Exception as _exc:  # pragma: no cover — defensive fallback
            logger.debug(f"dependency_scanner unavailable: {_exc}")

        return build_result(
            findings, repo_url, is_pro,
            dependency_findings=dependency_findings,
            dependency_count=dependency_count,
        )
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)
