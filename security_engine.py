"""
security_engine.py — Phase 1 Enterprise Security Engine
=========================================================
Additive module. Does not modify scanner.py, app.py route signatures,
or any existing data shapes — only adds new computed fields on top of
existing finding lists.

Provides:
  compute_security_score(findings)      → weighted 0-100 score + risk label
  map_compliance(finding)                → OWASP + NIST mapping for one finding
  enrich_findings_with_compliance(findings) → adds 'owasp'/'nist' to each finding
  compute_repo_health(findings, dep_findings) → repository health summary dict
  generate_auto_fix(finding)             → before/after/explanation/confidence
"""

import re
import logging

logger = logging.getLogger("safeaiscan.security_engine")


# ══════════════════════════════════════════════════════════════
#  1. ADVANCED SECURITY SCORING ENGINE
# ══════════════════════════════════════════════════════════════

_SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":      5,
}

def _risk_label(score: int) -> str:
    """Map a 0-100 score to a human-readable risk level."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Moderate"
    if score >= 25:
        return "High Risk"
    return "Critical"


def compute_security_score(findings: list) -> dict:
    """
    Weighted security scoring.

    Starts at 100 and deducts points per finding based on severity:
      CRITICAL = -40, HIGH = -20, MEDIUM = -10, LOW = -5

    Score is clamped to [0, 100].

    Returns:
        { "security_score": int, "risk_level": str }
    """
    score = 100
    for f in findings or []:
        sev = (f.get("severity") or "LOW").upper()
        score -= _SEVERITY_WEIGHTS.get(sev, 5)

    score = max(0, min(100, score))
    return {
        "security_score": score,
        "risk_level":      _risk_label(score),
    }


# ══════════════════════════════════════════════════════════════
#  2. COMPLIANCE MAPPING ENGINE (OWASP Top 10 + NIST 800-53)
# ══════════════════════════════════════════════════════════════

# Mapping rules: match against finding `type`/`title`/`category` (case-insensitive
# substring match). Order matters — first match wins. Falls back to a generic
# "A05 Security Misconfiguration" / "SI-2" mapping if nothing matches.
_COMPLIANCE_RULES: list[tuple[str, str, str]] = [
    # (substring to match in finding type/title, OWASP, NIST)
    ("sql injection",            "A03 Injection",                       "SI-10"),
    ("f-string sql",             "A03 Injection",                       "SI-10"),
    ("union select",             "A03 Injection",                       "SI-10"),
    ("command injection",        "A03 Injection",                       "SI-10"),
    ("os.popen",                 "A03 Injection",                       "SI-10"),
    ("shell=true",               "A03 Injection",                       "SI-10"),
    ("eval(",                    "A03 Injection",                       "SI-10"),
    ("exec(",                    "A03 Injection",                       "SI-10"),
    ("deserialize",              "A08 Software and Data Integrity Failures", "SI-7"),
    ("pickle.loads",             "A08 Software and Data Integrity Failures", "SI-7"),
    ("yaml.load",                "A08 Software and Data Integrity Failures", "SI-7"),

    ("xss",                      "A03 Injection",                       "SI-10"),
    ("innerhtml",                "A03 Injection",                       "SI-10"),
    ("dangerouslysetinnerhtml",  "A03 Injection",                       "SI-10"),
    ("document.write",           "A03 Injection",                       "SI-10"),
    ("prototype pollution",      "A03 Injection",                       "SI-10"),
    ("__proto__",                "A03 Injection",                       "SI-10"),

    ("path traversal",           "A01 Broken Access Control",           "AC-3"),
    ("access control",           "A01 Broken Access Control",           "AC-3"),
    ("authoriz",                 "A01 Broken Access Control",           "AC-3"),

    # Secrets / keys / tokens / credentials → Cryptographic Failures + SC-13/SC-28
    ("private key",               "A02 Cryptographic Failures",          "SC-12"),
    ("rsa key",                   "A02 Cryptographic Failures",          "SC-12"),
    ("ssh key",                   "A02 Cryptographic Failures",          "SC-12"),
    ("aws access key",            "A02 Cryptographic Failures",          "SC-28"),
    ("aws secret",                "A02 Cryptographic Failures",          "SC-28"),
    ("openai",                    "A02 Cryptographic Failures",          "SC-28"),
    ("anthropic",                 "A02 Cryptographic Failures",          "SC-28"),
    ("huggingface",               "A02 Cryptographic Failures",          "SC-28"),
    ("github pat",                "A02 Cryptographic Failures",          "SC-28"),
    ("github oauth",               "A02 Cryptographic Failures",          "SC-28"),
    ("slack bot token",           "A02 Cryptographic Failures",          "SC-28"),
    ("sendgrid",                  "A02 Cryptographic Failures",          "SC-28"),
    ("twilio",                    "A02 Cryptographic Failures",          "SC-28"),
    ("stripe",                    "A02 Cryptographic Failures",          "SC-28"),
    ("paypal secret",             "A02 Cryptographic Failures",          "SC-28"),
    ("supabase service role",     "A02 Cryptographic Failures",          "SC-28"),
    ("database connection",       "A02 Cryptographic Failures",          "SC-28"),
    ("jwt secret",                "A02 Cryptographic Failures",          "SC-13"),
    ("hardcoded password",        "A07 Identification and Authentication Failures", "IA-5"),
    ("hardcoded token",           "A07 Identification and Authentication Failures", "IA-5"),
    ("hardcoded api key",         "A07 Identification and Authentication Failures", "IA-5"),
    ("high-entropy",              "A02 Cryptographic Failures",          "SC-28"),
    ("secrets exposure",          "A02 Cryptographic Failures",          "SC-28"),
    (".env file",                 "A05 Security Misconfiguration",       "CM-6"),

    # Crypto weaknesses → A02
    ("md5",                       "A02 Cryptographic Failures",          "SC-13"),
    ("sha1",                      "A02 Cryptographic Failures",          "SC-13"),
    ("sha-1",                     "A02 Cryptographic Failures",          "SC-13"),
    ("des.new",                   "A02 Cryptographic Failures",          "SC-13"),
    ("rc4",                       "A02 Cryptographic Failures",          "SC-13"),
    ("math.random",               "A02 Cryptographic Failures",          "SC-13"),
    ("random.random",             "A02 Cryptographic Failures",          "SC-13"),

    # SSRF / network
    ("ssrf",                       "A10 Server-Side Request Forgery",     "SC-7"),
    ("curl ",                      "A10 Server-Side Request Forgery",     "SC-7"),
    ("wget ",                      "A10 Server-Side Request Forgery",     "SC-7"),
    ("verify=false",               "A02 Cryptographic Failures",          "SC-8"),
    ("check_hostname=false",       "A02 Cryptographic Failures",          "SC-8"),
    ("http://",                    "A02 Cryptographic Failures",          "SC-8"),

    # Misconfiguration / outdated deps → A06
    ("vulnerable dependency",      "A06 Vulnerable and Outdated Components", "SI-2"),
    ("outdated",                   "A06 Vulnerable and Outdated Components", "SI-2"),

    # Logging / monitoring
    ("audit",                      "A09 Security Logging and Monitoring Failures", "AU-2"),
    ("logging",                    "A09 Security Logging and Monitoring Failures", "AU-2"),
]

_DEFAULT_OWASP = "A05 Security Misconfiguration"
_DEFAULT_NIST  = "SI-2"


def map_compliance(finding: dict) -> dict:
    """
    Map a single finding to OWASP Top 10 (2021) and a relevant NIST 800-53
    control family. Matching is done on the finding's `type`/`title`/`category`
    fields (case-insensitive substring match), falling back to a generic
    security misconfiguration mapping.

    Returns:
        { "owasp": "A05 Security Misconfiguration", "nist": "SI-2" }
    """
    haystack = " ".join(str(finding.get(k, "")) for k in (
        "type", "title", "category", "description", "match"
    )).lower()

    for needle, owasp, nist in _COMPLIANCE_RULES:
        if needle in haystack:
            return {"owasp": owasp, "nist": nist}

    return {"owasp": _DEFAULT_OWASP, "nist": _DEFAULT_NIST}


def enrich_findings_with_compliance(findings: list) -> list:
    """
    Return a NEW list of findings, each with 'owasp' and 'nist' keys added.
    Does not mutate the input list — original finding dicts are copied.
    Safe to call on any list of dicts; unknown shapes get the default mapping.
    """
    enriched = []
    for f in findings or []:
        f2 = dict(f)
        f2.update(map_compliance(f))
        enriched.append(f2)
    return enriched


# ══════════════════════════════════════════════════════════════
#  3. REPOSITORY HEALTH DASHBOARD
# ══════════════════════════════════════════════════════════════

def compute_repo_health(
    findings: list,
    dependency_findings: list | None = None,
    dependency_count: int = 0,
) -> dict:
    """
    Build the repository health summary shown on the dashboard after a
    repository scan.

    Args:
        findings:            list of secret/vuln finding dicts (from scanner.py)
        dependency_findings: list of dependency vulnerability dicts (optional)
        dependency_count:    total number of dependencies detected (optional)

    Returns:
        {
          "security_score": int,
          "risk_level": str,
          "critical_count": int,
          "high_count": int,
          "medium_count": int,
          "low_count": int,
          "secret_count": int,
          "dependency_count": int,
          "outdated_packages": int,
        }
    """
    findings = findings or []
    dependency_findings = dependency_findings or []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    secret_count = 0

    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        # A finding is a "secret" if its type/category mentions a secret-ish term
        haystack = (str(f.get("type", "")) + " " + str(f.get("category", "")) + " " + str(f.get("title", ""))).lower()
        if any(term in haystack for term in (
            "key", "token", "secret", "password", "credential",
            "private key", "entropy", "jwt", "connection string"
        )):
            secret_count += 1

    # Fold dependency findings into the severity counts too
    outdated = 0
    for d in dependency_findings:
        sev = (d.get("severity") or "LOW").upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        outdated += 1

    score_info = compute_security_score(findings + dependency_findings)

    return {
        "security_score":    score_info["security_score"],
        "risk_level":         score_info["risk_level"],
        "critical_count":     counts["CRITICAL"],
        "high_count":         counts["HIGH"],
        "medium_count":       counts["MEDIUM"],
        "low_count":          counts["LOW"],
        "secret_count":       secret_count,
        "dependency_count":   dependency_count,
        "outdated_packages":  outdated,
    }


# ══════════════════════════════════════════════════════════════
#  4. AI AUTO-FIX ENGINE (rule-based before/after with confidence)
# ══════════════════════════════════════════════════════════════

# Each rule: (regex to find dangerous pattern, replacement template, explanation, confidence)
# `replacement` may use \1 \2 etc. backreferences from the match.
_AUTOFIX_RULES: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'\beval\s*\((.+?)\)'),
     r'ast.literal_eval(\1)',
     "eval() executes arbitrary Python code. ast.literal_eval() only parses literal "
     "Python data structures (strings, numbers, tuples, lists, dicts, booleans, None), "
     "making it safe for parsing user-supplied data.",
     95),

    (re.compile(r'\bexec\s*\((.+?)\)'),
     r'# exec(\1)  — remove dynamic execution; use explicit function dispatch instead',
     "exec() runs arbitrary code with full interpreter access. Replace dynamic code "
     "execution with an explicit mapping of allowed operations (e.g. a dict of functions).",
     80),

    (re.compile(r'os\.system\s*\((.+?)\)'),
     r'subprocess.run(\1, shell=False, check=True)',
     "os.system() invokes a full shell, enabling shell injection via unsanitised input. "
     "subprocess.run() with shell=False and an argument list avoids shell interpretation entirely.",
     90),

    (re.compile(r'subprocess\.call\((.+?),\s*shell\s*=\s*True\)'),
     r'subprocess.run(\1, shell=False, check=True)',
     "shell=True passes your command through a shell, allowing injection if any part "
     "of the command includes untrusted input. Pass arguments as a list with shell=False.",
     90),

    (re.compile(r'pickle\.loads?\((.+?)\)'),
     r'json.loads(\1)',
     "pickle.loads() can execute arbitrary code embedded in the pickled data. If the "
     "data is simple (dicts, lists, strings, numbers), json.loads() is a safe drop-in "
     "replacement with no code-execution risk.",
     70),

    (re.compile(r'yaml\.load\((.+?)\)'),
     r'yaml.safe_load(\1)',
     "yaml.load() can instantiate arbitrary Python objects from the YAML document, "
     "which can lead to code execution. yaml.safe_load() restricts parsing to basic "
     "YAML tags only.",
     95),

    (re.compile(r'hashlib\.md5\((.+?)\)'),
     r'hashlib.sha256(\1)',
     "MD5 is cryptographically broken and vulnerable to collision attacks. "
     "SHA-256 is a drop-in replacement for non-password hashing needs.",
     85),

    (re.compile(r'hashlib\.sha1\((.+?)\)'),
     r'hashlib.sha256(\1)',
     "SHA-1 is deprecated for security-sensitive use due to demonstrated collision "
     "attacks. SHA-256 provides a stronger, drop-in replacement.",
     85),

    (re.compile(r'verify\s*=\s*False'),
     r'verify=True',
     "Disabling SSL/TLS certificate verification allows man-in-the-middle attacks. "
     "Re-enable verification; if using a private CA, pass the CA bundle path instead "
     "of disabling verification entirely.",
     90),

    (re.compile(r'random\.random\(\)'),
     r'secrets.token_hex(16)',
     "random.random() is a non-cryptographic PRNG and is predictable. For security "
     "tokens, session IDs, or password reset codes, use the `secrets` module which "
     "is designed for cryptographic use.",
     80),

    (re.compile(r'Math\.random\(\)'),
     r'crypto.getRandomValues(new Uint32Array(1))[0]',
     "Math.random() in JavaScript is not cryptographically secure. For tokens or "
     "security-relevant randomness, use the Web Crypto API's getRandomValues().",
     80),

    (re.compile(r'\.innerHTML\s*=\s*(.+)'),
     r'.textContent = \1',
     "Assigning to innerHTML with untrusted data allows XSS via injected <script> or "
     "event-handler attributes. textContent renders the value as plain text, neutralising "
     "any HTML/JS payload. If HTML rendering is required, sanitise with DOMPurify first.",
     75),

    (re.compile(r"f[\"']SELECT.+?\{.+?\}.+?[\"']"),
     r'cursor.execute("SELECT ... WHERE id = %s", (value,))',
     "f-string interpolation directly into SQL allows SQL injection if any "
     "interpolated value comes from user input. Use parameterised queries — the "
     "driver escapes values safely.",
     85),
]


def generate_auto_fix(finding: dict) -> dict | None:
    """
    Given a finding dict (must contain a 'match' or 'description'/'type' field
    with the offending code snippet), attempt to generate a before/after fix.

    Returns:
        {
          "before": "<original snippet>",
          "after":  "<suggested replacement>",
          "explanation": "...",
          "confidence": 0-100
        }
        or None if no auto-fix rule matches.

    This is a pure, synchronous, rule-based engine — it never calls the network
    or the AI model, so it's safe to call on every finding without rate limits.
    """
    snippet = finding.get("match") or finding.get("title") or ""
    if not snippet:
        return None

    for pattern, replacement, explanation, confidence in _AUTOFIX_RULES:
        m = pattern.search(snippet)
        if m:
            try:
                after = pattern.sub(replacement, snippet, count=1)
            except re.error:
                after = replacement
            return {
                "before":      snippet.strip(),
                "after":       after.strip(),
                "explanation": explanation,
                "confidence":  confidence,
            }

    return None


def enrich_findings_with_autofix(findings: list) -> list:
    """
    Return a NEW list of findings, each with an 'auto_fix' key added
    (None if no rule matched). Does not mutate input.
    """
    enriched = []
    for f in findings or []:
        f2 = dict(f)
        f2["auto_fix"] = generate_auto_fix(f)
        enriched.append(f2)
    return enriched


# ══════════════════════════════════════════════════════════════
#  COMBINED ENRICHMENT  (used by app.py and tasks.py)
# ══════════════════════════════════════════════════════════════

def enrich_findings_full(findings: list) -> list:
    """
    Single entry point: adds compliance mapping (owasp/nist) and
    auto_fix suggestions to every finding in one pass. Does not mutate input.
    """
    findings = findings or []
    enriched = []
    for f in findings:
        f2 = dict(f)
        f2.update(map_compliance(f))
        f2["auto_fix"] = generate_auto_fix(f)
        enriched.append(f2)
    return enriched
