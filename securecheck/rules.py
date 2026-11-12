import os
import re
from pathlib import Path
from .models import Finding

SOURCE_EXTENSIONS = {
    ".ino", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".py", ".json", ".yaml", ".yml", ".toml",
}
IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "build", "dist",
    "node_modules", ".pio", ".idea", ".vscode",
}
PLACEHOLDER_MARKERS = (
    "your_", "example", "placeholder", "change_me", "changeme",
    "replace_me", "xxxx", "${", "{{", "<redacted",
)
SECRET_RE = re.compile(
    r"""(?ix)\b(?:ssid|wifi_password|password|passwd|api[_-]?key|access[_-]?token|secret)\b\s*(?:=|:)\s*["']([^"'\\]{4,})["']"""
)
HTTP_RE = re.compile(r"""(?i)\bhttp://([a-z0-9.-]+)(?::\d+)?""")
TLS_PATTERNS = [
    re.compile(r"\bsetInsecure\s*\(", re.I),
    re.compile(r"\bverify\s*=\s*False\b"),
    re.compile(r"\bCERT_NONE\b"),
    re.compile(r"\bcheck_hostname\s*=\s*False\b"),
]
WEAK_CRYPTO_PATTERNS = [
    (re.compile(r"\bMD5\s*\(", re.I), "MD5"),
    (re.compile(r"\bSHA1\s*\(", re.I), "SHA-1"),
    (re.compile(r"\bmbedtls_md5\b", re.I), "MD5"),
    (re.compile(r"\bmbedtls_sha1\b", re.I), "SHA-1"),
]
SERIAL_RE = re.compile(r"\bSerial[0-9]*\s*\.\s*print(?:ln)?\s*\(", re.I)
SENSITIVE_NAME_RE = re.compile(
    r"\b(?:password|passwd|secret|token|api[_-]?key|wifi[_-]?(?:key|password))\b", re.I
)

def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return any(marker in normalized for marker in PLACEHOLDER_MARKERS) or normalized in {
        "demo-password-not-for-production", "not-a-real-secret"
    }

def _finding(rule_id, severity, confidence, message, path, line, remediation):
    return Finding(rule_id, severity, confidence, message, str(path), line, remediation)

def scan_file(path: Path, text: str) -> list[Finding]:
    findings = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for match in SECRET_RE.finditer(line):
            if not _is_placeholder(match.group(1)):
                findings.append(_finding(
                    "SEC001", "HIGH", "MEDIUM",
                    "Possible hardcoded credential or secret", path, number,
                    "Remove secrets from source control, use secure provisioning, and rotate any real secret that was committed."
                ))
                break

        for match in HTTP_RE.finditer(line):
            host = match.group(1).lower()
            if host not in {"localhost", "127.0.0.1", "0.0.0.0"}:
                findings.append(_finding(
                    "NET001", "MEDIUM", "MEDIUM",
                    f"Plaintext HTTP URL points to '{host}'", path, number,
                    "Prefer HTTPS with certificate validation for sensitive traffic. Document any intentional HTTP use in the threat model."
                ))
                break

        if any(pattern.search(line) for pattern in TLS_PATTERNS):
            findings.append(_finding(
                "TLS001", "HIGH", "HIGH",
                "TLS certificate verification appears to be disabled", path, number,
                "Validate the server certificate and hostname using a trusted CA or a carefully managed pinning strategy."
            ))

        if SERIAL_RE.search(line) and SENSITIVE_NAME_RE.search(line):
            findings.append(_finding(
                "DBG001", "MEDIUM", "MEDIUM",
                "Serial output may expose a credential or secret", path, number,
                "Remove secret values from logs. Log a redacted status or non-sensitive identifier instead."
            ))

        for pattern, algorithm in WEAK_CRYPTO_PATTERNS:
            if pattern.search(line):
                findings.append(_finding(
                    "CRY001", "MEDIUM", "MEDIUM",
                    f"Weak or legacy hash algorithm detected: {algorithm}", path, number,
                    "Avoid MD5 and SHA-1 for security-sensitive uses. Select a modern, reviewed cryptographic construction."
                ))
                break

    joined = "\n".join(lines)
    begin_match = re.search(r"\bArduinoOTA\s*\.\s*begin\s*\(", joined)
    password_match = re.search(r"\bArduinoOTA\s*\.\s*setPassword(?:Hash)?\s*\(", joined)
    if begin_match and not password_match:
        line_number = joined[:begin_match.start()].count("\n") + 1
        findings.append(_finding(
            "OTA001", "HIGH", "LOW",
            "ArduinoOTA.begin() found without detectable password setup in this file",
            path, line_number,
            "Configure OTA authentication or a stronger authenticated update mechanism. This heuristic may miss setup performed in another file."
        ))
    return findings

def discover_files(root: Path, extra_excludes: list[str] | None = None) -> list[Path]:
    excludes = set(extra_excludes or [])
    found = []
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS and d not in excludes)
        for name in sorted(names):
            candidate = Path(current) / name
            if candidate.suffix.lower() in SOURCE_EXTENSIONS:
                found.append(candidate)
    return sorted(found)
