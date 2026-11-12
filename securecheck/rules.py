import os
import re
from pathlib import Path
from .models import Finding

SOURCE_EXTENSIONS = {
    ".ino", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".properties",
}
CONFIG_FILE_NAMES = {"sdkconfig", "sdkconfig.defaults"}

def is_kconfig_file(path: Path) -> bool:
    return path.name in CONFIG_FILE_NAMES or path.name.startswith("sdkconfig.defaults.")

IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "build", "dist",
    "node_modules", ".pio", ".idea", ".vscode",
}
PLACEHOLDER_MARKERS = (
    "your_", "example", "placeholder", "change_me", "changeme",
    "replace_me", "xxxx", "\x24{", "{{", "<redacted",
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
    re.compile(r"\bskip_common_name\s*=\s*(?:true|1)\b", re.I),
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
# Matches the common one-argument Arduino ESP32 WiFi.softAP(ssid) form.
# Calls with an explicit password are intentionally not reported.
OPEN_SOFTAP_RE = re.compile(
    r"\bWiFi\s*\.\s*softAP\s*\(\s*[^,()\n]+?\s*\)", re.I
)

def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return any(marker in normalized for marker in PLACEHOLDER_MARKERS) or normalized in {
        "demo-password-not-for-production", "not-a-real-secret"
    }

def _finding(rule_id, severity, confidence, message, path, line, remediation):
    return Finding(rule_id, severity, confidence, message, str(path), line, remediation)

def _is_reference_url(path: Path, line: str, host: str) -> bool:
    """Ignore reserved example hosts and URLs used only as descriptive metadata."""
    if host.lower() in {"example.com", "example.org", "example.net", "example.edu"}:
        return True
    if re.search(r"<(?:manufacturerURL|modelURL|presentationURL)\s*>", line, re.I):
        return True
    if re.search(r"\bhref\s*=", line, re.I):
        return True
    if path.name.lower() in {"library.json", "package.json", "component.json"}:
        if re.search(r"""["'](?:url|homepage|repository|documentation|bugs)["']\s*:""", line, re.I):
            return True
    if path.name.lower() == "library.properties":
        if re.search(r"^\s*(?:url|homepage|repository)\s*=", line, re.I):
            return True
    return False

def _strip_comments(text: str, suffix: str) -> str:
    """Remove source comments while preserving strings, newlines, and line numbers."""
    c_style = suffix in {".ino", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
    hash_style = suffix in {".py", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties"}
    hash_comment_chars = {"#"}
    if suffix in {".ini", ".cfg"}:
        hash_comment_chars.add(";")
    if suffix == ".properties":
        hash_comment_chars.add("!")
    chars = list(text)
    state = "code"
    quote = None
    triple = False
    escaped = False
    i = 0

    while i < len(text):
        char = text[i]
        next_char = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[i] = " "
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                chars[i] = chars[i + 1] = " "
                state = "code"
                i += 2
            else:
                if char != "\n":
                    chars[i] = " "
                i += 1
            continue

        if quote is not None:
            if escaped:
                escaped = False
                i += 1
            elif char == "\\":
                escaped = True
                i += 1
            elif triple and text.startswith(quote * 3, i):
                quote = None
                triple = False
                i += 3
            elif not triple and char == quote:
                quote = None
                i += 1
            else:
                i += 1
            continue

        if c_style and char == "/" and next_char == "/":
            chars[i] = chars[i + 1] = " "
            state = "line_comment"
            i += 2
        elif c_style and char == "/" and next_char == "*":
            chars[i] = chars[i + 1] = " "
            state = "block_comment"
            i += 2
        elif hash_style and char in hash_comment_chars:
            chars[i] = " "
            state = "line_comment"
            i += 1
        elif char in {"'", '"'}:
            quote = char
            triple = suffix == ".py" and text.startswith(char * 3, i)
            i += 3 if triple else 1
        else:
            i += 1

    return "".join(chars)

def scan_file(path: Path, text: str) -> list[Finding]:
    findings = []
    comment_suffix = ".toml" if is_kconfig_file(path) else path.suffix.lower()
    cleaned = _strip_comments(text, comment_suffix)
    lines = cleaned.splitlines()
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
            if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
                continue
            if _is_reference_url(path, line, host):
                continue
            findings.append(_finding(
                "NET001", "MEDIUM", "MEDIUM",
                f"Plaintext HTTP URL points to '{host}'", path, number,
                "Prefer HTTPS with certificate validation for network endpoints. Review whether this URL is an active firmware connection, local captive-portal redirect, or informational reference."
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
                    "CRY001", "LOW", "MEDIUM",
                    f"Review use of legacy hash algorithm: {algorithm}",
                    path, number,
                    "Do not use MD5 or SHA-1 where collision resistance, signatures, password storage, or authentication security is required. If used only for a non-security identifier or compatibility, document that purpose."
                ))
                break

    joined = "\n".join(lines)
    if is_kconfig_file(path):
        insecure_flags = (
            "CONFIG_ESP_TLS_INSECURE",
            "CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY",
        )
        enabled = [
            re.search(rf"^\s*{re.escape(flag)}\s*=\s*y\s*$", joined, re.M)
            for flag in insecure_flags
        ]
        if all(enabled):
            line_number = joined[:enabled[-1].start()].count("\n") + 1
            findings.append(_finding(
                "IDF001", "HIGH", "MEDIUM",
                "ESP-IDF enables the insecure ESP-TLS server-verification bypass",
                path, line_number,
                "Disable CONFIG_ESP_TLS_INSECURE and CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY. Use a trusted CA certificate, the certificate bundle, a global CA store, or an intentionally managed PSK verification method."
            ))

    for match in OPEN_SOFTAP_RE.finditer(joined):
        line_number = joined[:match.start()].count("\n") + 1
        findings.append(_finding(
            "WIFI001", "MEDIUM", "HIGH",
            "Wi-Fi SoftAP appears to be created without a password",
            path, line_number,
            "Require a strong WPA2/WPA3 passphrase for the setup access point and avoid exposing sensitive services on an open network."
        ))

    begin_match = re.search(r"\bArduinoOTA\s*\.\s*begin\s*\(", joined)
    password_match = re.search(r"\bArduinoOTA\s*\.\s*setPassword(?:Hash)?\s*\(", joined)
    ota_disabled_by_default = re.search(
        r"(?m)^\s*#\s*ifndef\s+OTA_ENABLE\s*\n\s*#\s*define\s+OTA_ENABLE\s+(?:false|0)\b",
        joined,
        re.I,
    )
    if begin_match and not password_match and not ota_disabled_by_default:
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
            if candidate.suffix.lower() in SOURCE_EXTENSIONS or is_kconfig_file(candidate):
                found.append(candidate)
    return sorted(found)
