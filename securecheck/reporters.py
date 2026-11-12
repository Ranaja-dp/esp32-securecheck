import json
from collections import Counter
from .models import Finding

def to_json(findings: list[Finding], scanned_files: int) -> str:
    return json.dumps({
        "tool": {"name": "ESP32 SecureCheck", "version": "0.1.0"},
        "summary": {
            "scanned_files": scanned_files,
            "findings": len(findings),
            "by_severity": dict(Counter(f.severity for f in findings)),
        },
        "findings": [f.to_dict() for f in findings],
    }, indent=2)

def to_sarif(findings: list[Finding]) -> str:
    rules, results = {}, []
    level_map = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "shortDescription": {"text": f.message},
            "help": {"text": f.remediation},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f"{f.message} (confidence: {f.confidence})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path.replace("\\", "/")},
                "region": {"startLine": f.line},
            }}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "ESP32 SecureCheck", "version": "0.1.0",
            "rules": list(rules.values()),
        }}, "results": results}],
    }, indent=2)

def to_terminal(findings: list[Finding], scanned_files: int) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        "ESP32 SecureCheck",
        f"Scanned files: {scanned_files}",
        f"Findings: {len(findings)}",
        f"Severity: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}",
        "",
    ]
    if not findings:
        lines.append("No findings detected. This does not guarantee firmware security.")
    for f in findings:
        lines.append(f"{f.severity:<6} {f.rule_id:<7} {f.path}:{f.line}  {f.message}")
        lines.append(f"       Fix: {f.remediation}")
    return "\n".join(lines)
