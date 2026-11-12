import argparse
import sys
from pathlib import Path
from . import __version__
from .reporters import to_json, to_sarif, to_terminal
from .rules import discover_files, is_kconfig_file, scan_file

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
SUPPORTED = {".ino", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties"}

def build_parser():
    parser = argparse.ArgumentParser(prog="securecheck", description="Static security checks for ESP32 and Arduino firmware.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a firmware project")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output")
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--fail-on", choices=("low", "medium", "high"))
    return parser

def run_scan(args):
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 2
    if root.is_file():
        files = [root] if root.suffix.lower() in SUPPORTED or is_kconfig_file(root) else []
    else:
        files = discover_files(root, args.exclude)

    if not files:
        print(
            f"Error: no supported source or configuration files found to scan in {root}",
            file=sys.stderr,
        )
        return 2

    findings = []
    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"Warning: cannot read {file_path}: {exc}", file=sys.stderr)
            continue
        # SARIF URIs must be relative to the repository checkout, not the
        # selected scan subdirectory, so GitHub can map results to source files.
        try:
            display_path = file_path.relative_to(Path.cwd())
        except ValueError:
            display_path = Path(file_path.name) if root.is_file() else file_path.relative_to(root)
        findings.extend(scan_file(display_path, content))

    report = (to_json(findings, len(files)) if args.format == "json"
              else to_sarif(findings) if args.format == "sarif"
              else to_terminal(findings, len(files)))
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0

def main():
    args = build_parser().parse_args()
    if args.command == "scan":
        raise SystemExit(run_scan(args))

if __name__ == "__main__":
    main()
