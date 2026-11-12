import json
from pathlib import Path
from securecheck.cli import build_parser, run_scan

def test_json_report_and_fail_threshold(tmp_path):
    (tmp_path / "main.ino").write_text('const char* password = "real-looking-secret";', encoding="utf-8")
    output = tmp_path / "report.json"
    args = build_parser().parse_args(["scan", str(tmp_path), "--format", "json", "--output", str(output), "--fail-on", "high"])
    assert run_scan(args) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] == 1
    assert report["findings"][0]["rule_id"] == "SEC001"

def test_missing_path_returns_error(tmp_path):
    args = build_parser().parse_args(["scan", str(tmp_path / "missing")])
    assert run_scan(args) == 2

def test_sarif_paths_include_scan_directory_from_repository_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "firmware"
    project.mkdir()
    (project / "main.ino").write_text('const char* password = "real-looking-secret";', encoding="utf-8")
    output = tmp_path / "report.sarif"
    args = build_parser().parse_args(["scan", "firmware", "--format", "sarif", "--output", str(output)])
    assert run_scan(args) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "firmware/main.ino"
