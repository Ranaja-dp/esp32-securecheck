from pathlib import Path
from securecheck.rules import scan_file

def ids_for(source):
    return [f.rule_id for f in scan_file(Path("sample.ino"), source)]

def test_detects_hardcoded_password():
    assert "SEC001" in ids_for('const char* password = "SuperSecret123";')

def test_ignores_placeholder_password():
    assert "SEC001" not in ids_for('const char* password = "YOUR_WIFI_PASSWORD";')

def test_detects_plain_http_but_ignores_loopback():
    ids = ids_for('const char* a = "http://example.com";\nconst char* b = "http://localhost";')
    assert ids.count("NET001") == 1

def test_detects_insecure_tls():
    assert "TLS001" in ids_for("client.setInsecure();")

def test_detects_ota_without_password():
    assert "OTA001" in ids_for("void setup() { ArduinoOTA.begin(); }")

def test_ota_password_prevents_finding():
    assert "OTA001" not in ids_for("ArduinoOTA.setPassword(otaPassword); ArduinoOTA.begin();")

def test_detects_secret_in_serial_log():
    assert "DBG001" in ids_for("Serial.println(wifi_password);")

def test_detects_weak_hash():
    assert "CRY001" in ids_for("MD5(data);")

def test_detects_open_softap():
    findings = scan_file(Path("sample.ino"), 'WiFi.softAP("ESP32-Setup");')
    wifi_findings = [f for f in findings if f.rule_id == "WIFI001"]
    assert len(wifi_findings) == 1
    assert wifi_findings[0].line == 1
    assert wifi_findings[0].confidence == "HIGH"

def test_ignores_softap_with_explicit_password():
    assert "WIFI001" not in ids_for('WiFi.softAP("ESP32-Setup", "strong-passphrase");')

def test_detects_multiline_open_softap():
    findings = scan_file(Path("sample.ino"), 'WiFi.softAP(\n    "ESP32-Setup"\n);')
    assert "WIFI001" in [f.rule_id for f in findings]

def test_empty_source():
    assert ids_for("// safe starter file") == []


def test_ignores_commented_out_cpp_patterns():
    source = '// client.setInsecure();\n/* MD5(data); */\n// WiFi.softAP("OpenNetwork");'
    ids = ids_for(source)
    assert "TLS001" not in ids
    assert "CRY001" not in ids
    assert "WIFI001" not in ids

def test_preserves_http_url_in_string_and_ignores_comment_url():
    source = 'const char* endpoint = "http://example.com"; // http://comment-only.example'
    assert ids_for(source).count("NET001") == 1

def test_ignores_python_comment_but_scans_string():
    source = '# client.setInsecure()\nurl = "http://example.com"\n'
    findings = scan_file(Path("sample.py"), source)
    ids = [finding.rule_id for finding in findings]
    assert "TLS001" not in ids
    assert "NET001" in ids


def test_detects_esp_idf_tls_verification_bypass():
    config = Path("sdkconfig")
    source = (
        "CONFIG_ESP_TLS_INSECURE=y\n"
        "CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y\n"
    )
    findings = scan_file(config, source)
    idf_findings = [f for f in findings if f.rule_id == "IDF001"]
    assert len(idf_findings) == 1
    assert idf_findings[0].line == 2
    assert idf_findings[0].severity == "HIGH"

def test_esp_idf_tls_rule_requires_both_options():
    config = Path("sdkconfig.defaults")
    source = "CONFIG_ESP_TLS_INSECURE=y\n# CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY is not set\n"
    assert "IDF001" not in [f.rule_id for f in scan_file(config, source)]

def test_discovers_sdkconfig_files(tmp_path):
    from securecheck.rules import discover_files
    (tmp_path / "sdkconfig").write_text("CONFIG_EXAMPLE=y\n", encoding="utf-8")
    (tmp_path / "sdkconfig.defaults.esp32").write_text("CONFIG_EXAMPLE=y\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not scanned\n", encoding="utf-8")
    names = [p.name for p in discover_files(tmp_path)]
    assert names == ["sdkconfig", "sdkconfig.defaults.esp32"]

def test_detects_esp_tls_skip_common_name():
    assert "TLS001" in ids_for("esp_tls_cfg_t cfg = {.skip_common_name = true};")
