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

def test_empty_source():
    assert ids_for("// safe starter file") == []
