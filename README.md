# ESP32 SecureCheck

A lightweight, local static security analyzer for ESP32 and Arduino firmware projects.

ESP32 SecureCheck scans source files for common security-sensitive patterns and reports findings with rule IDs, severity, confidence, file locations, and remediation guidance.

> **Important:** This is a heuristic source-code scanner, not a proof of security. It can produce false positives and false negatives. Review every finding in context. A clean scan is not a security certification.

## Features

- Detect likely hardcoded Wi-Fi credentials, passwords, API keys, and tokens (SEC001).
- Flag plaintext HTTP URLs (NET001).
- Scan ESP-IDF `sdkconfig` and `sdkconfig.defaults` for the documented insecure ESP-TLS verification bypass (IDF001).
- Detect common disabled TLS certificate-verification patterns (TLS001).
- Flag ArduinoOTA setup without an obvious password configuration (OTA001).
- Flag common one-argument ESP32 `WiFi.softAP(ssid)` calls that create an open access point (WIFI001).
- Detect likely credential values passed to serial logging (DBG001).
- Flag MD5 and SHA-1 usage (CRY001).
- Terminal, JSON, and SARIF output.
- Runs locally; scanned source files are not uploaded by the tool.

## Requirements

- Python 3.10 or later
- No third-party runtime dependencies

## Install from source

```bash
python -m pip install -e .
```

For development and tests:

```bash
python -m pip install -e ".[dev]"
```

## Usage

Scan the current project:

```bash
securecheck scan .
```

Scan a specific file or directory:

```bash
securecheck scan src/main.cpp
securecheck scan src/
```

Write JSON or SARIF output:

```bash
securecheck scan . --format json --output securecheck-report.json
securecheck scan . --format sarif --output securecheck.sarif
```

You can also run it as a module:

```bash
python -m securecheck scan .
```

Use `--fail-on low`, `--fail-on medium`, or `--fail-on high` to return exit status `1` when a finding at or above that severity is present. Without `--fail-on`, a completed scan exits with status `0`, even when findings are reported. Invalid paths return status `2`.

## Detection rules

| Rule | Default severity | What it looks for |
|---|---|---|
| SEC001 | High | Likely hardcoded passwords, API keys, tokens, or secrets |
| NET001 | Medium | Plaintext HTTP URLs (loopback URLs are ignored) |
| TLS001 | High | Common patterns that disable TLS certificate and hostname verification |
| IDF001 | High | Both ESP-IDF insecure ESP-TLS server-verification options enabled in an sdkconfig file |
| OTA001 | High | `ArduinoOTA.begin()` without a detectable password-setting call in the same file |
| WIFI001 | Medium | Common one-argument `WiFi.softAP(ssid)` calls with no password argument |
| DBG001 | Medium | Credential-like values passed to serial logging |
| CRY001 | Medium | MD5 or SHA-1 usage |

Rules are pattern-based and intentionally limited. IDF001 reports only when both `CONFIG_ESP_TLS_INSECURE=y` and `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y` are present in the same sdkconfig file. ESP-IDF documentation describes these options as a testing-only server-verification bypass; explicit per-connection certificate configuration may change the effective behavior. Review the project's TLS configuration before treating this finding as exploitable. See the [ESP-IDF ESP-TLS documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/protocols/esp_tls.html). WIFI001 only recognizes the common one-argument call form; calls wrapped in helpers or configured elsewhere may not be detected. OTA001 only checks whether a password-setting call appears in the scanned file; it cannot establish whether OTA is reachable or exploitable, and it may miss configuration performed in another file. TLS001 recognizes only a limited set of common APIs and patterns.

## Example output

```text
HIGH   SEC001  src/main.cpp:12  Possible hardcoded credential or secret
       Fix: Remove secrets from source control, use secure provisioning, and rotate any real secret that was committed.
```

The repository includes `examples/vulnerable_firmware.ino` as a synthetic fixture for trying the rules. It contains deliberately fake values and must not be used on a real device.

## Development

Run the test suite:

```bash
python -m pip install -e ".[dev]"
pytest
```

Tests use synthetic sample source. Do not put real credentials in tests, example files, or issue reports.

## Security and responsible use

ESP32 SecureCheck is intended to help developers review firmware they own or are authorized to assess. It does not connect to devices, exploit vulnerabilities, extract secrets, or modify firmware.

See [SECURITY.md](SECURITY.md) for reporting security issues and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## License

MIT. See [LICENSE](LICENSE).
