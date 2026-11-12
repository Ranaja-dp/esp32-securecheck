# Preliminary real-world evaluation — 2026-11-13

## Scope and method

This is a preliminary static-analysis evaluation, not a security audit or proof that any project is secure. The targets were cloned read-only at fixed commits, then scanned locally with ESP32 SecureCheck. No upstream repository was changed, and no hardware, firmware build, or runtime network test was performed.

The scanner version in `pyproject.toml` was `0.1.0`. Counts below refer to files discovered by SecureCheck, not the total files tracked by Git.

## Targets and results

| Target | Upstream commit | Files scanned | Result |
|---|---|---:|---|
| [Ranaja-dp/ESP32-IR-Remote](https://github.com/Ranaja-dp/ESP32-IR-Remote) | `2f1026773e6b07813a928b3241708b2b835fbe9b` | 0 | Not evaluable: the checked-out default branch contained only four tracked documentation/governance files and no supported firmware/configuration source files. SecureCheck now exits with status 2 for this case instead of reporting a clean scan. |
| [espressif/esp-idf-template](https://github.com/espressif/esp-idf-template) | `fc07431210543a4a47ed2664d3f7f0a84e8a1b4f` | 1 | 0 findings. This is a minimal starter template, so this is only a smoke test, not a meaningful security benchmark. |
| [crankyoldgit/IRremoteESP8266](https://github.com/crankyoldgit/IRremoteESP8266) | `1e2f0f3ef0a93cbf2a8ddb2e95130f8f4c584b3f` | 321 | 0 findings after triage-oriented refinements. An initial scan produced URL-metadata and disabled-by-default OTA noise; those cases are described below. |
| [wled/WLED](https://github.com/wled/WLED) | `bd5261796d4cbc3f9f406e20cad1d213514aaaf2` | 317 | 4 heuristic findings requiring human review. Only `wled00/` and `usermods/` were checked out and scanned, not the entire repository. |

## WLED findings reviewed

The WLED scan produced the following results:

| Rule | Count | Locations / interpretation |
|---|---:|---|
| CRY001 (low) | 2 | SHA-1 is used in a usermod to derive a device identifier from a MAC address plus salt, and in `wled00/util.cpp` for a stable device fingerprint. These are review prompts, not confirmed authentication or signature weaknesses. |
| OTA001 (high, low confidence) | 1 | `wled00/wled.cpp` calls `ArduinoOTA.begin()` when the optional `WLED_ENABLE_AOTA` build option and runtime `aOtaEnabled` setting are enabled. No `ArduinoOTA.setPassword*` call was found in the scanned checkout. Review the exact build/runtime configuration before treating this as an exposed unauthenticated update service. |
| NET001 (medium) | 1 | `wled00/wled_server.cpp` redirects a captive-portal request to `http://4.3.2.1` while the device access point is active. This appears to be an intentional local captive-portal redirect, not an outbound plaintext API connection. |

## False-positive fixes informed by the evaluation

The initial IRremoteESP8266 scan reported:
- HTTP links in `library.json` maintainer/repository metadata;
- an HTTP link embedded in generated HTML content;
- an OTA call in `BaseOTA.h`, where `OTA_ENABLE` is explicitly set to `false` by default.

The scanner was refined to ignore package-manifest URL metadata, descriptive HTML/XML URLs, and reserved example domains. It also skips the OTA finding when that file explicitly defines `OTA_ENABLE false` by default. Build-system overrides are not fully resolved, so an external compiler definition can still change the effective OTA configuration.

The CRY001 rule was lowered to an informational review severity because MD5/SHA-1 references are not automatically vulnerabilities; context and purpose matter.

## Reproduction

From the SecureCheck repository root:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m securecheck scan <path-to-cloned-project> --format json --output report.json
```

The original target commits are recorded above so future evaluations can compare like-for-like. Repeat the scans against newer commits before making claims about current upstream code.

## Limitations and next steps

- The rules are pattern-based and can miss code paths, build flags, generated sources, or configuration supplied by other files.
- The WLED run was a sparse checkout of two source directories, not a complete repository scan.
- The ESP-IDF starter template is too small to provide broad coverage.
- The ESP32-IR-Remote repository currently has no checked-in source files on its default branch, so its implementation cannot yet be evaluated by this scanner.
- These results demonstrate an early test against public codebases; they do not demonstrate broad adoption, active external users, or community validation.

Next validation should include a complete scan of a real ESP-IDF application, confirmation of each finding by maintainers, and feedback from developers who try the GitHub Action in their own repositories.
