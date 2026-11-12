# Use ESP32 SecureCheck in GitHub Actions

ESP32 SecureCheck is packaged as a composite GitHub Action. Add it to an existing workflow after checking out your firmware repository.

## Minimal workflow

Create `.github/workflows/firmware-security.yml` in your firmware repository:

```yaml
name: Firmware Security

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  securecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan ESP32 firmware
        uses: Ranaja-dp/esp32-securecheck@main
        with:
          scan-path: firmware
          fail-on: medium
          upload-sarif: "false"
```

Change `firmware` to the folder containing your source. Use `.` to scan the whole repository.

The action automatically creates a `securecheck.sarif` report and uploads it as a workflow artifact named `securecheck-sarif` (retained for 30 days). The scan step returns a failing status when `fail-on` is set to `low`, `medium`, or `high` and a matching finding is present. The default `none` reports findings without failing the workflow.

## Publish results in GitHub code scanning

To publish findings in your repository's Security tab, grant `security-events: write` to the job and set `upload-sarif: "true"`:

```yaml
permissions:
  contents: read

jobs:
  securecheck:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Ranaja-dp/esp32-securecheck@main
        with:
          scan-path: .
          fail-on: medium
          upload-sarif: "true"
```

The upload step is skipped for pull requests from forks because their workflow token cannot write code-scanning results. The SARIF artifact is still uploaded. GitHub code scanning availability and repository settings may affect whether uploaded results appear in the Security tab.

## Inputs

| Input | Default | Description |
|---|---|---|
| `scan-path` | `.` | Repository-relative folder or file to scan |
| `python-version` | `3.12` | Python version |
| `fail-on` | `none` | Severity threshold: `none`, `low`, `medium`, or `high` |
| `upload-sarif` | `false` | Publish results to GitHub code scanning |

## Version pinning

The examples use `@main` for convenience while the action is being developed. For stable production use, pin the action to a reviewed release tag or full commit SHA. A versioned release will be created after the action has been exercised in a separate firmware repository.

## Security notes

- Do not run untrusted pull-request code with elevated tokens.
- The action scans the checked-out repository; it does not connect to devices or upload firmware source code to an external service.
- Findings are heuristic and require review. A clean scan is not a security certification.
