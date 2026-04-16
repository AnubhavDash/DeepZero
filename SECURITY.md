# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ |
| Older releases | ❌ |

We only provide security fixes for the latest release. Please update before reporting.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via one of the following:

- **GitHub Private Advisories**: [Security Advisories](https://github.com/416rehman/DeepZero/security/advisories/new)
- **Email**: If a maintainer email is listed on their GitHub profile, use that.

Please include:

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected component (e.g., pipeline YAML parsing, processor loader, state ledger, CLI)
- Any suggested mitigations if you have them

You can expect an acknowledgment within **72 hours** and a status update within **7 days**.

---

## Threat Model & Known Risk Areas

DeepZero is a local pipeline orchestrator. The following areas carry inherent risk and are worth scrutinizing:

### Arbitrary Processor Loading
DeepZero dynamically loads Python modules from paths specified in pipeline YAML files (e.g., `processor: ./modules/example.py:ExampleImplementation`). **Only run pipelines from sources you trust.** A malicious YAML file can execute arbitrary code on your machine.

### YAML Deserialization
Pipeline configs are parsed from YAML. DeepZero uses safe YAML loading, but user-supplied configs should still be treated as untrusted input.

### Filesystem Access
The state ledger and work directory are written to the local filesystem based on paths in the pipeline config. Ensure pipeline YAMLs do not specify sensitive or unintended paths for `work_dir`.

### Worker Parallelism
Map-stage processors are parallelized across system workers. Processors that perform network I/O, spawn subprocesses, or access shared resources should be reviewed for race conditions and privilege escalation.

---

## Security Best Practices for Processor Authors

If you are writing a custom processor or contributing upstream:

- Never `eval`, `exec`, or deserialize untrusted data inside a processor.
- Avoid hardcoding credentials; use environment variables.
- Keep `setup()` / `teardown()` symmetric, don't leave sockets or file handles open.
- Run the required linting and security scan before submitting:
  ```bash
  ruff check . && ruff format --check . && bandit -r src processors
  ```
- `bandit` is already part of the CI gate, address all `HIGH` and `MEDIUM` severity findings before opening a PR.

---

## Disclosure Policy

We follow **coordinated disclosure**. Once a fix is ready, we will:

1. Release a patched version.
2. Publish a GitHub Security Advisory crediting the reporter (unless anonymity is requested).
3. Add a note to the changelog.

We ask that reporters allow us a reasonable remediation window before any public disclosure.
