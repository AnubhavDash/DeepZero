# DeepZero

**DeepZero** is an automated, AI-powered framework for discovering zero-day vulnerabilities in Windows kernel drivers at massive scale. 

**Read the disclosure blog post:** [Finding a Zero-Day in ASUS Drivers with DeepAgents, LangChain, and Vertex AI](https://blog.ahmadz.ai/automated-deepagents-langchain-pipeline-for-zero-days/)

## Overview

Finding vulnerabilities in Windows kernel drivers usually means manually reverse engineering binaries in IDA or Ghidra. `DeepZero` automates this process using a multi-stage pipeline:

1. **Mass Triage:** Parses thousands of `.sys` files locally via `pefile` to identify Windows kernel drivers with user-reachable IOCTL surfaces, scoring them against heuristics from the [LOLDrivers](https://www.loldrivers.io/) database.
2. **Decompilation:** Dispatches candidates to headless Ghidra to trace down `DriverEntry`, isolate the `IRP_MJ_DEVICE_CONTROL` dispatch handler, and extract clean C code for all IOCTL functions.
3. **Pattern Matching:** Runs custom Semgrep rules against the decompiled C to find known vulnerability shapes (e.g., `MmMapIoSpace` with attacker-controlled physical addresses, missing `ProbeForRead`).
4. **Agentic LLM Assessment:** Feeds the surviving candidates, decompiled dispatch handlers, and Semgrep findings into an LLM agent built on [DeepAgents](https://github.com/langchain-ai/deepagents) and Vertex AI (Gemini 2.5 Pro). The agent traces data flow, rejects false positives (e.g., hardware-gated paths), and generates a final `VULNERABLE` or `SAFE` report.

Everything before the LLM phase runs locally to save API costs. The pipeline deduplicates drivers by SHA256 hash to prevent redundant analysis.

## Prerequisites

- **Python 3.11+**
- **Ghidra** (download and unzip anywhere on your system)
- **Google Cloud Vertex AI** access (for the Gemini 2.5 Pro agent)

## Installation

DeepZero requires a standard Python environment and an external Ghidra installation to perform its reverse engineering subroutines.

1. Clone the repository:
   ```bash
   git clone https://github.com/416rehman/deepzero.git
   cd deepzero
   ```
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -e .
   ```

## Configuration

Copy `.env.example` to `.env` and fill in your paths and project details:

```ini
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
GOOGLE_CLOUD_LOCATION=us-central1
GHIDRA_INSTALL_DIR=C:\path\to\ghidra_11.x_PUBLIC
```

## Usage

You can point the agent at a single `.sys` file, a directory of drivers, or a massive driver pack:

```bash
# Analyze a specific driver pack directory
byovd "C:\Users\username\Downloads\Drivers"

# Specific driver
byovd "C:\path\to\target.sys"
```

The pipeline will emit JSON logs to `work/` and write the final LLM assessment for flagged drivers to `VULNERABLE_report.md` or `SAFE_report.md` inside driver-specific subdirectories under `work/`.

## Performance & Caching

Decompiling drivers is computationally expensive. Based on empirical runs:
- **Triage Phase:** Extremely fast (validating PE headers and import tables for thousands of drivers takes only seconds/minutes).
- **Ghidra Phase:** Takes roughly **1 to 3 minutes per driver** depending on complexity. 
- **Scale:** Because analysis runs concurrently across a thread pool, throughput is high. Analyzing a massive driver pack with ~7,500 candidates takes roughly **8 to 10 hours** (overnight) on a standard machine.

To mitigate this, `DeepZero` implements aggressive caching:
1. **SHA256 Deduplication:** Identical drivers found in different locations or under different filenames are deduplicated by their SHA256 hash. The pipeline will never analyze the same binary twice.
2. **Crash Resilience:** Triage results are cached locally. If the pipeline crashes or is interrupted, it will seamlessly resume from the exact candidate it was processing.
3. **Report Skipping:** If a `VULNERABLE_report.md` or `SAFE_report.md` already exists for a hash, the pipeline skips it entirely to save Vertex AI API costs.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  byovd-agent                     │
│                                                  │
│  Triage ──▶ Ghidra ──▶ Semgrep ──▶ Gemini 2.5   │
│  (.sys)     (headless)  (rules)    (Vertex AI)   │
│                                        │         │
│                                        ▼         │
│                                  VULNERABLE /    │
│                                  SAFE report     │
└──────────────────────────────────────────────────┘
```

## Disclaimer

This tool is for authorized security research and defensive purposes only. Do not use this to analyze or attack systems/software you do not own or have explicit permission to test.
