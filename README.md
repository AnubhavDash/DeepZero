<div align="center">
  <h1>DeepZero</h1>
  <p><b>Agentic Vulnerability Research & Binary Analysis at Scale</b></p>

  <p>
    <a href="https://github.com/416rehman/DeepZero/actions"><img src="https://img.shields.io/github/actions/workflow/status/416rehman/DeepZero/ci.yml?branch=main" alt="Build Status"></a>
    <a href="https://pypi.org/project/deepzero/"><img src="https://img.shields.io/pypi/v/deepzero" alt="PyPI - Version"></a>
    <a href="https://pypi.org/project/deepzero/"><img src="https://img.shields.io/pypi/pyversions/deepzero" alt="PyPI - Python Version"></a>
    <a href="https://github.com/416rehman/DeepZero/blob/main/LICENSE"><img src="https://img.shields.io/github/license/416rehman/DeepZero" alt="License"></a>
  </p>
</div>

---

**DeepZero** is a highly parallelized, breadth-first pipeline orchestrator engineered to automate massive-scale binary analysis and vulnerability research. 

By flawlessly coordinating tools like Headless Ghidra, Semgrep, and modern Foundation Models (via `litellm`), DeepZero empowers engineers to construct complex, declarative processing workflows capable of traversing thousands of payloads simultaneously.

Unlike traditional ad-hoc scripting, DeepZero utilizes a robust **State Ledger Architecture**. State is intrinsically decoupled and written deterministically to the local filesystem. This implies complete idempotency: if a pipeline parsing 50,000 Windows kernel drivers is terminated halfway, DeepZero resumes instantly without re-processing overhead, gracefully capturing execution footprints into unified data schemas.

---

## ⚡ Execution Architecture 

DeepZero structurally enforces processing boundaries into distinct polymorphic primitives, ensuring horizontal execution across large-scale datasets while preventing process deadlocks.

* **Ingest** (`1:N`): Crawl specific filesystems, extract structured metadata, and parse binaries natively (e.g., `pe_ingest`).
* **Map** (`1:1`): Apply deep processing onto isolated sample nodes parallelized across system workers (e.g., `ghidra_decompile`, `generic_llm`).
* **Bulk Scan** (`N:Batch`): Route entire decompiled datasets directly through high-throughput asynchronous external binaries (e.g., `semgrep_scanner`).
* **Reduce Barriers** (`N:1`): Erect synchronous execution walls to truncate, rank, or aggressively filter the active sample volume (e.g., `top_k`, `sort`).

---

## 📦 Installation & Setup

DeepZero requires **Python 3.11+**.

```bash
# Clone the repository natively
git clone https://github.com/416rehman/DeepZero.git
cd DeepZero

# Install the engine coupled with structural parsing limits and Litellm context routing
pip install -e .[pe,llm]
```

### 🎯 Environmental Dependencies

DeepZero acts strictly as the central execution engine. Any custom stages configured within the pipeline require their respective toolchains natively available in your environment.

If orchestrating the out-of-the-box Windows driver pipeline (`loldrivers`), you need:
* **Headless Ghidra**: Establish the `GHIDRA_INSTALL_DIR` environment string pointing toward an unzipped v11+ release.
* **Semgrep Core**: Required directly inside your local `$PATH` configuration.
* **LiteLLM Routes**: Configure API credentials relevant to your `pipeline.yaml` routing specifications (e.g. `$GEMINI_API_KEY`, `$OPENAI_API_KEY`, or GCP Application Defaults).

---

## 🚀 Running Your First Pipeline

DeepZero enforces declarative data logic formatted exclusively in YAML. To evaluate the included `loldrivers` pipeline against a collection of `.sys` files:

```bash
# Supply pipeline path (-p) and override the foundational LLM backend (-m)
deepzero run ./drivers_folder \
  -p pipelines/loldrivers/pipeline.yaml \
  -m gemini/gemini-2.5-pro
```

Because DeepZero structures contextual outputs exclusively around the filesystem ledger, you can seamlessly branch your interactive flows into internal `REPL` interrogations to examine the exact output states mid-run:

```bash
deepzero status -w ./work/
```

---

## 🛠 Anatomy of a Pipeline Context (YAML)

All executions funnel synchronously down your `stages` block sequentially. Below is an example depicting an abstract, horizontally-scaled execution framework.

```yaml
name: generic_vulnerability_discovery
description: "Parallelized static triage with LLM fallback routing"
version: "1.0"

settings:
  work_dir: work
  max_workers: 8 # Cap deep parallelism automatically

stages:
  # 1. Instantiate state objects utilizing dynamic discovery modules
  - name: discover
    processor: pe_ingest/pe_ingest.py
    config:
      extensions: [".exe", ".sys"]

  # 2. Decompile mapped samples securely (parallel execution)
  - name: decompile
    processor: ghidra_decompile/ghidra_decompile.py
    timeout: 300
    config:
      ghidra_install_dir: ${GHIDRA_INSTALL_DIR}

  # 3. Synchronous ranking logic blocking the execution chain
  - name: rank
    processor: sort
    config:
      by: decompile.function_count
      order: desc

  # 4. LLM triage analysis
  - name: evaluate
    processor: generic_llm
    on_failure: skip  # Drop API failures securely without throwing orchestrator faults
    config:
      prompt: pipelines/prompts/evaluate.j2
```

---

## 🔧 Building Custom Processors (Developer Guide)

DeepZero treats plugins as self-contained state nodes designed to sequentially mutate or interpret samples. Integrating legacy tools or custom scripts is designed to mirror our built-in processing sequence entirely. 

### Execution Lifecycle

Processors expose strict sequence hooks executed synchronously by the Engine wrapper:

1. `validate(self, ctx: ProcessorContext) -> list[str]`
    * **Pre-flight Offline Checker**: Instantly triggered when a pipeline is validated to ensure configuration limits or external credential assertions are logically present before the orchestrator binds to memory.
2. `setup(self, ctx: ProcessorContext) -> None`
    * **Initialization Barrier**: Run immediately prior to the mapped execution queue. Used strictly for massive structural reservations (spawning socket nodes or API web-links).
3. `process(self, ctx: ProcessorContext, entry: ProcessorEntry) -> ProcessorResult`
    * **Map Payload**: Scaled synchronously or concurrently based strictly on your assigned Node limits (`1:1` mapped returns vs `N:1` reduced arrays).
4. `teardown(self) -> None`
    * **Reclamation Hook**: Cleans hanging threads upon queue finalization.

### Processor Integrations (Local & Upstream)

**Writing Project-Specific Stages**: 
You can implement proprietary logic privately inside your own isolated directories. DeepZero parses generic path nodes seamlessly, isolating your local codebase from structural interference:
```yaml
  - name: custom_firewall_bypass
    processor: ./my_local_modules/bypass_logic.py:BypassImplementation
```

**Contributing Upstream**:
To deploy generalized architectural node handlers (like IDA Pro de-compilation binaries or generic Docker execution routes) natively into DeepZero:
1. Write the processor targeting `src/deepzero/stages/` (for fundamental Python primitives like sorts or filter loops).
2. Or construct a modular standalone folder inside the root `processors/` hierarchy for heavy plugins (like `ghidra_decompile`).
3. Assert that tests successfully target `.validate()` layer configurations, run the `pytest` matrix, and generate an upstream Pull Request!

---

## 🤝 Contributing & License

DeepZero thrives through collaborative engineering. Whether you're debugging State Ledger optimizations, submitting new Foundation Model routing logic, or expanding the processor schemas, we actively welcome Pull Requests! 

For formatting compliance upstream, ensure:
```bash
ruff check . && ruff format --check . && bandit -r src processors
```

DeepZero is released under the [MIT License](LICENSE).
