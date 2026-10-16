# dockerfile-sec-linter

[![CI](https://github.com/developer/dockerfile-sec-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/developer/dockerfile-sec-linter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 2021](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/Version-0.1.0-emerald.svg)](Cargo.toml)

> **High-performance Rust static analyzer for Dockerfiles designed to enforce cloud security postures and eliminate cloud infrastructure & registry storage waste.**

---

## Table of Contents
- [Why dockerfile-sec-linter?](#why-dockerfile-sec-linter)
- [Architecture & Design](#architecture--design)
- [Rule Catalog](#rule-catalog)
  - [Cloud Security Rules (`SEC001` - `SEC005`)](#cloud-security-rules)
  - [Cloud Cost & Size Optimization Rules (`COST001` - `COST003`)](#cloud-cost--size-optimization-rules)
- [Installation & Building](#installation--building)
- [CLI Usage](#cli-usage)
  - [Basic Analysis](#basic-analysis)
  - [JSON Output for CI/CD Pipelines](#json-output-for-cicd-pipelines)
  - [Threshold Enforcement (`--fail-on` and `--min-score`)](#threshold-enforcement)
  - [Listing Available Rules](#listing-available-rules)
  - [Initializing Configuration](#initializing-configuration)
- [Configuration Reference (`.dockerlint.toml`)](#configuration-reference)
- [Scoring Model](#scoring-model)
- [Sample Outputs](#sample-outputs)
- [GitHub Actions Integration](#github-actions-integration)
- [License](#license)

---

## Why dockerfile-sec-linter?

Container security and cloud compute bills are inextricably linked:
1. **Security Vulnerabilities:** Running as `root`, baking static API keys into `ENV`/`ARG` layers, or relying on mutable `:latest` tags expose infrastructure to privilege escalation, supply-chain tampering, and credential leakage.
2. **Cloud Cost Overhead:** Heavyweight base images (e.g. standard Ubuntu/Python/Node) combined with orphaned package manager caches (`/var/lib/apt/lists/*`) and unchained `RUN` instructions unnecessarily inflate container images by hundreds of megabytes. In Kubernetes clusters, this results in:
   - Higher egress and ingress bandwidth fees.
   - Slower pod auto-scaling cold starts.
   - Massive container registry (ECR, GCR, ACR) storage bills.

`dockerfile-sec-linter` inspects Dockerfiles line-by-line using a native AST parser written in Rust, scores your Dockerfiles on a 0-100 health index, and outputs actionable terminal diagnostics or machine-readable JSON.

---

## Architecture & Design

```
                     ┌──────────────────────────┐
                     │     Target Dockerfile    │
                     └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │   DockerfileParser (AST) │
                     │  - Multi-line \ joins    │
                     │  - Stage & Alias tracking│
                     │  - Comments & Directives │
                     └─────────────┬────────────┘
                                   │
                     ┌─────────────▼────────────┐
                     │      LinterEngine        │
                     │  - Rule Dispatcher       │
                     │  - Config Overrides      │
                     └──────┬────────────┬──────┘
                            │            │
            ┌───────────────┘            └───────────────┐
            ▼                                            ▼
┌───────────────────────────────┐        ┌───────────────────────────────┐
│     Cloud Security Rules      │        │    Cost & Optimization Rules  │
│  - SEC001: Non-root USER      │        │  - COST001: Bloated Images    │
│  - SEC002: Pinned Image Tags  │        │  - COST002: Package Caches    │
│  - SEC003: Hardcoded Secrets  │        │  - COST003: Chained Layers    │
│  - SEC004: Insecure ADD       │        └───────────────┬───────────────┘
│  - SEC005: Sudo Invocations   │                        │
└───────────────┬───────────────┘                        │
                │                                        │
                └───────────────┬────────────────────────┘
                                │
                                ▼
                     ┌──────────────────────────┐
                     │     Scoring Engine       │
                     │  - Security Score (60%)  │
                     │  - Cost Score (40%)      │
                     │  - Composite & Grade     │
                     └─────────────┬────────────┘
                                   │
                     ┌─────────────▼────────────┐
                     │        Reporters         │
                     │  - ANSI Color Terminal   │
                     │  - Structured JSON       │
                     └──────────────────────────┘
```

---

## Rule Catalog

| Rule ID | Category | Severity | Name | Description |
|---|---|---|---|---|
| `SEC001` | Security | **High** | Container running as root user | Flags missing `USER` instruction or final `USER` set to `root`/`0` in the runtime stage. |
| `SEC002` | Security | **High** | Unpinned base image tag | Flags `:latest` or omitting an explicit version tag or SHA256 digest in `FROM`. |
| `SEC003` | Security | **Critical** | Hardcoded secret or credential | Detects sensitive keys (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, `AWS_`) or tokens in `ENV`/`ARG`. |
| `SEC004` | Security | **Medium** | Insecure or ambiguous `ADD` | Flags using `ADD` instead of `COPY` for local files or unverified remote URLs. |
| `SEC005` | Security | **Medium** | Usage of `sudo` inside `RUN` | Flags `sudo` invocations inside container build layers. |
| `COST001` | Cost | **Medium** | Bloated base image in runtime stage | Flags full-OS images (`ubuntu`, `debian`, `node`, `python`, `golang`) not using `-slim` or `-alpine`. |
| `COST002` | Cost | **Medium** | Package manager cache not cleaned | Flags package installers (`apt-get`, `apk`, `pip`, `yum`) omitting cleanup flags or cache removal. |
| `COST003` | Cost | **Low** | Consecutive `RUN` instructions | Flags sequential `RUN` instructions that should be combined with `&& \` to reduce layers. |

### Cloud Security Rules

#### `SEC001`: Container running as root user (High)
* **Risk:** By default, Docker containers execute processes as UID 0 (`root`). In the event of a container breakout or application vulnerability (e.g. RCE), the attacker inherits root capabilities.
* **Remediation:** Create an unprivileged user and group in your Dockerfile and switch to it using `USER` before the `ENTRYPOINT` or `CMD`:
  ```dockerfile
  RUN addgroup -g 10001 -S appgroup && adduser -u 10001 -S -G appgroup appuser
  USER 10001:10001
  ```

#### `SEC002`: Unpinned base image tag (High)
* **Risk:** Omitting image tags or using `:latest` results in non-reproducible builds. Upstream changes or malicious image takeovers can break production or inject vulnerabilities without code modifications.
* **Remediation:** Pin your base image to an explicit version tag or immutable SHA256 digest:
  ```dockerfile
  # Bad
  FROM python:latest

  # Good
  FROM python:3.11.8-slim@sha256:7539c80521e8b2b62bb63fcb0d1822709cb4abef29281a62ac6ee6fc74304ffb
  ```

#### `SEC003`: Hardcoded secret or credential (Critical)
* **Risk:** Values defined in `ENV` or `ARG` are baked into the image manifest and visible to anyone with access to the container image registry via `docker history` or `docker inspect`.
* **Remediation:** Never store secrets in Dockerfiles. Use Docker BuildKit secret mounts during build time:
  ```dockerfile
  RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret
  ```

#### `SEC004`: Insecure or ambiguous `ADD` instruction (Medium)
* **Risk:** `ADD` has implicit auto-extraction behaviors and allows downloading unverified remote HTTP URLs without checksum validation (susceptible to man-in-the-middle attacks).
* **Remediation:** Use `COPY` for regular files and directories. Only use `ADD` when intentionally extracting local tarballs (`.tar.gz`). For remote assets, use `curl`/`wget` and verify SHA256 hashes in a `RUN` step.

#### `SEC005`: Usage of `sudo` inside `RUN` (Medium)
* **Risk:** Containers should not contain or invoke `sudo`. It expands the container attack surface and indicates improperly configured build user permissions.
* **Remediation:** Run initial setup commands as root during build, then drop privileges with `USER`.

---

### Cloud Cost & Size Optimization Rules

#### `COST001`: Bloated base image in runtime stage (Medium)
* **Impact:** Standard full-OS base images (`ubuntu:22.04`, `python:3.11`, `node:20`) are between 500 MB and 1.2 GB. Minimal alternatives (`-slim`, `-alpine`, or `distroless`) reduce image size to 20 MB - 150 MB, slashing storage costs and download latency.
* **Remediation:** Use multi-stage builds where heavyweight toolchains remain in the builder stage, and copy only the compiled binary or runtime assets to a minimal base image:
  ```dockerfile
  FROM golang:1.22-alpine AS builder
  # ... build app ...

  FROM alpine:3.19 AS runtime
  COPY --from=builder /app /app
  ```

#### `COST002`: Package manager cache not cleaned (Medium)
* **Impact:** Running `apt-get install`, `apk add`, or `pip install` without clearing caches permanently burns downloaded archives and package indices into that image layer.
* **Remediation:** Always clear caches in the same `RUN` command:
  ```dockerfile
  # Debian/Ubuntu
  RUN apt-get update && apt-get install -y --no-install-recommends curl \
      && rm -rf /var/lib/apt/lists/*

  # Alpine
  RUN apk add --no-cache git ca-certificates

  # Python
  RUN pip install --no-cache-dir -r requirements.txt
  ```

#### `COST003`: Consecutive `RUN` instructions not chained (Low)
* **Impact:** Every `RUN` instruction creates a separate read-only filesystem layer with storage metadata overhead.
* **Remediation:** Chain consecutive commands using `&& \`:
  ```dockerfile
  RUN apt-get update && \
      apt-get install -y --no-install-recommends curl && \
      rm -rf /var/lib/apt/lists/*
  ```

---

## Installation & Building

### Prerequisites
- Rust 1.75+ and Cargo ([https://rustup.rs](https://rustup.rs))

### Build from Source
```bash
git clone https://github.com/developer/dockerfile-sec-linter.git
cd dockerfile-sec-linter
cargo build --release
```

The compiled binary will be located at:
- **Linux/macOS:** `target/release/dockerfile-sec-linter`
- **Windows:** `target\release\dockerfile-sec-linter.exe`

---

## CLI Usage

### Basic Analysis
Analyze a Dockerfile in your current directory:
```bash
dockerfile-sec-linter Dockerfile
```

Analyze a specific Dockerfile path:
```bash
dockerfile-sec-linter ./deploy/Dockerfile.production
```

### JSON Output for CI/CD Pipelines
Generate structured JSON output for automated ingestion:
```bash
dockerfile-sec-linter Dockerfile --format json
```

### Threshold Enforcement
Enforce policies that fail the build (exit code `1`) if any finding meets or exceeds a severity threshold:
```bash
# Fail if any HIGH or CRITICAL issues are found
dockerfile-sec-linter Dockerfile --fail-on high

# Fail if composite health score drops below 80
dockerfile-sec-linter Dockerfile --min-score 80

# Ignore specific rules
dockerfile-sec-linter Dockerfile --ignore COST003,SEC004
```

### Listing Available Rules
```bash
dockerfile-sec-linter rules
```

### Initializing Configuration
Generate a `.dockerlint.toml` configuration template:
```bash
dockerfile-sec-linter init
```

---

## Configuration Reference

You can customize linter behavior via `.dockerlint.toml` placed in your repository root or passed via `--config <path>`:

```toml
# List of rule IDs to ignore during analysis
ignore_rules = [
    # "COST003",
]

# Minimum severity threshold to report: "low", "medium", "high", "critical"
min_severity = "low"

# Minimum score threshold (0-100). Fails with non-zero exit code if score is lower
min_score = 75

# Fail-on severity threshold: "low", "medium", "high", "critical"
fail_on = "high"

# Allow root in intermediate builder stages (only enforces SEC001 on runtime stage)
allow_root_in_build_stages = true

# Whitelisted internal base images exempted from bloated image checks
allowed_base_images = [
    # "internal-registry.company.com/golden-base:*",
]
```

---

## Scoring Model

The Composite Health Score (0 - 100) reflects the security posture and cost efficiency of your Dockerfile:

$$\text{Composite Score} = (0.60 \times \text{Security Score}) + (0.40 \times \text{Cost Score})$$

Deductions per finding:
- **Critical (`SEC003`):** -25 points
- **High (`SEC001`, `SEC002`):** -15 points
- **Medium (`SEC004`, `SEC005`, `COST001`, `COST002`):** -8 points
- **Low (`COST003`):** -3 points

### Letter Grades
- `95 - 100`: **A+** (Production-Grade Hardened)
- `90 - 94` : **A**  (Excellent)
- `80 - 89` : **B**  (Good)
- `70 - 79` : **C**  (Acceptable, Remediation Recommended)
- `60 - 69` : **D**  (Poor, High Cloud Waste / Security Risk)
- `0 - 59`  : **F**  (Critical Policy Violations)

---

## Sample Outputs

### Terminal Report (`--format text`)
```text
╔══════════════════════════════════════════════════════════════════════════════╗
║  DOCKERFILE CLOUD SECURITY & COST OPTIMIZER                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
  Target File   : tests/fixtures/Dockerfile.vulnerable
  Build Stages  : 1
  Instructions  : 11

─── FINDINGS (12) ────────────────────────────────────────────────

  1. [CRITICAL] SEC003: Hardcoded secret or credential  [SECURITY] (line 9)
     • Issue: Potentially hardcoded secret detected in ARG 'AWS_ACCESS_KEY_ID'
       │ ARG AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
     ↳ Fix  : Use BuildKit secrets mount (`RUN --mount=type=secret`) or inject environment variables at container runtime.

  2. [HIGH] SEC001: Container running as root user  [SECURITY] (line 6)
     • Issue: Build stage <runtime> (base image 'ubuntu') does not specify a non-root USER instruction
       │ FROM ubuntu:latest
     ↳ Fix  : Define and switch to a non-root USER (e.g., `USER appuser` or `USER 10001:10001`) in the final build stage.

  3. [MEDIUM] COST001: Bloated base image in runtime stage  [COST-EFFICIENCY] (line 6)
     • Issue: Runtime stage uses heavyweight base image 'ubuntu:latest' instead of a lightweight variant
       │ FROM ubuntu:latest
     ↳ Fix  : Switch the final runtime base image to a lean variant such as '-slim', '-alpine', or GoogleContainerTools 'distroless'.

─── METRICS & SCORECARD ────────────────────────────────────────────────────

  Composite Health Score : 28 / 100  [Grade: F]
  ├── Cloud Security     : 0 / 100
  └── Cost & Size        : 70 / 100

  Findings Breakdown: 3 Critical | 2 High | 5 Medium | 2 Low

  ✖ POLICY FAILURE: Found violations with severity CRITICAL which meets or exceeds '--fail-on HIGH'
```

### JSON Report (`--format json`)
```json
{
  "file_path": "tests/fixtures/Dockerfile.optimized",
  "findings": [],
  "score": {
    "security_score": 100,
    "cost_score": 100,
    "total_score": 100,
    "grade": "A+",
    "total_findings": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0
  },
  "has_failure": false,
  "failure_reason": null,
  "stages_count": 2,
  "instructions_count": 14
}
```

---

## GitHub Actions Integration

Add `dockerfile-sec-linter` to your continuous integration workflow to block insecure or bloated images before merge:

```yaml
name: Dockerfile Security & Cost Audit

on:
  pull_request:
    paths:
      - '**/Dockerfile*'

jobs:
  dockerfile-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build Linter
        run: cargo build --release

      - name: Audit Dockerfile
        run: |
          ./target/release/dockerfile-sec-linter Dockerfile \
            --fail-on high \
            --min-score 80
```

---

## License

This project is licensed under the [MIT License](LICENSE).
