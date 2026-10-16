# dockerfile-sec-linter

> **High-performance Rust static analyzer for Dockerfiles designed to enforce cloud security postures and eliminate cloud infrastructure & registry storage waste.**

## Why dockerfile-sec-linter?
Container security and cloud compute bills are inextricably linked:
1. **Security Vulnerabilities:** Running as root, baking static API keys into ENV/ARG layers, or relying on mutable :latest tags expose infrastructure to privilege escalation.
2. **Cloud Cost Overhead:** Heavyweight base images combined with orphaned package manager caches and unchained RUN instructions unnecessarily inflate container images by hundreds of megabytes.

## Installation & Building
```bash
git clone https://github.com/bighnaraj2008-ai/dockerfile-sec-linter.git
cd dockerfile-sec-linter
cargo build --release
```
