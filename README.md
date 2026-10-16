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
## Rule Catalog
| Rule ID | Category | Severity | Name |
|---|---|---|---|
| `SEC001` | Security | High | Container running as root user |
| `SEC002` | Security | High | Unpinned base image tag |
| `SEC003` | Security | Critical | Hardcoded secret or credential |
| `SEC004` | Security | Medium | Insecure or ambiguous ADD |
| `SEC005` | Security | Medium | Usage of sudo inside RUN |
| `COST001` | Cost | Medium | Bloated base image in runtime stage |
| `COST002` | Cost | Medium | Package manager cache not cleaned |
| `COST003` | Cost | Low | Consecutive RUN instructions not chained |

## CLI Usage
```bash
dockerfile-sec-linter Dockerfile
dockerfile-sec-linter Dockerfile --fail-on high
dockerfile-sec-linter Dockerfile --min-score 80
```
