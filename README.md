# AI DevSecOps Sentinel

[![CI](https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel/actions/workflows/ci.yml)

AI DevSecOps Sentinel is an AI-powered DevOps and DevSecOps engineering assistant that performs contextual repository analysis, security reviews, infrastructure validation, and secure engineering guidance using AI-driven reasoning.

The platform combines:

* Repository-aware security analysis
* Infrastructure-as-Code inspection
* Secret and misconfiguration detection
* Attack surface reasoning
* Compliance mapping
* Contextual DevOps/DevSecOps knowledge assistance

---

# 🚀 Features

## Repository Security Analysis

* Full repository security reviews
* Severity-based findings dashboard
* Cross-file correlation and observations
* Expandable per-file analysis cards
* Repository-wide recommendations

---

## Secret Detection

Detects:

* Hardcoded passwords
* API tokens
* AWS access keys
* Private keys
* Sensitive credentials

Includes:

* Exact evidence snippets
* Line numbers
* Blast radius reasoning
* Secure remediation guidance

---

## Infrastructure-as-Code Analysis

Supports:

* Terraform
* Dockerfiles
* Kubernetes manifests
* Helm charts
* CI/CD workflows

Capabilities:

* Misconfiguration detection
* Open network exposure analysis
* IAM permission review
* Insecure defaults identification
* Security hardening recommendations

---

## Scanner-Grounded Findings

Uploaded files are scanned by deterministic security tools before the
AI ever reasons about them:

* **gitleaks** — hardcoded secret detection (values redacted)
* **checkov** — IaC misconfiguration checks across Terraform,
  Kubernetes, Dockerfiles, Helm, and CI/CD workflows
* **trivy** — vulnerable dependency detection (CVEs) in
  requirements.txt, package-lock.json, pom.xml, go.mod, and more
* **hadolint** — Dockerfile best-practice linting
* **semgrep** — SAST for application code (Python, JS/TS, Java, Go)
* **kubesec** — Kubernetes manifest risk scoring

The AI treats scanner output as verified ground truth: it correlates
findings across tools and files, deduplicates, prioritizes by
exploitability, and tags every finding `[SCANNER-VERIFIED]` or
`[AI-DETECTED]` so you always know which claims are tool-backed.
Verified findings are also returned as structured JSON and rendered
in a dedicated panel in the UI.

---

## Measured Detection — Benchmark

Detection quality is not claimed, it is measured: `evals/run_benchmark.py`
scores the scanner pipeline against deliberately vulnerable repositories
pinned to specific commits, checking that every documented planted
vulnerability class ("canary") is detected. No LLM involved — the run is
deterministic and free.

| Benchmark | Planted issues detected | Total findings | Scan time |
|---|---|---|---|
| terragoat (Terraform) | **8/8** | 730 | ~5s |
| cfngoat (CloudFormation) | **6/6** | 79 | ~4s |
| kubernetes-goat (Kubernetes) | **9/9** | 699 | ~8s |

Canary-level detail lives in [evals/RESULTS.md](evals/RESULTS.md); the
benchmark also runs weekly in CI and fails if any canary regresses.

---

## AI-Powered Security Reasoning

The platform provides:

* Attack chain analysis
* Exploitability reasoning
* Confidence scoring
* Blast radius analysis
* Context-aware remediation guidance

Example:

```text
Hardcoded Secret → Public Exposure → Credential Pivot
```

---

## Compliance Mapping

Maps findings to:

* CWE
* OWASP
* NIST
* CIS
* MITRE ATT&CK

---

## Knowledge Assistant

AI DevSecOps Sentinel also functions as a contextual engineering assistant.

Users can ask:

* What is GitOps?
* Explain ArgoCD
* Docker security best practices
* Terraform state management
* Kubernetes RBAC
* Zero trust networking

The assistant correlates explanations with uploaded repository context whenever applicable.

---

# 🛠 Supported Technologies

## DevOps

* Docker
* Kubernetes
* Helm
* Terraform
* GitHub Actions
* CI/CD pipelines
* ArgoCD
* GitOps

## Security

* DevSecOps
* Shift-left security
* Infrastructure security
* Supply chain security
* Secrets management
* Secure configuration analysis

---

# 📂 Supported File Types

* Dockerfile
* `.tf`
* `.yaml`
* `.yml`
* `.json`
* `.sh`
* `pom.xml`
* Helm charts
* Kubernetes manifests
* GitHub Actions workflows
* ZIP repositories
* Public GitHub repositories — paste a repo URL in chat (supports `/tree/<branch>`, 50 MB limit)

---

# 🧠 Core Capabilities

| Capability              | Description                              |
| ----------------------- | ---------------------------------------- |
| Repository Analysis     | Full contextual repository understanding |
| Security Findings       | AI-generated findings with evidence      |
| Attack Surface Analysis | Multi-step risk reasoning                |
| Compliance Mapping      | CWE / OWASP / NIST mapping               |
| Cross-file Correlation  | Connects findings across files           |
| Session Isolation       | Per-tab sessions — multi-user safe       |
| Knowledge Assistant     | DevOps and DevSecOps explanations        |
| AI Remediation          | Secure fix recommendations               |
| Severity Dashboard      | Critical / High / Medium / Low summaries |

---

# 🎯 Example Use Cases

* Secure Terraform reviews
* Dockerfile hardening analysis
* Kubernetes security validation
* Secret detection in repositories
* DevSecOps onboarding assistance
* Internal engineering security reviews
* Infrastructure risk analysis
* CI/CD security assessments

---

# 🖥 UI Highlights

* Interactive findings dashboard
* Expandable file analysis cards
* Severity counters
* Suggested follow-up actions
* AI-generated recommendations
* Context retention across uploaded files
* Security and knowledge workflows

---

# 📌 Project Vision

AI DevSecOps Sentinel aims to improve developer experience and security posture by combining:

* AI-assisted reasoning
* DevOps workflows
* DevSecOps practices
* Context-aware repository intelligence

into a single engineering assistant platform.

---

# 📷 Screenshots

![alt text](images/image.png)
![alt text](images/image-1.png)
![alt text](images/image-2.png)
![alt text](images/image-3.png)
![alt text](images/image-4.png)
![alt text](images/image-5.png)
![alt text](images/image-6.png)
---

# 📄 License

This project is currently a prototype/internal initiative and intended for learning, experimentation, and DevSecOps workflow innovation.

---

# 👨‍💻 Author

Ravi Rajput

DevOps | DevSecOps | AI-Assisted Engineering
