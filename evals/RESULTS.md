# Detection Benchmark Results

Generated 2026-07-16 by `evals/run_benchmark.py` — deterministic scanner pipeline only (no LLM), repositories pinned to commits.

| Benchmark | Canaries detected | Findings | Scan time |
|---|---|---|---|
| [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat/tree/729f8da) | **8/8** | 730 (checkov 365, trivy 327, semgrep 34, gitleaks 4) | 5s |
| [bridgecrewio/cfngoat](https://github.com/bridgecrewio/cfngoat/tree/0c09b69) | **6/6** | 79 (checkov 70, semgrep 7, gitleaks 2) | 4s |
| [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat/tree/723a0db) | **9/9** | 699 (checkov 337, kubesec 132, trivy 91, semgrep 75, hadolint 53, gitleaks 11) | 8s |

## bridgecrewio/terragoat — Vulnerable-by-design Terraform (AWS/Azure/GCP)

| Canary (documented planted issue) | Hits | Status |
|---|---|---|
| `hardcoded-cloud-credentials` | 4 | ✅ detected |
| `secrets-in-iac` | 5 | ✅ detected |
| `ssh-open-to-world` | 1 | ✅ detected |
| `unencrypted-ebs-volume` | 1 | ✅ detected |
| `hardcoded-provider-credentials` | 1 | ✅ detected |
| `unencrypted-launch-config-storage` | 2 | ✅ detected |
| `critical-dependency-cve` | 25 | ✅ detected |
| `ci-mutable-action-tags` | 7 | ✅ detected |

## bridgecrewio/cfngoat — Vulnerable-by-design CloudFormation

| Canary (documented planted issue) | Hits | Status |
|---|---|---|
| `hardcoded-aws-access-key` | 1 | ✅ detected |
| `sast-detects-aws-key` | 1 | ✅ detected |
| `ssh-open-to-world` | 1 | ✅ detected |
| `s3-missing-public-access-block` | 6 | ✅ detected |
| `iam-policy-issues` | 3 | ✅ detected |
| `secrets-in-template` | 3 | ✅ detected |

## madhuakula/kubernetes-goat — Vulnerable-by-design Kubernetes environment

| Canary (documented planted issue) | Hits | Status |
|---|---|---|
| `privileged-container-kubesec` | 4 | ✅ detected |
| `privileged-container-checkov` | 4 | ✅ detected |
| `privilege-escalation-allowed` | 16 | ✅ detected |
| `containers-run-as-root` | 16 | ✅ detected |
| `dockerfile-missing-user` | 13 | ✅ detected |
| `missing-resource-limits` | 9 | ✅ detected |
| `hardcoded-secrets` | 11 | ✅ detected |
| `dockerfile-best-practices` | 53 | ✅ detected |
| `vulnerable-dependencies` | 91 | ✅ detected |
