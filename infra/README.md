# Infrastructure

Terraform for the GCP resources that are **new and owned by this
repo**: the GKE Autopilot cluster and the Artifact Registry repo.

```bash
cd infra
terraform init
terraform plan -out=tf.plan
terraform apply tf.plan
```

Auth: `gcloud auth application-default login` once, or prefix
commands with `GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)`.

## One-time bootstrap (already done, kept for reference)

The state bucket can't be managed by the state it stores:

```bash
gcloud storage buckets create gs://project-0c628a24-2e5e-4878-861-tfstate \
  --location=us-central1 --uniform-bucket-level-access
gcloud storage buckets update gs://project-0c628a24-2e5e-4878-861-tfstate --versioning
```

## Shared OIDC infra (NOT managed here)

The workload identity pool `github-pool`, its `github` provider, and
`github-actions-sa` predate this repo and are shared with other
repositories in the project — importing them into this state would
let a `terraform destroy` here break those pipelines. They were
extended for this repo with:

```bash
# Add this repo to the provider's trust condition (condition is
# REPLACED, not appended — keep the other repos in the expression)
gcloud iam workload-identity-pools providers update-oidc github \
  --workload-identity-pool=github-pool --location=global \
  --attribute-condition='attribute.repository == "ravisinghrajput95/AI-Powered-DevSecOps-CI-CD-Pipeline" || attribute.repository == "ravisinghrajput95/platform-engineering-idp" || attribute.repository == "ravisinghrajput95/AI-DevSecOps-Sentinel"'

# Let workflows from this repo impersonate the CI service account
gcloud iam service-accounts add-iam-policy-binding \
  github-actions-sa@project-0c628a24-2e5e-4878-861.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/861082766890/locations/global/workloadIdentityPools/github-pool/attribute.repository/ravisinghrajput95/AI-DevSecOps-Sentinel"
```

`github-actions-sa` carries `roles/artifactregistry.writer` and
`roles/container.developer` — push images, deploy to GKE, nothing more.

## Teardown

The cluster has `deletion_protection = true`. To destroy: flip it to
`false`, apply, then `terraform destroy`.
