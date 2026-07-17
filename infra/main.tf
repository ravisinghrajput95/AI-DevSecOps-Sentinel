# =========================================================
# NEW infrastructure for AI DevSecOps Sentinel.
#
# Deliberately NOT managed here (pre-existing, shared with
# other repos in this project — changed via the documented
# gcloud commands in README.md instead):
#   - workload identity pool `github-pool` + provider `github`
#   - service account `github-actions-sa`
# =========================================================

resource "google_artifact_registry_repository" "sentinel" {
  location      = var.region
  repository_id = "sentinel"
  format        = "DOCKER"
  description   = "AI DevSecOps Sentinel container images (backend + frontend)"

  # SHA-tagged images accumulate on every push — keep the
  # 10 newest, delete the rest automatically.
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"
    condition {
      older_than = "2592000s" # 30 days
    }
  }
}

resource "google_container_cluster" "sentinel" {
  name     = "sentinel"
  location = var.region

  enable_autopilot = true

  release_channel {
    channel = "REGULAR"
  }

  # Prevents `terraform destroy` from silently taking the
  # cluster with it — flip to false first when you really
  # mean to tear it down.
  deletion_protection = true
}
