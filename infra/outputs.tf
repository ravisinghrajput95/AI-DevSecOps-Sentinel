output "cluster_name" {
  value = google_container_cluster.sentinel.name
}

output "cluster_location" {
  value = google_container_cluster.sentinel.location
}

output "artifact_registry" {
  description = "Prefix for image tags"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.sentinel.repository_id}"
}
