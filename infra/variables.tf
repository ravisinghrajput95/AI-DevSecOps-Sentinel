variable "project_id" {
  description = "GCP project that hosts the Sentinel deployment"
  type        = string
  default     = "project-0c628a24-2e5e-4878-861"
}

variable "region" {
  description = "Region for the cluster and Artifact Registry"
  type        = string
  default     = "us-central1"
}
