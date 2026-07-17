terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }

  # Bucket created once, outside Terraform (see README):
  #   gcloud storage buckets create gs://project-0c628a24-2e5e-4878-861-tfstate \
  #     --location=us-central1 --uniform-bucket-level-access
  backend "gcs" {
    bucket = "project-0c628a24-2e5e-4878-861-tfstate"
    prefix = "sentinel"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
