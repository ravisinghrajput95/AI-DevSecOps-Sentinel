# Deliberately vulnerable Terraform fixture for scanner tests.
# The AWS credentials below are FAKE (random characters in valid
# key format) — they do not belong to any real account.

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAQWERTYU1OPASDF2G"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"
  acl    = "public-read"
}
