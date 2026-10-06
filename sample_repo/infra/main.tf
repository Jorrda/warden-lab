terraform {
  required_version = ">= 1.5"
}

provider "aws" {
  region     = var.region
  access_key = "AKIA7V7FCDKY2SJTSEXA"
  secret_key = var.aws_secret
}

resource "aws_s3_bucket" "documents" {
  bucket = "fleetline-portal-documents"
}
