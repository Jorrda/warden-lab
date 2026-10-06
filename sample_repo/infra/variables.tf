variable "region" {
  default = "eu-central-1"
}

variable "aws_secret" {
  sensitive = true
}

variable "example_access_key" {
  description = "Shape of an access key id, for documentation only"
  default     = "AKIAEXAMPLEKEY000000"
}
