"""Document storage on S3. Credentials come from the environment (see .env)."""
import os

import boto3

BUCKET = "fleetline-portal-documents"


def client():
    return boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "eu-central-1"))


def upload(path: str, key: str) -> None:
    client().upload_file(path, BUCKET, key)
