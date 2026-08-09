#!/usr/bin/env sh
set -eu

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-southeast-2}"

awslocal s3api create-bucket \
  --bucket inventa-research-baseline \
  --create-bucket-configuration LocationConstraint="$AWS_DEFAULT_REGION" >/dev/null 2>&1 || true

awslocal s3api create-bucket \
  --bucket inventa-lab-evidence \
  --create-bucket-configuration LocationConstraint="$AWS_DEFAULT_REGION" >/dev/null 2>&1 || true

VPC_ID="$(awslocal ec2 create-vpc --cidr-block 10.60.0.0/16 --query 'Vpc.VpcId' --output text 2>/dev/null || true)"
if [ -n "$VPC_ID" ]; then
  awslocal ec2 create-tags --resources "$VPC_ID" --tags Key=Name,Value=inventa-localstack-vpc >/dev/null 2>&1 || true
  SG_ID="$(awslocal ec2 create-security-group --group-name inventa-localstack-sg --description 'Inventa simulated hybrid boundary' --vpc-id "$VPC_ID" --query 'GroupId' --output text 2>/dev/null || true)"
  if [ -n "$SG_ID" ]; then
    awslocal ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    awslocal ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
  fi
fi
