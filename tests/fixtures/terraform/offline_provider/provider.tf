terraform {
  required_version = "= 1.9.8"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.10.0"
    }
  }
}

# Test-only credentials and loopback endpoints. Never use this configuration for deployment.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "synthetic-test-only"
  secret_key                  = "synthetic-test-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true

  endpoints {
    ec2 = "http://127.0.0.1:9"
    sts = "http://127.0.0.1:9"
  }
}
