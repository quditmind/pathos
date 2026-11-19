scoutsuite_results =
{
  "account_id": "123456789012",
  "environment": "default",
  "last_run": {
    "ruleset_name": "default",
    "run_parameters": {},
    "summary": {},
    "time": "2025-11-19 10:00:00+00:00",
    "version": "5.14.0"
  },
  "metadata": {},
  "partition": "aws",
  "provider_code": "aws",
  "provider_name": "Amazon Web Services",
  "result_format": "json",
  "service_list": [
    "ec2",
    "iam",
    "s3"
  ],
  "services": {
    "ec2": {
      "findings": {
        "ec2-security-group-opens-SSH-port-to-all": {
          "checked_items": 12,
          "compliance": [
            {
              "name": "CIS Amazon Web Services Foundations",
              "reference": "4.1",
              "version": "1.2.0"
            }
          ],
          "dashboard_name": "Rules",
          "description": "Security Group Opens SSH Port to All",
          "flagged_items": 2,
          "id_suffix": "TCP-22",
          "items": [
            "ec2.regions.eu-west-1.vpcs.vpc-0a1b2c3d.security_groups.sg-0123456789abcdef0.rules.ingress.protocols.TCP.ports.22.cidrs.0.CIDR",
            "ec2.regions.us-east-1.vpcs.vpc-0f9e8d7c.security_groups.sg-0fedcba9876543210.rules.ingress.protocols.TCP.ports.22.cidrs.0.CIDR"
          ],
          "level": "danger",
          "path": "ec2.regions.id.vpcs.id.security_groups.id.rules.id.protocols.id.ports.id.cidrs.id.CIDR",
          "rationale": "SSH open to 0.0.0.0/0 exposes the hosts to brute force attacks.",
          "references": [
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"
          ],
          "remediation": "Restrict the source to known networks.",
          "service": "EC2"
        }
      }
    },
    "iam": {
      "findings": {
        "iam-root-account-no-mfa": {
          "checked_items": 1,
          "compliance": null,
          "dashboard_name": "Accounts",
          "description": "Root Account without MFA",
          "flagged_items": 0,
          "items": [],
          "level": "danger",
          "path": "iam.credential_reports.id",
          "rationale": "",
          "references": [],
          "remediation": null,
          "service": "IAM"
        }
      }
    },
    "s3": {
      "findings": {
        "s3-bucket-no-logging": {
          "checked_items": 3,
          "compliance": null,
          "dashboard_name": "Buckets",
          "description": "Bucket Access Logging Disabled",
          "flagged_items": 1,
          "id_suffix": "logging",
          "items": [
            "s3.buckets.example-logs-bucket.logging"
          ],
          "level": "warning",
          "path": "s3.buckets.id",
          "rationale": "Access logs record requests made to the bucket.",
          "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
          ],
          "remediation": null,
          "service": "S3"
        }
      }
    }
  }
}
