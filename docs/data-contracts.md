# Data Contracts

The repository publishes versioned JSON Schema contracts for its simplified offline inputs, supported native exports, and shared findings output.

| Contract | Schema |
| --- | --- |
| AWS CloudTrail log file | [`aws-cloudtrail-records-v1.0.schema.json`](../schemas/aws-cloudtrail-records-v1.0.schema.json) |
| AWS IAM authorization details snapshot | [`aws-iam-authorization-details-v1.0.schema.json`](../schemas/aws-iam-authorization-details-v1.0.schema.json) |
| AWS EC2 security group snapshot | [`aws-ec2-describe-security-groups-v1.0.schema.json`](../schemas/aws-ec2-describe-security-groups-v1.0.schema.json) |
| AWS S3 security evidence bundle | [`aws-s3-evidence-bundle-v1.0.schema.json`](../schemas/aws-s3-evidence-bundle-v1.0.schema.json) |
| IAM environment | [`iam-environment-v1.0.schema.json`](../schemas/iam-environment-v1.0.schema.json) |
| Storage environment | [`storage-environment-v1.0.schema.json`](../schemas/storage-environment-v1.0.schema.json) |
| Network environment | [`network-environment-v1.0.schema.json`](../schemas/network-environment-v1.0.schema.json) |
| CloudTrail-style events | [`cloudtrail-events-v1.0.schema.json`](../schemas/cloudtrail-events-v1.0.schema.json) |
| Shared findings file | [`findings-v1.0.schema.json`](../schemas/findings-v1.0.schema.json) |

The schemas use JSON Schema Draft 2020-12. Contract tests validate every committed sample and an analyzer-generated findings file against these schemas.

The environment contracts describe the lab's simplified analyzer models. The native IAM contract describes the fields consumed from a non-truncated AWS `GetAccountAuthorizationDetails` snapshot; the accompanying credential report follows AWS's CSV contract and is validated by required headers and values in Python. The S3 bundle contract groups multiple native account and per-bucket responses without flattening collection errors into configuration values. The EC2 contract represents a complete direct `DescribeSecurityGroups` response; its adapter flattens permission targets while retaining CIDR, prefix-list, and security-group peer context in the network environment. The CloudTrail contract describes supported `Records` entries before multiple JSON or gzip files are merged and deduplicated. All normalizers convert native evidence into existing analyzer environments, keeping the detection contracts stable.

Runtime analyzers use only the Python standard library and perform lightweight top-level validation. Full JSON Schema validation is a development and CI gate supplied by the optional `dev` dependencies.

The shared findings loader also verifies that `finding_count` equals the number of objects in `findings`. That cross-field equality is enforced in Python because JSON Schema does not express it directly.
