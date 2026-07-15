# Data Contracts

The repository publishes versioned JSON Schema contracts for its simplified offline inputs and shared findings output.

| Contract | Schema |
| --- | --- |
| IAM environment | [`iam-environment-v1.0.schema.json`](../schemas/iam-environment-v1.0.schema.json) |
| Storage environment | [`storage-environment-v1.0.schema.json`](../schemas/storage-environment-v1.0.schema.json) |
| Network environment | [`network-environment-v1.0.schema.json`](../schemas/network-environment-v1.0.schema.json) |
| CloudTrail-style events | [`cloudtrail-events-v1.0.schema.json`](../schemas/cloudtrail-events-v1.0.schema.json) |
| Shared findings file | [`findings-v1.0.schema.json`](../schemas/findings-v1.0.schema.json) |

The schemas use JSON Schema Draft 2020-12. Contract tests validate every committed sample and an analyzer-generated findings file against these schemas.

The input contracts intentionally describe the lab's simplified models. They are not claims of direct compatibility with unmodified AWS API responses. Native AWS normalization is a separate roadmap milestone.

Runtime analyzers use only the Python standard library and perform lightweight top-level validation. Full JSON Schema validation is a development and CI gate supplied by the optional `dev` dependencies.

The shared findings loader also verifies that `finding_count` equals the number of objects in `findings`. That cross-field equality is enforced in Python because JSON Schema does not express it directly.
