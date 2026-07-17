"""Adapters that convert native cloud evidence into analyzer contracts."""

from cloud_security_lab.normalizers.cloudtrail import (
    CloudTrailNormalizationResult,
    load_aws_cloudtrail_environment,
    normalize_aws_cloudtrail_environment,
)
from cloud_security_lab.normalizers.common import write_normalized_environment
from cloud_security_lab.normalizers.ec2 import (
    Ec2NormalizationResult,
    load_aws_ec2_environment,
    normalize_aws_ec2_environment,
)
from cloud_security_lab.normalizers.iam import (
    IamNormalizationResult,
    load_aws_iam_environment,
    normalize_aws_iam_environment,
)
from cloud_security_lab.normalizers.s3 import (
    S3NormalizationResult,
    load_aws_s3_environment,
    normalize_aws_s3_environment,
)

__all__ = [
    "CloudTrailNormalizationResult",
    "Ec2NormalizationResult",
    "IamNormalizationResult",
    "S3NormalizationResult",
    "load_aws_cloudtrail_environment",
    "load_aws_ec2_environment",
    "load_aws_iam_environment",
    "load_aws_s3_environment",
    "normalize_aws_cloudtrail_environment",
    "normalize_aws_ec2_environment",
    "normalize_aws_iam_environment",
    "normalize_aws_s3_environment",
    "write_normalized_environment",
]
