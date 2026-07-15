"""Adapters that convert native cloud evidence into analyzer contracts."""

from cloud_security_lab.normalizers.iam import (
    IamNormalizationResult,
    load_aws_iam_environment,
    normalize_aws_iam_environment,
    write_normalized_environment,
)

__all__ = [
    "IamNormalizationResult",
    "load_aws_iam_environment",
    "normalize_aws_iam_environment",
    "write_normalized_environment",
]
