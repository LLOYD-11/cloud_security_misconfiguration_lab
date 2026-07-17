import base64
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from urllib.parse import quote

from cloud_security_lab.normalizers.iam import (
    load_aws_iam_environment,
    normalize_aws_iam_environment,
    write_normalized_environment,
)
from iam_analyzer.analyzer import analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH = (
    PROJECT_ROOT / "sample_data/aws/iam/account_authorization_details.json"
)
CREDENTIAL_PATH = PROJECT_ROOT / "sample_data/aws/iam/credential_report.csv"
AS_OF = date(2026, 6, 30)


def _authorization_details():
    return json.loads(AUTHORIZATION_PATH.read_text(encoding="utf-8"))


def _credential_row(
    username,
    arn,
    *,
    password="TRUE",
    password_last_used="2026-06-28T00:00:00+00:00",
    password_last_changed="2026-02-01T00:00:00+00:00",
    mfa="TRUE",
    active="FALSE",
    rotated="N/A",
    key_last_used="N/A",
):
    return {
        "user": username,
        "arn": arn,
        "password_enabled": password,
        "password_last_used": password_last_used,
        "password_last_changed": password_last_changed,
        "mfa_active": mfa,
        "access_key_1_active": active,
        "access_key_1_last_rotated": rotated,
        "access_key_1_last_used_date": key_last_used,
        "access_key_2_active": "FALSE",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }


def _sample_credential_rows():
    return {
        "alice-admin": _credential_row(
            "alice-admin",
            "arn:aws:iam::111122223333:user/alice-admin",
            password_last_used="2026-06-25T00:00:00+00:00",
            password_last_changed="2026-01-05T00:00:00+00:00",
            mfa="FALSE",
            active="TRUE",
            rotated="2026-02-08T00:00:00+00:00",
            key_last_used="2026-06-26T00:00:00+00:00",
        ),
        "data-engineer": _credential_row(
            "data-engineer",
            "arn:aws:iam::111122223333:user/engineering/data-engineer",
            password="FALSE",
            password_last_used="N/A",
            password_last_changed="N/A",
            active="TRUE",
            rotated="2026-06-18T00:00:00+00:00",
            key_last_used="2026-06-29T00:00:00+00:00",
        ),
        "readonly-analyst": _credential_row(
            "readonly-analyst",
            "arn:aws:iam::111122223333:user/analytics/readonly-analyst",
        ),
    }


class NativeIamNormalizerTests(unittest.TestCase):
    def test_native_sample_preserves_expected_iam_analysis(self):
        result = load_aws_iam_environment(
            AUTHORIZATION_PATH,
            CREDENTIAL_PATH,
            as_of=AS_OF,
        )
        simplified = load_environment(
            PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"
        )

        native_findings = analyze_environment(result.environment)
        simplified_findings = analyze_environment(simplified)
        native_signatures = [
            (item.rule_id, item.severity, item.resource_type, item.resource_id)
            for item in native_findings
        ]
        simplified_signatures = [
            (item.rule_id, item.severity, item.resource_type, item.resource_id)
            for item in simplified_findings
        ]

        self.assertEqual((), result.warnings)
        self.assertEqual((), result.skipped_evidence)
        self.assertEqual("111122223333", result.environment["account_id"])
        self.assertEqual(simplified_signatures, native_signatures)
        self.assertTrue(result.environment["root_account"]["mfa_enabled"])
        self.assertEqual(142, result.environment["users"][0]["access_keys"][0]["age_days"])
        self.assertEqual(
            "ReadOnlyReports",
            result.environment["groups"][0]["attached_policies"][0]["policy_name"],
        )
        self.assertEqual(
            ["readonly-analyst"],
            result.environment["groups"][0]["members"],
        )
        self.assertEqual(
            "DataEngineeringBoundary",
            result.environment["users"][1]["permissions_boundary"]["policy_name"],
        )

    def test_loader_accepts_base64_aws_cli_credential_report_json(self):
        content = CREDENTIAL_PATH.read_bytes()
        payload = {
            "Content": base64.b64encode(content).decode("ascii"),
            "ReportFormat": "text/csv",
            "GeneratedTime": "2026-06-30T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "credential-report.json"
            normalized_path = Path(tmpdir) / "normalized.json"
            report_path.write_text(json.dumps(payload), encoding="utf-8")

            result = load_aws_iam_environment(
                AUTHORIZATION_PATH,
                report_path,
                as_of=AS_OF,
            )
            write_normalized_environment(normalized_path, result.environment)
            written = json.loads(normalized_path.read_text(encoding="utf-8"))

        self.assertEqual(result.environment, written)

    def test_url_encoded_policy_and_default_version_id_fallback_are_supported(self):
        authorization = _authorization_details()
        inline_policy = authorization["UserDetailList"][1]["UserPolicyList"][0]
        inline_policy["PolicyDocument"] = quote(json.dumps(inline_policy["PolicyDocument"]))
        managed_version = authorization["Policies"][0]["PolicyVersionList"][0]
        managed_version["IsDefaultVersion"] = False

        result = normalize_aws_iam_environment(
            authorization,
            _sample_credential_rows(),
            as_of=AS_OF,
        )

        self.assertEqual(9, len(analyze_environment(result.environment)))

    def test_decoded_policy_preserves_literal_percent_encoded_resource_text(self):
        authorization = _authorization_details()
        document = authorization["UserDetailList"][1]["UserPolicyList"][0][
            "PolicyDocument"
        ]
        document["Statement"][0]["Resource"] = "arn:aws:s3:::company-data/prefix%2Fname/*"
        authorization["UserDetailList"][1]["UserPolicyList"][0]["PolicyDocument"] = (
            json.dumps(document)
        )

        result = normalize_aws_iam_environment(
            authorization,
            _sample_credential_rows(),
            as_of=AS_OF,
        )

        resource = result.environment["users"][1]["attached_policies"][0]["statements"][0][
            "resource"
        ]
        self.assertEqual("arn:aws:s3:::company-data/prefix%2Fname/*", resource)

    def test_truncated_authorization_details_are_rejected(self):
        authorization = _authorization_details()
        authorization["IsTruncated"] = True

        with self.assertRaisesRegex(ValueError, "collect all pages"):
            normalize_aws_iam_environment(
                authorization,
                _sample_credential_rows(),
                as_of=AS_OF,
            )

    def test_incomplete_authorization_details_are_rejected(self):
        for missing_field in ("IsTruncated", "RoleDetailList"):
            with self.subTest(missing_field=missing_field):
                authorization = _authorization_details()
                del authorization[missing_field]

                with self.assertRaises(ValueError):
                    normalize_aws_iam_environment(
                        authorization,
                        _sample_credential_rows(),
                        as_of=AS_OF,
                    )

    def test_missing_credential_user_is_rejected(self):
        rows = _sample_credential_rows()
        del rows["data-engineer"]

        with self.assertRaisesRegex(ValueError, "no row for IAM user data-engineer"):
            normalize_aws_iam_environment(
                _authorization_details(),
                rows,
                as_of=AS_OF,
            )

    def test_partial_related_evidence_produces_deterministic_warnings(self):
        authorization = _authorization_details()
        authorization["UserDetailList"][2]["GroupList"] = ["MissingGroup"]
        authorization["UserDetailList"][0]["AttachedManagedPolicies"][0][
            "PolicyArn"
        ] = "arn:aws:iam::111122223333:policy/MissingPolicy"
        rows = _sample_credential_rows()
        rows["stale-user"] = _credential_row(
            "stale-user", "arn:aws:iam::111122223333:user/stale-user"
        )

        result = normalize_aws_iam_environment(authorization, rows, as_of=AS_OF)

        self.assertEqual(
            (
                "User alice-admin references managed policy "
                "arn:aws:iam::111122223333:policy/MissingPolicy, but its document is absent.",
                "User readonly-analyst references group MissingGroup, but its detail is absent.",
                "Credential report user(s) absent from authorization details: stale-user",
            ),
            result.warnings,
        )
        self.assertEqual(
            {
                "IAM_IDENTITY_DETAIL_ABSENT",
                "IAM_REFERENCED_POLICY_DOCUMENT_ABSENT",
            },
            {item.code for item in result.skipped_evidence},
        )

    def test_managed_policy_without_default_document_is_warned_and_skipped(self):
        authorization = _authorization_details()
        authorization["Policies"][0]["PolicyVersionList"] = []

        result = normalize_aws_iam_environment(
            authorization,
            _sample_credential_rows(),
            as_of=AS_OF,
        )

        self.assertIn("has no readable default policy version", result.warnings[0])
        self.assertIn("but its document is absent", result.warnings[1])
        self.assertEqual(
            "IAM_REFERENCED_POLICY_DOCUMENT_ABSENT",
            result.skipped_evidence[0].code,
        )

    def test_missing_permissions_boundary_document_is_preserved_with_warning(self):
        authorization = _authorization_details()
        authorization["UserDetailList"][1]["PermissionsBoundary"][
            "PermissionsBoundaryArn"
        ] = "arn:aws:iam::111122223333:policy/MissingBoundary"

        result = normalize_aws_iam_environment(
            authorization,
            _sample_credential_rows(),
            as_of=AS_OF,
        )
        boundary = result.environment["users"][1]["permissions_boundary"]

        self.assertFalse(boundary["document_available"])
        self.assertEqual([], boundary["statements"])
        self.assertIn("permissions boundary", result.warnings[0])

    def test_invalid_permissions_boundary_shape_is_rejected(self):
        cases = (
            ("not-an-object", "must be an object"),
            (
                {
                    "PermissionsBoundaryType": "Policy",
                    "PermissionsBoundaryArn": (
                        "arn:aws:iam::111122223333:policy/DataEngineeringBoundary"
                    ),
                },
                "PermissionsBoundaryType",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                authorization = _authorization_details()
                authorization["UserDetailList"][1]["PermissionsBoundary"] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_iam_environment(
                        authorization,
                        _sample_credential_rows(),
                        as_of=AS_OF,
                    )

    def test_conflicting_account_ids_are_rejected(self):
        rows = _sample_credential_rows()
        rows["data-engineer"]["arn"] = "arn:aws:iam::999988887777:user/data-engineer"

        with self.assertRaisesRegex(ValueError, "conflicting account IDs"):
            normalize_aws_iam_environment(
                _authorization_details(),
                rows,
                as_of=AS_OF,
            )

    def test_duplicate_managed_policy_is_rejected(self):
        authorization = _authorization_details()
        authorization["Policies"].append(authorization["Policies"][0])

        with self.assertRaisesRegex(ValueError, "duplicate managed policy"):
            normalize_aws_iam_environment(
                authorization,
                _sample_credential_rows(),
                as_of=AS_OF,
            )

    def test_direct_credential_rows_are_contract_checked(self):
        rows = _sample_credential_rows()
        del rows["alice-admin"]["mfa_active"]

        with self.assertRaisesRegex(ValueError, "missing required field"):
            normalize_aws_iam_environment(
                _authorization_details(),
                rows,
                as_of=AS_OF,
            )

    def test_invalid_credential_values_are_rejected(self):
        cases = (
            ("mfa_active", "UNKNOWN", "must be TRUE or FALSE"),
            ("password_enabled", "UNKNOWN", "must be TRUE or FALSE"),
            ("password_last_changed", "N/A", "active password without"),
            ("access_key_1_last_rotated", "yesterday", "ISO 8601"),
            ("access_key_1_last_rotated", "N/A", "active access key without"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                rows = _sample_credential_rows()
                rows["alice-admin"][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_iam_environment(
                        _authorization_details(),
                        rows,
                        as_of=AS_OF,
                    )

    def test_invalid_identity_structures_are_rejected(self):
        mutations = (
            (
                lambda payload: payload["UserDetailList"][0].__setitem__(
                    "UserPolicyList", {}
                ),
                "UserPolicyList must be a list",
            ),
            (
                lambda payload: payload["UserDetailList"][1]["UserPolicyList"][
                    0
                ].__delitem__("PolicyDocument"),
                "missing PolicyDocument",
            ),
            (
                lambda payload: payload["UserDetailList"][1]["UserPolicyList"][
                    0
                ].__setitem__("PolicyDocument", "not-json"),
                "invalid IAM policy document",
            ),
            (
                lambda payload: payload["RoleDetailList"][0].__delitem__(
                    "AssumeRolePolicyDocument"
                ),
                "missing AssumeRolePolicyDocument",
            ),
            (
                lambda payload: payload["UserDetailList"][2].__setitem__(
                    "GroupList", "ReportingReaders"
                ),
                "GroupList must be a list",
            ),
            (
                lambda payload: payload["UserDetailList"][2].__setitem__(
                    "GroupList", ["ReportingReaders", "ReportingReaders"]
                ),
                "duplicate group names",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                authorization = _authorization_details()
                mutate(authorization)
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_iam_environment(
                        authorization,
                        _sample_credential_rows(),
                        as_of=AS_OF,
                    )

    def test_credential_report_file_contract_errors_are_clear(self):
        sample_csv = CREDENTIAL_PATH.read_text(encoding="utf-8")
        cases = (
            ("{", "JSON is invalid"),
            ("[]", "must contain an object"),
            (json.dumps({"ReportFormat": "application/json", "Content": "eA=="}), "text/csv"),
            (json.dumps({"ReportFormat": "text/csv"}), "missing Base64 Content"),
            (sample_csv.replace("mfa_active,", "", 1), "missing required column"),
            (sample_csv + sample_csv.splitlines()[2] + "\n", "duplicate user"),
        )

        for content, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                report_path = Path(tmpdir) / "credential-report.txt"
                report_path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    load_aws_iam_environment(AUTHORIZATION_PATH, report_path, as_of=AS_OF)

    def test_duplicate_identities_are_rejected(self):
        identity_cases = (
            ("GroupDetailList", "duplicate group"),
            ("UserDetailList", "duplicate user"),
            ("RoleDetailList", "duplicate role"),
        )
        for key, message in identity_cases:
            with self.subTest(key=key):
                authorization = _authorization_details()
                authorization[key].append(authorization[key][0])
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_iam_environment(
                        authorization,
                        _sample_credential_rows(),
                        as_of=AS_OF,
                    )

    def test_future_active_key_rotation_is_rejected(self):
        rows = _sample_credential_rows()
        rows["alice-admin"]["access_key_1_last_rotated"] = "2026-07-01T00:00:00Z"

        with self.assertRaisesRegex(ValueError, "occurs after the analysis date"):
            normalize_aws_iam_environment(
                _authorization_details(),
                rows,
                as_of=AS_OF,
            )

    def test_multiple_root_rows_are_rejected(self):
        rows = _sample_credential_rows()
        rows["<root_account>"] = _credential_row(
            "<root_account>",
            "arn:aws:iam::111122223333:root",
        )
        rows["root_account"] = _credential_row(
            "root_account",
            "arn:aws:iam::111122223333:root",
        )

        with self.assertRaisesRegex(ValueError, "multiple root account rows"):
            normalize_aws_iam_environment(
                _authorization_details(),
                rows,
                as_of=AS_OF,
            )

    def test_malformed_credential_report_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "credential-report.json"
            report_path.write_text(
                json.dumps({"Content": "not-base64!", "ReportFormat": "text/csv"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "not valid Base64"):
                load_aws_iam_environment(AUTHORIZATION_PATH, report_path, as_of=AS_OF)


if __name__ == "__main__":
    unittest.main()
