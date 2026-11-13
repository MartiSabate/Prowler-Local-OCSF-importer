import json
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from api.management.ocsf_importer import (
    DuplicateOCSFReport,
    OCSFImportError,
    build_import_id,
    import_ocsf_report,
    load_ocsf_report,
)
from api.models import (
    Finding,
    FindingGroupDailySummary,
    Provider,
    Resource,
    Scan,
    ScanSummary,
)
from django.core.management import call_command


def make_record(**overrides):
    record = {
        "class_uid": 2004,
        "time": 1770729008,
        "time_dt": "2026-02-10T13:10:08+00:00",
        "severity": "High",
        "status": "New",
        "status_code": "FAIL",
        "status_detail": "The resource is not compliant.",
        "finding_info": {
            "uid": "prowler-aws-s3_bucket_public_access-123456789012-bucket",
            "title": "S3 bucket public access is blocked",
            "desc": "Checks whether public access is blocked.",
            "types": ["Software and Configuration Checks"],
        },
        "metadata": {
            "event_code": "s3_bucket_public_access",
            "product": {"name": "Prowler", "version": "5.48.0"},
        },
        "cloud": {
            "provider": "aws",
            "account": {"uid": "123456789012", "name": "Development"},
            "org": {"uid": "o-example", "name": "Example"},
        },
        "resources": [
            {
                "uid": "arn:aws:s3:::example",
                "name": "example",
                "region": "eu-west-1",
                "type": "AwsS3Bucket",
                "group": {"name": "s3"},
                "cloud_partition": "aws",
                "labels": ["Environment:Development"],
                "data": {"details": "details", "metadata": {"arn": "example"}},
            }
        ],
        "remediation": {
            "desc": "Block public access.",
            "references": ["https://hub.prowler.com/check/s3_bucket_public_access"],
        },
        "risk_details": "Public access may expose data.",
        "unmapped": {
            "provider": "aws",
            "provider_uid": "123456789012",
            "scan_id": "019c2c86-3b2e-7c39-98fb-2f88643c246e",
            "categories": ["internet-exposed"],
            "compliance": {"CIS-1.5": ["2.1.5"]},
            "related_url": "",
            "additional_urls": [],
            "depends_on": [],
            "related_to": [],
            "notes": "",
        },
    }
    record.update(overrides)
    return record


def write_report(tmp_path, records):
    report = tmp_path / "report.ocsf.json"
    report.write_text(json.dumps(records), encoding="utf-8")
    return report


def test_load_ocsf_report_maps_detection_finding(tmp_path):
    report = write_report(tmp_path, [make_record()])

    parsed = load_ocsf_report(report)

    assert parsed.provider_type == "aws"
    assert parsed.provider_uid == "123456789012"
    assert parsed.account_name == "Development"
    assert parsed.total_records == 1
    assert parsed.invalid_records == 0
    assert parsed.duplicate_records == 0
    finding = parsed.findings[0]
    assert finding.check_id == "s3_bucket_public_access"
    assert finding.resource_uid == "arn:aws:s3:::example"
    assert finding.resource_tags == {"Environment": "Development"}
    assert finding.compliance == {"CIS-1.5": ["2.1.5"]}
    assert finding.get_metadata()["risk"] == "Public access may expose data."


def test_load_ocsf_report_counts_invalid_and_duplicate_records(tmp_path):
    valid = make_record()
    invalid = make_record(class_uid=1001)
    report = write_report(tmp_path, [valid, valid, invalid])

    parsed = load_ocsf_report(report)

    assert parsed.total_records == 3
    assert len(parsed.findings) == 1
    assert parsed.invalid_records == 1
    assert parsed.duplicate_records == 1


def test_load_ocsf_report_rejects_mixed_accounts(tmp_path):
    other = make_record()
    other["cloud"]["account"]["uid"] = "999999999999"
    report = write_report(tmp_path, [make_record(), other])

    with pytest.raises(OCSFImportError, match="multiple provider accounts"):
        load_ocsf_report(report)


def test_load_ocsf_report_rejects_non_array(tmp_path):
    report = write_report(tmp_path, {"class_uid": 2004})

    with pytest.raises(OCSFImportError, match="JSON array"):
        load_ocsf_report(report)


def test_build_import_id_is_stable_and_report_specific():
    first = build_import_id(
        "aws", "123456789012", "2026-02-10T13:10:08+00:00", "a" * 64
    )
    same = build_import_id(
        "aws", "123456789012", "2026-02-10T13:10:08+00:00", "a" * 64
    )
    different = build_import_id(
        "aws", "123456789012", "2026-02-10T13:10:08+00:00", "b" * 64
    )

    assert first == same
    assert first != different
    assert len(first) == 64


@pytest.mark.django_db(databases="__all__")
def test_import_ocsf_report_uses_scan_persistence_pipeline(tmp_path, tenants_fixture):
    tenant_id = str(tenants_fixture[0].id)
    parsed = load_ocsf_report(write_report(tmp_path, [make_record()]))

    result = import_ocsf_report(parsed, tenant_id)

    assert result.imported_findings == 1
    assert result.imported_resources == 1
    assert result.invalid_records == 0
    assert result.duplicate_records == 0
    with rls_transaction(tenant_id):
        provider = Provider.objects.get(uid="123456789012")
        scan = Scan.objects.get(id=result.scan_id)
        finding = Finding.objects.get(scan=scan)
        resource = Resource.objects.get(provider=provider)
        assert provider.connected is False
        assert scan.state == "completed"
        assert scan.progress == 100
        assert scan.is_full_scope() is False
        assert scan.scanner_args["ocsf_import"]["id"] == parsed.import_id
        assert scan.started_at == parsed.scan_timestamp
        assert finding.inserted_at == parsed.findings[0].timestamp
        assert finding.check_id == "s3_bucket_public_access"
        assert finding.compliance == {"CIS-1.5": ["2.1.5"]}
        assert resource.uid == "arn:aws:s3:::example"
        assert resource.metadata == json.dumps({"arn": "example"})
        assert ScanSummary.objects.filter(scan=scan).exists()
        finding_group_summary = FindingGroupDailySummary.objects.get(
            provider=provider,
            check_id="s3_bucket_public_access",
        )
        assert finding_group_summary.fail_count == 1
        assert finding_group_summary.pass_count == 0


@pytest.mark.django_db(databases="__all__")
def test_import_ocsf_report_rejects_same_report_twice(tmp_path, tenants_fixture):
    tenant_id = str(tenants_fixture[0].id)
    parsed = load_ocsf_report(write_report(tmp_path, [make_record()]))
    import_ocsf_report(parsed, tenant_id)

    with pytest.raises(DuplicateOCSFReport, match=parsed.import_id):
        import_ocsf_report(parsed, tenant_id)


def test_import_command_prints_sanitized_summary(tmp_path):
    report = write_report(tmp_path, [make_record()])
    result = SimpleNamespace(
        import_id="a" * 64,
        provider_id="provider-id",
        scan_id="scan-id",
        total_records=1,
        imported_findings=1,
        imported_resources=1,
        skipped_records=0,
        invalid_records=0,
        duplicate_records=0,
    )
    output = StringIO()

    with patch(
        "api.management.commands.import_prowler_ocsf.import_ocsf_report",
        return_value=result,
    ):
        call_command(
            "import_prowler_ocsf",
            str(report),
            tenant_id="00000000-0000-0000-0000-000000000001",
            stdout=output,
        )

    rendered = output.getvalue()
    assert "Findings imported: 1" in rendered
    assert "Resources imported: 1" in rendered
    assert "scan-id" in rendered


def test_directory_command_continues_after_one_report_fails(tmp_path):
    first = tmp_path / "111111111111" / "first.ocsf.json"
    second = tmp_path / "222222222222" / "second.ocsf.json"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("[]", encoding="utf-8")
    second.write_text("[]", encoding="utf-8")
    parsed = SimpleNamespace(path=first)
    result = SimpleNamespace(
        imported_findings=3,
        imported_resources=2,
        invalid_records=1,
        duplicate_records=0,
    )
    output = StringIO()

    with (
        patch(
            "api.management.commands.import_prowler_ocsf_directory.load_ocsf_report",
            side_effect=[parsed, OCSFImportError("bad report")],
        ),
        patch(
            "api.management.commands.import_prowler_ocsf_directory.import_ocsf_report",
            return_value=result,
        ),
    ):
        call_command(
            "import_prowler_ocsf_directory",
            str(tmp_path),
            tenant_id="00000000-0000-0000-0000-000000000001",
            stdout=output,
        )

    rendered = output.getvalue()
    assert "Accounts processed: 2" in rendered
    assert "Successful: 1" in rendered
    assert "Failed: 1" in rendered
    assert "Findings imported: 3" in rendered
