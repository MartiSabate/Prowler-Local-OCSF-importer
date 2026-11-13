import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prowler.lib.check.models import Severity


class OCSFImportError(ValueError):
    pass


class DuplicateOCSFReport(OCSFImportError):
    pass


@dataclass(frozen=True)
class OCSFFindingAdapter:
    auth_method: str
    timestamp: datetime
    account_uid: str
    account_name: str
    account_organization_uid: str
    account_organization_name: str
    uid: str
    status: str
    status_extended: str
    muted: bool
    resource_uid: str
    resource_metadata: dict[str, Any]
    resource_name: str
    resource_details: str
    resource_tags: dict[str, str]
    partition: str | None
    region: str
    compliance: dict[str, Any]
    raw: dict[str, Any]
    check_id: str
    severity: Severity
    resource_type: str
    service_name: str
    check_metadata: dict[str, Any]

    def get_metadata(self) -> dict[str, Any]:
        return self.check_metadata.copy()


@dataclass(frozen=True)
class ParsedOCSFReport:
    path: Path
    report_hash: str
    provider_type: str
    provider_uid: str
    account_name: str
    organization_uid: str
    organization_name: str
    scan_timestamp: datetime
    regions: tuple[str, ...]
    scan_ids: tuple[str, ...]
    findings: tuple[OCSFFindingAdapter, ...]
    total_records: int
    invalid_records: int
    duplicate_records: int

    @property
    def import_id(self) -> str:
        return build_import_id(
            self.provider_type,
            self.provider_uid,
            self.scan_timestamp.isoformat(),
            self.report_hash,
        )


@dataclass(frozen=True)
class OCSFImportResult:
    import_id: str
    provider_id: str
    scan_id: str
    total_records: int
    imported_findings: int
    imported_resources: int
    skipped_records: int
    invalid_records: int
    duplicate_records: int


def build_import_id(
    provider_type: str,
    provider_uid: str,
    scan_timestamp: str,
    report_hash: str,
) -> str:
    payload = "\0".join(
        (provider_type.lower(), provider_uid, scan_timestamp, report_hash.lower())
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as report_file:
        for chunk in iter(lambda: report_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if not isinstance(value, str) or not value:
        raise ValueError("missing finding timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_labels(labels: Any) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not isinstance(labels, list):
        return parsed
    for label in labels:
        if isinstance(label, str):
            key, separator, value = label.partition(":")
            if key:
                parsed[key] = value if separator else ""
        elif isinstance(label, dict):
            key = label.get("key", label.get("Key"))
            if key:
                parsed[str(key)] = str(
                    label.get("value", label.get("Value", ""))
                )
    return parsed


def _string(value: Any, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"invalid {field_name}")
    return value


def _record_to_finding(record: Any) -> tuple[OCSFFindingAdapter, str, str, str, str]:
    if not isinstance(record, dict):
        raise ValueError("record is not an object")
    if record.get("class_uid") != 2004:
        raise ValueError("record is not an OCSF Detection Finding")

    metadata = record.get("metadata")
    finding_info = record.get("finding_info")
    unmapped = record.get("unmapped") or {}
    cloud = record.get("cloud") or {}
    resources = record.get("resources")
    if not isinstance(metadata, dict) or not isinstance(finding_info, dict):
        raise ValueError("missing finding metadata")
    if not isinstance(unmapped, dict) or not isinstance(cloud, dict):
        raise ValueError("invalid Prowler metadata")
    if not isinstance(resources, list) or len(resources) != 1:
        raise ValueError("each finding must contain exactly one resource")
    resource = resources[0]
    if not isinstance(resource, dict):
        raise ValueError("invalid finding resource")

    product = metadata.get("product") or {}
    if not isinstance(product, dict) or str(product.get("name", "")).lower() != "prowler":
        raise ValueError("record was not produced by Prowler")

    provider_type = _string(
        unmapped.get("provider") or cloud.get("provider"), "provider"
    ).lower()
    account = cloud.get("account") or {}
    if not isinstance(account, dict):
        raise ValueError("invalid cloud account")
    provider_uid = _string(
        account.get("uid") or unmapped.get("provider_uid"), "provider UID"
    )
    account_name = account.get("name") if isinstance(account.get("name"), str) else ""
    organization = cloud.get("org") or {}
    if not isinstance(organization, dict):
        organization = {}

    finding_uid = _string(finding_info.get("uid"), "finding UID")
    if len(finding_uid) > 300:
        raise ValueError("finding UID exceeds 300 characters")
    check_id = _string(metadata.get("event_code"), "check ID")
    if len(check_id) > 100:
        raise ValueError("check ID exceeds 100 characters")

    status = _string(record.get("status_code"), "status").upper()
    muted = str(record.get("status", "")).lower() == "suppressed" or status == "MUTED"
    if status == "MUTED":
        status = "FAIL"
    if status not in {"PASS", "FAIL", "MANUAL"}:
        raise ValueError("unsupported finding status")

    severity_value = _string(record.get("severity"), "severity").lower()
    if severity_value in {"unknown", "other"}:
        severity_value = Severity.informational.value
    severity = Severity(severity_value)

    resource_uid = _string(resource.get("uid"), "resource UID", allow_empty=True)
    resource_name = _string(
        resource.get("name") or resource_uid, "resource name", allow_empty=True
    )
    region = _string(
        resource.get("region") or cloud.get("region") or "global",
        "resource region",
    )
    resource_type = _string(resource.get("type") or "Other", "resource type")
    resource_group = resource.get("group") or {}
    service_name = _string(
        resource_group.get("name") if isinstance(resource_group, dict) else None,
        "service name",
    )
    resource_data = resource.get("data") or {}
    if not isinstance(resource_data, dict):
        resource_data = {}
    resource_metadata = resource_data.get("metadata") or {}
    if not isinstance(resource_metadata, dict):
        resource_metadata = {"value": resource_metadata}
    resource_details = resource_data.get("details") or ""
    if not isinstance(resource_details, str):
        resource_details = json.dumps(resource_details, default=str)

    remediation = record.get("remediation") or {}
    if not isinstance(remediation, dict):
        remediation = {}
    references = remediation.get("references") or []
    remediation_url = references[0] if isinstance(references, list) and references else ""
    if not isinstance(remediation_url, str):
        remediation_url = ""

    categories = unmapped.get("categories") or []
    if not isinstance(categories, list):
        categories = []
    compliance = unmapped.get("compliance") or {}
    if not isinstance(compliance, dict):
        compliance = {}
    timestamp = _parse_datetime(record.get("time_dt") or record.get("time"))

    check_metadata = {
        "provider": provider_type,
        "checkid": check_id,
        "checktitle": _string(finding_info.get("title"), "check title"),
        "checktype": finding_info.get("types") or [],
        "checkaliases": [],
        "servicename": service_name,
        "subservicename": "",
        "resourceidtemplate": "",
        "severity": severity.value,
        "resourcetype": resource_type,
        "resourcegroup": "",
        "description": str(finding_info.get("desc") or ""),
        "risk": str(record.get("risk_details") or ""),
        "relatedurl": str(unmapped.get("related_url") or ""),
        "remediation": {
            "code": {"nativeiac": "", "terraform": "", "cli": "", "other": ""},
            "recommendation": {
                "text": str(remediation.get("desc") or ""),
                "url": remediation_url,
            },
        },
        "additionalurls": unmapped.get("additional_urls") or [],
        "categories": categories,
        "dependson": unmapped.get("depends_on") or [],
        "relatedto": unmapped.get("related_to") or [],
        "notes": str(unmapped.get("notes") or ""),
        "compliance": compliance,
    }

    finding = OCSFFindingAdapter(
        auth_method="imported-ocsf",
        timestamp=timestamp,
        account_uid=provider_uid,
        account_name=account_name,
        account_organization_uid=str(organization.get("uid") or ""),
        account_organization_name=str(organization.get("name") or ""),
        uid=finding_uid,
        status=status,
        status_extended=str(record.get("status_detail") or record.get("message") or ""),
        muted=muted,
        resource_uid=resource_uid,
        resource_metadata=resource_metadata,
        resource_name=resource_name,
        resource_details=resource_details,
        resource_tags=_parse_labels(resource.get("labels")),
        partition=resource.get("cloud_partition"),
        region=region,
        compliance=compliance,
        raw=record,
        check_id=check_id,
        severity=severity,
        resource_type=resource_type,
        service_name=service_name,
        check_metadata=check_metadata,
    )
    return (
        finding,
        provider_type,
        provider_uid,
        account_name,
        str(unmapped.get("scan_id") or ""),
    )


def load_ocsf_report(path: str | Path) -> ParsedOCSFReport:
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file():
        raise OCSFImportError(f"OCSF report not found: {report_path}")
    if report_path.stat().st_size == 0:
        raise OCSFImportError("OCSF report is empty")
    if not report_path.name.endswith(".ocsf.json"):
        raise OCSFImportError("report filename must end with .ocsf.json")

    try:
        with report_path.open(encoding="utf-8") as report_file:
            records = json.load(report_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OCSFImportError(f"invalid OCSF JSON: {error}") from error
    if not isinstance(records, list):
        raise OCSFImportError("OCSF report must contain a JSON array")
    if not records:
        raise OCSFImportError("OCSF report contains no records")

    findings: list[OCSFFindingAdapter] = []
    identities: set[tuple[str, str]] = set()
    seen_finding_uids: set[str] = set()
    account_names: list[str] = []
    scan_ids: set[str] = set()
    invalid_records = 0
    duplicate_records = 0

    for record in records:
        try:
            finding, provider_type, provider_uid, account_name, scan_id = (
                _record_to_finding(record)
            )
        except (TypeError, ValueError):
            invalid_records += 1
            continue
        identities.add((provider_type, provider_uid))
        if len(identities) > 1:
            raise OCSFImportError("report contains multiple provider accounts")
        if finding.uid in seen_finding_uids:
            duplicate_records += 1
            continue
        seen_finding_uids.add(finding.uid)
        findings.append(finding)
        if account_name:
            account_names.append(account_name)
        if scan_id:
            scan_ids.add(scan_id)

    if not findings:
        raise OCSFImportError("OCSF report contains no valid Prowler findings")

    provider_type, provider_uid = next(iter(identities))
    first = findings[0]
    return ParsedOCSFReport(
        path=report_path,
        report_hash=_sha256(report_path),
        provider_type=provider_type,
        provider_uid=provider_uid,
        account_name=account_names[0] if account_names else "",
        organization_uid=first.account_organization_uid,
        organization_name=first.account_organization_name,
        scan_timestamp=min(finding.timestamp for finding in findings),
        regions=tuple(sorted({finding.region for finding in findings})),
        scan_ids=tuple(sorted(scan_ids)),
        findings=tuple(findings),
        total_records=len(records),
        invalid_records=invalid_records,
        duplicate_records=duplicate_records,
    )


def _provider_alias(report: ParsedOCSFReport) -> str:
    if len(report.account_name.strip()) >= 3:
        return report.account_name.strip()[:100]
    return f"Imported {report.provider_type.upper()} {report.provider_uid}"[:100]


def import_ocsf_report(
    report: ParsedOCSFReport,
    tenant_id: str,
    *,
    batch_size: int | None = None,
) -> OCSFImportResult:
    from collections import defaultdict

    from api.db_utils import rls_transaction
    from api.models import (
        Finding,
        Provider,
        ResourceScanSummary,
        Scan,
        ScanCategorySummary,
        ScanGroupSummary,
        StateChoices,
    )
    from tasks.jobs.scan import (
        FINDINGS_MICRO_BATCH_SIZE,
        _bulk_update_resource_failed_findings_counts,
        _process_finding_micro_batch,
        aggregate_findings,
        aggregate_finding_group_summaries,
    )

    micro_batch_size = batch_size or FINDINGS_MICRO_BATCH_SIZE
    if micro_batch_size < 1:
        raise OCSFImportError("batch size must be a positive integer")

    finding_uids = [finding.uid for finding in report.findings]
    completed_at = max(finding.timestamp for finding in report.findings)

    with rls_transaction(tenant_id):
        provider, _ = Provider.objects.get_or_create(
            tenant_id=tenant_id,
            provider=report.provider_type,
            uid=report.provider_uid,
            defaults={
                "alias": _provider_alias(report),
                "connected": False,
                "metadata": {
                    "source": "ocsf-import",
                    "organization_uid": report.organization_uid,
                    "organization_name": report.organization_name,
                    "regions": list(report.regions),
                },
            },
        )
        provider = Provider.objects.select_for_update().get(pk=provider.pk)

        duplicate = Scan.objects.filter(
            tenant_id=tenant_id,
            provider=provider,
            scanner_args__ocsf_import__id=report.import_id,
        ).first()
        if duplicate:
            raise DuplicateOCSFReport(
                f"report {report.import_id} was already imported as scan {duplicate.id}"
            )

        previous_first_seen = {
            row["uid"]: row["first_seen_at"]
            for row in Finding.all_objects.filter(
                tenant_id=tenant_id, uid__in=finding_uids
            )
            .values("uid", "first_seen_at")
            .order_by("uid", "-inserted_at")
            .distinct("uid")
        }

        scan = Scan.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            name=f"Imported OCSF {report.scan_timestamp:%Y-%m-%d %H:%M UTC}",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.EXECUTING,
            progress=0,
            started_at=report.scan_timestamp,
            scanner_args={
                "checks": ["imported-ocsf"],
                "ocsf_import": {
                    "id": report.import_id,
                    "report_sha256": report.report_hash,
                    "source_scan_ids": list(report.scan_ids),
                    "source_timestamp": report.scan_timestamp.isoformat(),
                },
            },
        )

        resource_cache = {}
        tag_cache = {}
        last_status_cache = {}
        resource_failed_findings_cache = defaultdict(int)
        unique_resources: set[tuple[str, str]] = set()
        scan_resource_cache: set[tuple[str, str, str, str]] = set()
        scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
        scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}

        findings = list(report.findings)
        for start in range(0, len(findings), micro_batch_size):
            _process_finding_micro_batch(
                tenant_id=tenant_id,
                findings_batch=findings[start : start + micro_batch_size],
                scan_instance=scan,
                provider_instance=provider,
                resource_cache=resource_cache,
                tag_cache=tag_cache,
                last_status_cache=last_status_cache,
                resource_failed_findings_cache=resource_failed_findings_cache,
                unique_resources=unique_resources,
                scan_resource_cache=scan_resource_cache,
                mute_rules_cache={},
                scan_categories_cache=scan_categories_cache,
                scan_resource_groups_cache=scan_resource_groups_cache,
                group_resources_cache=group_resources_cache,
            )

        resources_to_update = []
        for resource_uid, failed_count in resource_failed_findings_cache.items():
            resource = resource_cache.get(resource_uid)
            if resource is not None:
                resource.failed_findings_count = failed_count
                resources_to_update.append(resource)
        _bulk_update_resource_failed_findings_counts(
            tenant_id=tenant_id,
            scan_id=str(scan.id),
            resources_to_update=resources_to_update,
        )

        imported_findings = list(Finding.objects.filter(scan=scan))
        source_by_uid = {finding.uid: finding for finding in report.findings}
        for finding in imported_findings:
            source = source_by_uid[finding.uid]
            finding.inserted_at = source.timestamp
            finding.updated_at = source.timestamp
            finding.first_seen_at = previous_first_seen.get(finding.uid) or source.timestamp
        Finding.objects.bulk_update(
            imported_findings,
            ["inserted_at", "updated_at", "first_seen_at"],
            batch_size=micro_batch_size,
        )

        ResourceScanSummary.objects.bulk_create(
            [
                ResourceScanSummary(
                    tenant_id=tenant_id,
                    scan_id=scan.id,
                    resource_id=resource_id,
                    service=service,
                    region=region,
                    resource_type=resource_type,
                )
                for resource_id, service, region, resource_type in scan_resource_cache
            ],
            batch_size=micro_batch_size,
            ignore_conflicts=True,
        )
        ScanCategorySummary.objects.bulk_create(
            [
                ScanCategorySummary(
                    tenant_id=tenant_id,
                    scan_id=scan.id,
                    category=category,
                    severity=severity,
                    total_findings=counts["total"],
                    failed_findings=counts["failed"],
                    new_failed_findings=counts["new_failed"],
                )
                for (category, severity), counts in scan_categories_cache.items()
            ],
            batch_size=micro_batch_size,
            ignore_conflicts=True,
        )
        ScanGroupSummary.objects.bulk_create(
            [
                ScanGroupSummary(
                    tenant_id=tenant_id,
                    scan_id=scan.id,
                    resource_group=resource_group,
                    severity=severity,
                    total_findings=counts["total"],
                    failed_findings=counts["failed"],
                    new_failed_findings=counts["new_failed"],
                    resources_count=len(
                        group_resources_cache.get(resource_group, set())
                    ),
                )
                for (resource_group, severity), counts in scan_resource_groups_cache.items()
            ],
            batch_size=micro_batch_size,
            ignore_conflicts=True,
        )

        scan.state = StateChoices.COMPLETED
        scan.progress = 100
        scan.completed_at = completed_at
        scan.duration = max(
            0, int((completed_at - report.scan_timestamp).total_seconds())
        )
        scan.unique_resource_count = len(unique_resources)
        scan.save(
            update_fields=[
                "state",
                "progress",
                "completed_at",
                "duration",
                "unique_resource_count",
                "updated_at",
            ]
        )
        Scan.objects.filter(pk=scan.pk).update(
            inserted_at=report.scan_timestamp,
            updated_at=completed_at,
        )

        provider_id = str(provider.id)
        scan_id = str(scan.id)
        # Resource is unique by tenant/provider/UID in the Local Server model.
        # ResourceScanSummary may contain more rows if an upstream report reuses a
        # UID across regions, so the resource cache is the database-object count.
        imported_resources = len(resource_cache)
        imported_findings_count = len(imported_findings)

    aggregate_findings(tenant_id=tenant_id, scan_id=scan_id)
    # Normal Local Server scans materialize this table during their completion
    # chain. The latest/all-scans Findings view reads these summaries instead of
    # aggregating the raw Finding table, so imported scans must do the same.
    aggregate_finding_group_summaries(tenant_id=tenant_id, scan_id=scan_id)

    return OCSFImportResult(
        import_id=report.import_id,
        provider_id=provider_id,
        scan_id=scan_id,
        total_records=report.total_records,
        imported_findings=imported_findings_count,
        imported_resources=imported_resources,
        skipped_records=report.duplicate_records,
        invalid_records=report.invalid_records,
        duplicate_records=report.duplicate_records,
    )
