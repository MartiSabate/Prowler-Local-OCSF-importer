from pathlib import Path
from uuid import UUID

from api.db_router import MainRouter
from api.management.ocsf_importer import (
    DuplicateOCSFReport,
    OCSFImportError,
    import_ocsf_report,
    load_ocsf_report,
)
from api.rls import Tenant
from django.core.management.base import BaseCommand, CommandError


def resolve_tenant_id(value: str | None) -> str:
    if value:
        try:
            return str(UUID(value))
        except ValueError as error:
            raise CommandError("--tenant-id must be a valid UUID") from error

    tenant_ids = list(
        Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)[:2]
    )
    if not tenant_ids:
        raise CommandError("no Local Server tenant exists")
    if len(tenant_ids) > 1:
        raise CommandError(
            "multiple tenants exist; select one explicitly with --tenant-id"
        )
    return str(tenant_ids[0])


class Command(BaseCommand):
    help = "Import one Prowler CLI .ocsf.json report through the OSS scan pipeline."

    def add_arguments(self, parser):
        parser.add_argument("report", type=Path)
        parser.add_argument("--tenant-id", type=str)
        parser.add_argument("--batch-size", type=int)

    def handle(self, *args, **options):
        tenant_id = resolve_tenant_id(options.get("tenant_id"))
        try:
            report = load_ocsf_report(options["report"])
            result = import_ocsf_report(
                report,
                tenant_id,
                batch_size=options.get("batch_size"),
            )
        except DuplicateOCSFReport as error:
            self.stdout.write(self.style.WARNING(f"Already imported: {error}"))
            return
        except OCSFImportError as error:
            raise CommandError(str(error)) from error

        self.stdout.write(self.style.SUCCESS("OCSF import completed"))
        self.stdout.write(f"Import ID: {result.import_id}")
        self.stdout.write(f"Provider ID: {result.provider_id}")
        self.stdout.write(f"Scan ID: {result.scan_id}")
        self.stdout.write(f"Total input records: {result.total_records}")
        self.stdout.write(f"Findings imported: {result.imported_findings}")
        self.stdout.write(f"Resources imported: {result.imported_resources}")
        self.stdout.write(f"Skipped records: {result.skipped_records}")
        self.stdout.write(f"Invalid records: {result.invalid_records}")
        self.stdout.write(f"Duplicate records: {result.duplicate_records}")
