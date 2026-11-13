from pathlib import Path

from api.management.commands.import_prowler_ocsf import resolve_tenant_id
from api.management.ocsf_importer import (
    DuplicateOCSFReport,
    OCSFImportError,
    import_ocsf_report,
    load_ocsf_report,
)
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Import Prowler CLI .ocsf.json reports recursively; failures are isolated."

    def add_arguments(self, parser):
        parser.add_argument("directory", type=Path)
        parser.add_argument("--tenant-id", type=str)
        parser.add_argument("--batch-size", type=int)

    def handle(self, *args, **options):
        directory = options["directory"].expanduser().resolve()
        if not directory.is_dir():
            raise CommandError(f"report directory not found: {directory}")

        reports = sorted(directory.rglob("*.ocsf.json"))
        if not reports:
            raise CommandError(f"no .ocsf.json reports found under {directory}")

        tenant_id = resolve_tenant_id(options.get("tenant_id"))
        successful = 0
        failed = 0
        duplicate_reports = 0
        findings = 0
        resources = 0
        invalid = 0
        duplicate_records = 0

        for report_path in reports:
            try:
                report = load_ocsf_report(report_path)
                result = import_ocsf_report(
                    report,
                    tenant_id,
                    batch_size=options.get("batch_size"),
                )
            except DuplicateOCSFReport as error:
                successful += 1
                duplicate_reports += 1
                self.stdout.write(
                    self.style.WARNING(f"Skipped {report_path}: {error}")
                )
                continue
            except (OCSFImportError, OSError, ValueError) as error:
                failed += 1
                self.stderr.write(self.style.ERROR(f"Failed {report_path}: {error}"))
                continue

            successful += 1
            findings += result.imported_findings
            resources += result.imported_resources
            invalid += result.invalid_records
            duplicate_records += result.duplicate_records
            self.stdout.write(self.style.SUCCESS(f"Imported {report_path}"))

        self.stdout.write("")
        self.stdout.write(f"Accounts processed: {len(reports)}")
        self.stdout.write(f"Successful: {successful}")
        self.stdout.write(f"Failed: {failed}")
        self.stdout.write(f"Findings imported: {findings}")
        self.stdout.write(f"Resources imported: {resources}")
        self.stdout.write(f"Invalid records: {invalid}")
        self.stdout.write(f"Duplicate records skipped: {duplicate_records}")
        self.stdout.write(f"Duplicate reports skipped: {duplicate_reports}")
