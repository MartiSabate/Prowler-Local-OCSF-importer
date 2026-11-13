# Prowler Local OCSF Importer

Proof-of-concept Django management commands for importing Prowler CLI
`.ocsf.json` reports into a self-hosted Prowler Local Server so the resulting
scans and findings appear in the normal Local Server UI.

This project does **not** use Prowler Cloud, require a commercial API key,
disable authentication, bypass subscription controls, or write raw SQL. It
reuses the open-source Local Server Django models and scan persistence pipeline.

## Compatibility

This version is pinned to:

- Prowler Local Server `5.48.0`
- Git revision `8a5aebb8a8c34dcecd17eba79466b94226440804`
- Official Docker Compose image deployment

The importer calls underscore-prefixed helpers from `tasks.jobs.scan`; treat
those as unstable. Review and retest this project before using it with another
Prowler release.

## What it imports

For each Prowler OCSF Detection Finding (`class_uid=2004`), the importer
preserves the check ID and title, status, severity, resource UID, region,
service, risk, remediation, compliance mappings, timestamps, raw OCSF record,
and provider/account identifiers.

It creates or updates the same Local Server objects used by a normal scan:

- Provider and Scan
- Resource and ResourceTag
- Finding and ResourceFindingMapping
- ResourceScanSummary, ScanCategorySummary, ScanGroupSummary, ScanSummary, and
  FindingGroupDailySummary (required by the Findings latest/all-scans view)

Imported providers remain disconnected and receive no cloud credentials.

## Installation

Clone this repository, then run the installer with the Prowler Compose directory
and host directory containing the reports:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL prowler-local-ocsf-importer
cd prowler-local-ocsf-importer

./install.sh /opt/prowler /path/to/prowler/results
```

The installer:

1. Checks the running API image version when available.
2. Copies the extension under `/opt/prowler/extensions/ocsf-importer`.
3. Creates `/opt/prowler/docker-compose.importer.yml`.
4. Validates the merged Compose configuration.
5. Does not restart containers or import data automatically.

Activate or update the read-only mounts:

```bash
cd /opt/prowler
docker compose -f docker-compose.yml -f docker-compose.importer.yml up -d api
```

## Import all reports in a directory

The host reports directory is mounted as `/imports` inside the API container.
Run the directory command once; it searches account subdirectories recursively:

```bash
cd /opt/prowler

docker compose -f docker-compose.yml -f docker-compose.importer.yml exec -T api \
  uv run python manage.py import_prowler_ocsf_directory /imports
```

Previously imported reports are skipped. One invalid report does not stop the
remaining reports. CSV files are ignored.

Example host layout:

```text
results/
  111111111111/
    report.ocsf.json
  222222222222/
    report.ocsf.json
```

## Import one report

```bash
docker compose -f docker-compose.yml -f docker-compose.importer.yml exec -T api \
  uv run python manage.py import_prowler_ocsf \
  /imports/111111111111/report.ocsf.json
```

If Local Server contains multiple tenants, add `--tenant-id TENANT_UUID`.

## Duplicate protection

The stable import ID is derived from:

- provider type and account ID
- source scan timestamp
- SHA-256 hash of the report

The ID is stored in `Scan.scanner_args.ocsf_import`. Importing the exact same
report again stops safely and reports the existing scan.

## Verification and logs

```bash
cd /opt/prowler

docker compose -f docker-compose.yml -f docker-compose.importer.yml ps
docker compose -f docker-compose.yml -f docker-compose.importer.yml logs --tail=200 api
```

Sign in to the Local Server UI, open **Scans**, and refresh the page.

## Backup and removal

Create a PostgreSQL backup before the first import. The importer changes Local
Server data through Django even though it does not alter the schema.

To remove only the code mounts while retaining imported data:

```bash
cd /opt/prowler
docker compose -f docker-compose.yml up -d --force-recreate api
```

Then archive or remove `docker-compose.importer.yml` and
`extensions/ocsf-importer`. Removing the extension does not delete imported
scans. Database rollback requires restoring a pre-import backup or a carefully
reviewed application-layer deletion.

## Known limitations

- This is independent of the official commercial Manage Ingestions feature and
  does not add an ingestion UI.
- Per-finding compliance mappings are preserved, but disconnected providers do
  not initialize compliance requirement catalogs.
- Attack-path/Neo4j ingestion is not run.
- The JSON array is loaded into memory.
- Each OCSF finding must contain exactly one resource, matching Prowler CLI
  `5.48.0` output.
- Resources are unique by tenant/provider/UID, following Local Server behavior.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Publish to GitHub

After reviewing the staged files, configure your Git identity and create the
initial commit:

```bash
git config user.name "YOUR NAME"
git config user.email "YOUR GITHUB EMAIL"
git commit -m "Initial Prowler Local OCSF importer"
```

Create an empty GitHub repository, then connect and push it:

```bash
git remote add origin git@github.com:YOUR-USER/YOUR-REPOSITORY.git
git push -u origin main
```
