#!/usr/bin/env bash
set -euo pipefail

readonly supported_version="5.48.0"
readonly repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly prowler_dir="${1:-/opt/prowler}"
readonly reports_dir_input="${2:-}"

if [[ -z "$reports_dir_input" ]]; then
  echo "Usage: $0 PROWLER_DIR REPORTS_DIR" >&2
  echo "Example: $0 /opt/prowler /home/user/prowler-results" >&2
  exit 2
fi

if [[ ! -f "$prowler_dir/docker-compose.yml" ]]; then
  echo "Prowler Compose file not found: $prowler_dir/docker-compose.yml" >&2
  exit 1
fi

if [[ ! -d "$reports_dir_input" ]]; then
  echo "Reports directory not found: $reports_dir_input" >&2
  exit 1
fi

readonly reports_dir="$(cd "$reports_dir_input" && pwd)"
if [[ "$reports_dir" == *'"'* || "$reports_dir" == *'$'* || \
      "$reports_dir" == *'\'* || "$reports_dir" == *':'* || \
      "$reports_dir" == *$'\n'* ]]; then
  echo "Reports directory contains characters unsupported by the Compose template." >&2
  exit 1
fi

api_container_id="$({
  cd "$prowler_dir"
  docker compose -f docker-compose.yml ps -q api
} 2>/dev/null || true)"

if [[ -n "$api_container_id" ]]; then
  installed_version="$(
    docker inspect \
      --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
      "$api_container_id"
  )"
  if [[ "$installed_version" != "$supported_version" ]]; then
    echo "Unsupported Prowler version: $installed_version" >&2
    echo "This importer is pinned to Prowler $supported_version." >&2
    exit 1
  fi
fi

readonly extension_dir="$prowler_dir/extensions/ocsf-importer"
readonly overlay_path="$prowler_dir/docker-compose.importer.yml"
readonly backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ -d "$extension_dir" ]]; then
  cp -a "$extension_dir" "${extension_dir}.backup-${backup_stamp}"
fi
if [[ -f "$overlay_path" ]]; then
  cp -a "$overlay_path" "${overlay_path}.backup-${backup_stamp}"
fi

install -d -m 755 "$extension_dir/commands"
install -m 644 "$repo_dir/src/ocsf_importer.py" \
  "$extension_dir/ocsf_importer.py"
install -m 644 "$repo_dir/src/commands/import_prowler_ocsf.py" \
  "$extension_dir/commands/import_prowler_ocsf.py"
install -m 644 "$repo_dir/src/commands/import_prowler_ocsf_directory.py" \
  "$extension_dir/commands/import_prowler_ocsf_directory.py"
install -m 644 "$repo_dir/README.md" "$extension_dir/README.md"

overlay="$(<"$repo_dir/deploy/docker-compose.importer.yml.template")"
overlay="${overlay//__REPORTS_DIR__/$reports_dir}"
printf '%s\n' "$overlay" > "$overlay_path"
chmod 644 "$overlay_path"

(
  cd "$prowler_dir"
  docker compose \
    -f docker-compose.yml \
    -f docker-compose.importer.yml \
    config --quiet
)

echo "Importer files installed for Prowler $supported_version."
echo "Reports directory: $reports_dir"
echo
echo "Activate the extension with:"
echo "  cd $prowler_dir"
echo "  docker compose -f docker-compose.yml -f docker-compose.importer.yml up -d api"
