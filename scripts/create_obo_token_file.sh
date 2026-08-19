#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <admin-profile> <service-principal-application-id> <output-json-outside-repo>" >&2
  exit 2
fi

admin_profile=$1
application_id=$2
output_file=$3
repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
mkdir -p "$(dirname "$output_file")"
output_abs=$(cd "$(dirname "$output_file")" && pwd)/$(basename "$output_file")

case "$output_abs" in
  "$repo_root"/*)
    echo "refusing to write a credential inside the repository" >&2
    exit 2
    ;;
esac

umask 077
temporary=$(mktemp "${output_abs}.tmp.XXXXXX")
cleanup() { rm -f "$temporary"; }
trap cleanup EXIT

databricks token-management create-obo-token "$application_id" \
  --profile "$admin_profile" \
  --lifetime-seconds 3600 \
  --comment "temporary ABAC system-table verification" \
  --output json >"$temporary"

chmod 600 "$temporary"
mv "$temporary" "$output_abs"
trap - EXIT
printf 'sensitive token response written with mode 600; revoke it after testing: %s\n' "$output_abs"
