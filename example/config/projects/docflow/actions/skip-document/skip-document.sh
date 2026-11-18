#!/usr/bin/env bash
# Example action script; "docflowctl" is a placeholder CLI (see requeue-job.sh).
#
# Called by dutydesk-act with validated arguments: --job-id N --document-id doc-…
set -euo pipefail

[[ $# -eq 4 && $1 == --job-id && $3 == --document-id ]] || {
  echo "usage: skip-document.sh --job-id N --document-id ID" >&2
  exit 2
}
job_id=$2
document_id=$4

docflowctl documents quarantine --job "$job_id" --id "$document_id" --reason dutydesk
docflowctl jobs show --id "$job_id" --fields id,status,processed_count,updated_at
