#!/usr/bin/env bash
# Example action script; "docflowctl" is a placeholder CLI (see requeue-job.sh).
#
# Called by dutydesk-act with validated arguments: --job-id N --status queued|done|failed
set -euo pipefail

[[ $# -eq 4 && $1 == --job-id && $3 == --status ]] || {
  echo "usage: reset-job-status.sh --job-id N --status STATUS" >&2
  exit 2
}
job_id=$2
status=$4

docflowctl jobs set-status --id "$job_id" --status "$status" --reason dutydesk
docflowctl jobs show --id "$job_id" --fields id,status,updated_at
