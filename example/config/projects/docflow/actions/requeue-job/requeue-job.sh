#!/usr/bin/env bash
# Example action script. "docflowctl" is a placeholder for the project's own
# admin CLI; its credentials come from the action's env file on the action
# host (DOCFLOWCTL_TOKEN), never from the agent.
#
# Called by dutydesk-act with validated arguments: --job-id N
set -euo pipefail

[[ $# -eq 2 && $1 == --job-id ]] || { echo "usage: requeue-job.sh --job-id N" >&2; exit 2; }
job_id=$2

docflowctl jobs requeue --id "$job_id" --reason dutydesk
docflowctl jobs show --id "$job_id" --fields id,status,updated_at
