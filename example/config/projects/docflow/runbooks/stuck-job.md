---
id: stuck-job
applies_to: [stuck-job]
actions: [requeue-job, skip-document, reset-job-status]
action_instance: docflow-stuck-job        # lockssh profile, run = "auto": requeue-job, skip-document
ask_instance: docflow-stuck-job-ask       # lockssh profile, run = "ask": reset-job-status
recheck_default: 20m
max_runs: 5
---
# Stuck job

A job has had the status `running` for more than 30 minutes.

## What is normal

- Large batches (`job_kind = 'bulk-import'`) legitimately run for up to 2 hours.
- A job is **progressing** when its `processed_count` or `updated_at` moved in the last
  10 minutes. A slow job that progresses is not an incident.
- Right after a deployment, workers restart and jobs resume within a few minutes.

## How to investigate

1. Read the job (SQL lock): `status`, `job_kind`, `started_at`, `updated_at`, `processed_count`,
   `total_count`, `worker_id`, `current_document_id`.
2. Read it again one or two minutes later. Did `processed_count` or `updated_at` move?
3. Read the logs of this job (log lock), filtered on its job id, over the last 30 minutes:
   last line, repeated errors, the document being processed.
4. Is the worker alive? Look for recent log lines of `worker_id` for any job.
5. Are other jobs stuck too? Count jobs in `running` for more than 30 minutes. Several stuck jobs
   on different workers point to a shared cause (database, storage, upstream): escalate.

## Deciding

| What you see | What to do |
|---|---|
| The job progresses | `recheck` in 20 minutes. No action. |
| A `bulk-import` younger than 2 hours, no error in the logs | `recheck` in 30 minutes. |
| The worker is gone (no log line for 10 minutes), the job no longer progresses | `requeue-job`. |
| The same document fails in a loop (same error, same `current_document_id`, 3 times or more) | `skip-document` for that document, then `recheck` in 10 minutes. If the error is a defect in the code, also propose a merge request. |
| The job is finished according to the logs but its status is still `running` | `reset-job-status` (green light). |
| Several jobs are stuck, or you cannot tell | `escalate` with your diagnosis. |

## Actions

- **`requeue-job --job-id N`** (auto). Puts the job back in the queue; a healthy worker resumes
  it from its last checkpoint. Only when the job does not progress **and** its worker is gone.
  Never twice for the same job in one incident: if it gets stuck again, escalate.
- **`skip-document --job-id N --document-id doc-…`** (auto). Moves one document of the job to the
  quarantine list so the job can continue. Only for a document that failed 3 times or more with
  the same error. Name the document and the error in your verdict.
- **`reset-job-status --job-id N --status done|failed|queued`** (green light). Rewrites the status
  of a job that is no longer running. A human decides: you will receive a pending ticket; end the
  pass with outcome `green_light` and the ticket.

After an action, verify with a read (status, `updated_at`), or answer `recheck` in 10 minutes
when the effect needs time. Do not answer `resolved` on the action's output alone.
