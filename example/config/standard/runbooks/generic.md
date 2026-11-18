---
id: generic
applies_to: ["*"]
recheck_default: 30m
max_runs: 2
---
# Generic runbook

No specific runbook exists for this source. You have **no action** available.

## What to do

1. Confirm the signal is still true with a read through the locks.
2. Investigate read-only, following the standard method: timeline, scope (one item or many),
   what changed just before, the most likely cause.
3. Do not attempt any change. Do not look for a way to act.

## Verdict

- `escalate`, with your diagnosis: what is broken, since when, how wide, what you ruled out,
  what you would look at next. This is the normal outcome of this runbook.
- `resolved` only if you verified that the condition has disappeared by itself.
- `recheck` at most once, when the signal is very recent and may still clear.
- `blocked` if one precise action would fix it: describe it in `missing_action`.

If this source deserves its own runbook, propose one (`improvement`).
