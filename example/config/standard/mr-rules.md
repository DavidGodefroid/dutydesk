# Merge request rules

These rules apply to every merge request DutyDesk opens on a project repository. A project may
replace them with its own `mr-rules.md`.

1. **One cause, one merge request.** Do not bundle unrelated fixes, refactoring or formatting.
   If a merge request is already open for this incident family, do not open another.
2. **The smallest change that fixes the root cause.** No workaround in code for what an action
   already handles, no dependency upgrade, no change to CI, deployment or secrets.
3. **Tests.** Add or adjust a test that fails without the fix, when the code has tests nearby.
   You do not run the suite; the merge request's CI decides.
4. **Draft unless confidence is high.** A merge request is opened as a draft whenever the
   verdict's confidence is not `high`.
5. **Label** `dutydesk`. DutyDesk never merges; a human reviews and merges.
6. **No secret and no personal data** in the diff, the title or the description. Quote only
   masked extracts.

## Title

`fix(<area>): <what changes>`, one line, 72 characters at most, no incident number.

## Description template

```markdown
## Incident
<incident id>, opened <date and time>, source <check or alert>.

## Symptoms
What was observed in production, since when, how many items.

## Root cause
The defect, and why it produces the symptoms.

## Evidence
The queries and masked extracts that demonstrate the cause.

## Fix
What this change does, and why it is the smallest sufficient change.

## Tests
Tests added or changed, and what they prove. "None" with the reason if there are none.

## Risk
What could go wrong, what else uses the changed code.

## Rollback
How to undo it (revert, flag, data to restore if any).
```
