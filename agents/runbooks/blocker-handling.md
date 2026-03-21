# Runbook: blocker handling

## Goal

Handle unresolved parity or implementation blockers in a recoverable way.

## Procedure

1. Record blocker in touched repository artifact (not detached notes).
2. State parity impact explicitly.
3. Add concrete closure experiment with expected evidence.
4. Mark status as `blocked`; keep unaffected items `confirmed` or `open`.
5. Resume from the closure experiment result and update status deterministically.
6. If code/tests/requirements changed since last capture, refresh stale evidence before moving status to `confirmed`.
