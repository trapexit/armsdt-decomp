# State recovery and evidence freshness

Use this file when resuming work or deciding whether existing evidence can still satisfy closeout criteria.

## Recovery order

1. Read `README.md`, `workflow_manifest.json`, and `workflow_status.md`.
2. Determine the active step from required outputs and closeout status.
3. Validate evidence freshness for claims that gate closeout.
4. Refresh stale evidence before changing status to `confirmed`.

## Deterministic stale-evidence triggers

Treat a previously recorded evidence row as stale if any of the following occurred after the evidence capture:

1. A material code change in covered implementation paths (`recompiled/src/` or `recreated/src/`).
2. A change to test logic, fixtures, or harness behavior used by that evidence.
3. A change to requirement mapping, requirement wording, or must-match classification in the active step artifact/spec.
4. A change to command-line options or defaults that affect the validated behavior.
5. A change to output-generation logic for a compatibility-sensitive artifact.

If none of these triggers occurred, evidence can remain current.

## Refresh protocol

When evidence is stale:

1. Re-run the original command and fixture set.
2. Re-capture stdout/stderr, exit code, and parity result (`cmp` or approved semantic comparison).
3. Update linked evidence IDs in the active artifact.
4. Keep previous stale entries only if they remain useful as historical trace.

## Status transition discipline

- Move to `confirmed` only with current evidence.
- Use `open` when investigation is active and closure experiments are defined.
- Use `blocked` when progress cannot continue and the blocker plus next closure experiment is explicit.

## Minimal resume checklist

1. Select tool and step from repository state.
2. Verify start gates for the selected step.
3. Apply stale-evidence triggers to all closeout-critical claims.
4. Refresh any stale evidence.
5. Update `workflow_status.md` when readiness or blocker state changes.
