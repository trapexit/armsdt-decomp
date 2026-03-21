# Execution index for reverse-engineering workflow

Use this file as the shortest route to the next correct action.

## Canonical authority and routing

1. [README.md](README.md)
2. [workflow_manifest.json](workflow_manifest.json)
3. [generic_step1.md](generic_step1.md), [generic_step2.md](generic_step2.md), [generic_step3.md](generic_step3.md)
4. Per-tool step docs (`*_step1.md`, `*_step2.md`, `*_step3.md`)
5. [../HOW_TO_PROCESS_DECOMP_C.md](../HOW_TO_PROCESS_DECOMP_C.md) (overview only)

## Quick routes

### Start or resume work

1. Read [README.md](README.md).
2. Read [workflow_manifest.json](workflow_manifest.json).
3. Read [workflow_status.md](workflow_status.md) for current readiness and blockers.
4. Read [state_recovery.md](state_recovery.md) before trusting prior evidence.
5. Use [workflow_diagram.md](workflow_diagram.md) if selection/readiness is ambiguous.
6. Pick the first ready tool and step using manifest priority and readiness rules.
7. Load the matching generic step doc and matching per-tool step doc.

### Handle blockers

1. Keep blocker details in touched repository artifacts.
2. Record parity impact and closure experiment.
3. Keep status language to `confirmed`, `open`, `blocked`.
4. Reflect state in [workflow_status.md](workflow_status.md).

### Update evidence and traceability

1. Use templates in [templates/README.md](templates/README.md).
2. Ensure runtime/static evidence references are reproducible.
3. Keep requirement/evidence/test linkage explicit in step artifacts.
4. When step 2 is active, start from [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md).

### Decide "near-complete" priority

1. Confirm all required outputs already exist.
2. Confirm remaining work is only evidence refresh, focused parity checks, or narrowly scoped fixes.
3. Confirm no unresolved hard-stop issue remains.
4. If all checks pass, finish this candidate first; otherwise use standard tool priority.

### Close out a batch

1. Verify closeout criteria in the active step doc.
2. Update [workflow_status.md](workflow_status.md).
3. Run `python3 decomp-docs/validate_docs.py` after workflow doc edits.

## Shared templates

- [templates/README.md](templates/README.md)
- [templates/step1_evidence_log.md](templates/step1_evidence_log.md)
- [templates/step2_traceability_matrix.md](templates/step2_traceability_matrix.md)
- [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md)
- [templates/step3_parity_summary.md](templates/step3_parity_summary.md)
- [templates/blocker_closure_record.md](templates/blocker_closure_record.md)
