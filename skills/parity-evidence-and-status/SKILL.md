# Skill: Parity evidence and status discipline

## Purpose

Standardize evidence capture and status language for all workflow steps.

## Inputs

- Step-specific generic docs in `decomp-docs/`
- Active tool artifacts under `<tool>/recompiled/`, `<tool>/technical_specification.md`, `<tool>/recreated/`

## Procedure

1. Capture command, fixture identity, stdout/stderr, and exit code for runtime claims.
2. Capture byte-level parity evidence (`cmp`) where required.
3. Capture static references (source path and line ranges) for non-obvious logic.
4. Resolve source conflicts using canonical precedence; record rationale.
5. Apply stale-evidence triggers before accepting prior captures as current.
6. Use only `confirmed`, `open`, `blocked` in inventories/checklists.

## Output

Repository artifacts with reproducible parity evidence and consistent status language across steps.
