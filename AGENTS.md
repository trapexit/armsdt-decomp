# Agent entrypoint

This repository supports generic coding-agent workflows.

Before doing any implementation work, read:

1. `decomp-docs/README.md` (canonical human workflow entrypoint)
2. `decomp-docs/workflow_manifest.json` (canonical machine routing)
3. `decomp-docs/execution_index.md` (quick execution routing)
4. `decomp-docs/workflow_status.md` (current readiness and blockers)
5. `decomp-docs/state_recovery.md` (evidence freshness and resume rules)
6. `decomp-docs/workflow_diagram.md` (state and routing diagram)
7. `HOW_TO_PROCESS_DECOMP_C.md` (repository overview only)

## Authority order

If instructions conflict, use this order:

1. Original binary runtime behavior
2. `decomp-docs/README.md`
3. `decomp-docs/workflow_manifest.json`
4. `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, `decomp-docs/generic_step3.md`
5. Per-tool `decomp-docs/*_step*.md`
6. `HOW_TO_PROCESS_DECOMP_C.md`

## Universal agent contract

1. Recompute the next ready tool and step from repository state.
2. Read the matching generic step doc and matching per-tool step doc.
3. Work only in the selected tool directory and required inputs for that step.
4. Treat missing parity evidence as incomplete, even when output files exist.
5. Apply deterministic stale-evidence checks from `decomp-docs/state_recovery.md`.
6. Use status terms consistently: `confirmed`, `open`, `blocked`.
7. Keep blocker notes and closure experiments in touched repository artifacts.

## Agent operations layout

- `agents/README.md`: cross-agent operations overview.
- `agents/runbooks/`: repeatable execution procedures (`session-setup.md`, `select-next-step.md`, `blocker-handling.md`, `migration-map.md`).
- `skills/`: reusable workflow skills.
- `prompts/templates/`: reusable prompt templates.

These files orchestrate work; they do not replace canonical workflow docs in `decomp-docs/`.
