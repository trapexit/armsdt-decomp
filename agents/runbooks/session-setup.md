# Runbook: session setup

## Goal

Start any coding-agent session with canonical workflow behavior and repository-state recoverability.

## Setup sequence

1. Open repository root and read `AGENTS.md`.
2. Load canonical routing docs:
   - `decomp-docs/README.md`
   - `decomp-docs/workflow_manifest.json`
   - `decomp-docs/execution_index.md`
   - `decomp-docs/workflow_status.md`
   - `decomp-docs/state_recovery.md`
   - `decomp-docs/workflow_diagram.md`
   - `HOW_TO_PROCESS_DECOMP_C.md` (overview only)
3. Load skills index and required skill for the task:
   - `skills/README.md`
   - one or more `skills/*/SKILL.md`
4. Use prompt templates from `prompts/templates/` when resuming, handing off, or triaging blockers.

## Session contract

1. Recompute next ready tool/step from repository state.
2. Use canonical authority order when sources conflict.
3. Apply stale-evidence triggers before accepting prior closeout evidence.
4. Keep status language to `confirmed`, `open`, `blocked`.
5. Keep blockers and closure experiments in repository artifacts.
6. Avoid creating duplicate authority docs that diverge from `decomp-docs/*`.
