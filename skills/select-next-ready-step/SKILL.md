# Skill: Select next ready tool and step

## Purpose

Choose the next actionable tool/step from repository state with no chat-memory dependence.

## Inputs

- `decomp-docs/README.md`
- `decomp-docs/workflow_manifest.json`
- Tool directories (`armlib/`, `decaof/`, `armlink/`, `armasm/`, `armcc/`, `armcpp/`)

## Procedure

1. Read canonical routing docs and authority order.
2. Apply near-complete checklist criteria before opening new fronts.
3. Otherwise evaluate tools in priority order from the manifest.
4. Apply readiness checks:
   - Step 1: required `recompiled/` outputs or parity evidence missing.
   - Step 2: step 1 outputs exist, but `technical_specification.md` missing/incomplete.
   - Step 3: step 2 spec exists, but `recreated/` outputs or parity evidence missing.
5. Report selected tool, step, and explicit file evidence.

## Output

A deterministic selection statement: `<tool> step <n>` with rationale tied to repository artifacts.
