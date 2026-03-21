# Agent workflow entrypoint for `decomp-docs`

This file is the canonical human-readable starting point for autonomous coding agents working in this repository. Read this file first, then use [workflow_manifest.json](workflow_manifest.json) for machine-readable routing. Treat [../HOW_TO_PROCESS_DECOMP_C.md](../HOW_TO_PROCESS_DECOMP_C.md) as repository-level overview only. Use [execution_index.md](execution_index.md) for quick operator routing and [workflow_status.md](workflow_status.md) for repository-state progress tracking. This repository uses decompiled artifacts as reverse-engineering inputs; its deliverables are compilable `recompiled/` reconstructions that aim to preserve likely original C89 source structure, exact behavior specifications, and clean-room `recreated/` implementations.

## What this doc set covers

- Step 1: start `<tool>/recompiled/` by copying the tool's Ghidra decompiled C file, commit that baseline, then reverse engineer and recompile it into a faithful C89 reconstruction that preserves likely original function boundaries and structure rather than materially redesigning the code.
- Step 2: write the exact-original behavior specification at `<tool>/technical_specification.md`.
- Step 3: build a clean-room recreation in `<tool>/recreated/` using C11.
- Default success bar: no externally visible mismatch versus the original binary.

## Canonical authority order

If two docs appear to disagree, resolve the conflict in this order:

1. Original binary runtime behavior.
2. `decomp-docs/README.md` for navigation and sequencing.
3. `decomp-docs/workflow_manifest.json` for machine-readable routing, prerequisites, and resume signals.
4. `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, and `decomp-docs/generic_step3.md` for shared step rules.
5. Per-tool `*_step1.md`, `*_step2.md`, and `*_step3.md` docs for tool-specific rules.
6. `HOW_TO_PROCESS_DECOMP_C.md` for project overview only.
7. Any other prose or notes as background, not authority.

## Cold-start checklist

1. Read this file.
2. Read [workflow_manifest.json](workflow_manifest.json).
3. Read [execution_index.md](execution_index.md), [workflow_status.md](workflow_status.md), and [state_recovery.md](state_recovery.md) before selecting work.
4. Choose the first ready tool and step in priority order.
5. Read the matching generic step doc plus the matching tool-specific step doc.
6. Inspect only the referenced tool directory and required inputs for the selected step.
7. Work until the selected step meets its closeout criteria or the remaining blocker is explicit and reproducible.

## Execution index and status surfaces

- [execution_index.md](execution_index.md): concise entrypoint for "start", "resume", "blocker", and "closeout" routes.
- [workflow_status.md](workflow_status.md): baseline and rolling status matrix for tool/step readiness and blockers.
- [workflow_diagram.md](workflow_diagram.md): compact state and routing diagram.
- [state_recovery.md](state_recovery.md): deterministic evidence-freshness and resume rules.
- [templates/README.md](templates/README.md): reusable templates for evidence, traceability, parity summaries, and closure experiments.
- [worked_examples.md](worked_examples.md): compact examples for closeout-ready artifacts.
- [glossary.md](glossary.md): shared terms and compatibility vocabulary.

Keep `workflow_status.md` current when step readiness, blockers, or artifact completeness changes.

## How to choose the next tool and step

| Step | Ready when | Canonical output |
| --- | --- | --- |
| 1 | Any required output under `<tool>/recompiled/` is missing, or parity evidence and closeout requirements are incomplete. | `<tool>/recompiled/Makefile`, `<tool>/recompiled/src/`, `<tool>/recompiled/tests/`, `<tool>/recompiled/build/<tool>` |
| 2 | Step 1 outputs exist and `<tool>/technical_specification.md` is missing, or the spec lacks traceability, evidence, or complete feature inventory. | `<tool>/technical_specification.md` |
| 3 | Step 2 spec exists and required outputs under `<tool>/recreated/` are missing, or three-way parity evidence and closeout requirements are incomplete. | `<tool>/recreated/Makefile`, `<tool>/recreated/src/`, `<tool>/recreated/tests/`, `<tool>/recreated/build/<tool>` |

Additional routing rules:

- Prefer finishing near-complete work before opening a new front.
- Otherwise choose the first ready tool in this priority order: `armlib`, `decaof`, `armlink`, `armasm`, `armcc`, `armcpp`.
- Never start step 3 for a tool until step 1 outputs exist and `<tool>/technical_specification.md` is current.
- If a step has required outputs but missing parity evidence, treat the step as still active.

### Near-complete decision checklist

Treat a candidate as near-complete only when all checks are true:

1. All required outputs for that step already exist.
2. Remaining work is limited to evidence refresh, focused parity checks, or narrowly scoped fixes.
3. No unresolved hard-stop issue remains (`blocked` without an executable closure experiment fails this check).
4. Remaining work is expected to fit in one material batch.
5. Finishing this candidate does not violate any step start gate.

If multiple candidates are ready, prefer the one that passes all checks above. If none pass all checks, fall back to the repository priority order.

## Shared workflow documents

| Step | Shared doc | Purpose |
| --- | --- | --- |
| Step 1 | [generic_step1.md](generic_step1.md) | Shared reverse-engineering, recompilation, testing, portability, and parity rules. |
| Step 2 | [generic_step2.md](generic_step2.md) | Shared technical-specification, evidence, traceability, and uncertainty rules. |
| Step 3 | [generic_step3.md](generic_step3.md) | Shared clean-room recreation, three-way validation, and replacement rules. |

## Tool priority and doc map

| Tool | Role | Recompiled priority | Recreated priority | Step 1 | Step 2 | Step 3 | Step 2 spec path |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `armlib` | ARM Library Manager | 1 | 7 | [armlib_step1.md](armlib_step1.md) | [armlib_step2.md](armlib_step2.md) | [armlib_step3.md](armlib_step3.md) | `armlib/technical_specification.md` |
| `decaof` | AOF Decoder v4.20 | 2 | 8 | [decaof_step1.md](decaof_step1.md) | [decaof_step2.md](decaof_step2.md) | [decaof_step3.md](decaof_step3.md) | `decaof/technical_specification.md` |
| `armlink` | ARM Linker v5.20 | 3 | 9 | [armlink_step1.md](armlink_step1.md) | [armlink_step2.md](armlink_step2.md) | [armlink_step3.md](armlink_step3.md) | `armlink/technical_specification.md` |
| `armasm` | ARM AOF Macro Assembler v2.50 | 4 | 10 | [armasm_step1.md](armasm_step1.md) | [armasm_step2.md](armasm_step2.md) | [armasm_step3.md](armasm_step3.md) | `armasm/technical_specification.md` |
| `armcc` | ARM C Compiler | 5 | 11 | [armcc_step1.md](armcc_step1.md) | [armcc_step2.md](armcc_step2.md) | [armcc_step3.md](armcc_step3.md) | `armcc/technical_specification.md` |
| `armcpp` | ARM C++ Compiler | 6 | 12 | [armcpp_step1.md](armcpp_step1.md) | [armcpp_step2.md](armcpp_step2.md) | [armcpp_step3.md](armcpp_step3.md) | `armcpp/technical_specification.md` |

## Resume protocol

- Recompute state from files and docs, not from conversation memory.
- Update `workflow_status.md` whenever tool/step readiness or blocker state changes.
- Treat a step as incomplete if required outputs exist but closeout evidence is missing or stale.
- Apply [state_recovery.md](state_recovery.md) before trusting previously captured parity evidence.
- Keep status language aligned to `confirmed`, `open`, and `blocked`.
- When blocked, leave the blocker, parity impact, and closure experiment in the touched step artifact or technical spec rather than in detached notes.
- After each material implementation change, create a git commit with an ASCII-only summary before starting the next material batch.
- For touched implementation `.c` files under `<tool>/recompiled/src/` or `<tool>/recreated/src/`, maintain an ASCII `HISTORY:` block plus current state notes so the next agent can recover progress from repository state alone.
- Do not rely on scratch notes as the sole source of state; the repository should be enough to recover the next action.

## Step 2 specification scaffold

Use [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md) as the default starting structure for `<tool>/technical_specification.md`, then apply tool-specific constraints from the matching `*_step2.md`.

## Validation

Use these commands after changing workflow docs:

```bash
python3 decomp-docs/validate_docs.py
git --no-pager diff --stat
```

The validator checks the canonical entrypoint, manifest, relative links, required sections, the explicit step 2 specification path contract, and the commit/history guidance anchors that agents rely on.
