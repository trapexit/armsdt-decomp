# Recompiling and Recreating from Decompiled Inputs

This file is the repository-level overview for the ARM SDT replacement effort. Decompiled C, disassembly, and metadata captures are step 1 reference inputs, not the end goal. The actual deliverables are compilable `recompiled/` reconstructions that aim to preserve likely original C89 source structure, exact technical specifications, and clean-room `recreated/` implementations. For autonomous execution, start with [decomp-docs/README.md](decomp-docs/README.md) and then load [decomp-docs/workflow_manifest.json](decomp-docs/workflow_manifest.json). Detailed shared rules now live in [decomp-docs/generic_step1.md](decomp-docs/generic_step1.md), [decomp-docs/generic_step2.md](decomp-docs/generic_step2.md), and [decomp-docs/generic_step3.md](decomp-docs/generic_step3.md).

## Canonical entrypoints

- Human-readable workflow entrypoint: [decomp-docs/README.md](decomp-docs/README.md)
- Machine-readable workflow routing: [decomp-docs/workflow_manifest.json](decomp-docs/workflow_manifest.json)
- Execution routing quick index: [decomp-docs/execution_index.md](decomp-docs/execution_index.md)
- Workflow status surface: [decomp-docs/workflow_status.md](decomp-docs/workflow_status.md)
- Agent-oriented entrypoint: [AGENTS.md](AGENTS.md)
- Doc validator: `python3 decomp-docs/validate_docs.py`
- Shared step guidance: `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, `decomp-docs/generic_step3.md`
- Reusable workflow templates: `decomp-docs/templates/README.md`

## Agent operations layer

- `AGENTS.md` provides a cross-agent startup contract and points to canonical workflow docs.
- `agents/runbooks/` contains repeatable procedures for session setup, step selection, blocker handling, and migration.
- `skills/` contains reusable step-oriented skills (`SKILL.md`) for routing, step execution, and parity/status discipline.
- `prompts/templates/` contains reusable startup, handoff, and blocker triage prompt templates.

These agent-operation files orchestrate execution and must not replace the canonical authority in `decomp-docs/`.

## Tools

| Directory | Tool | Description |
| --- | --- | --- |
| `armlib/` | ARM Library Manager | Creates, modifies, and lists ALF library archives |
| `decaof/` | AOF Decoder v4.20 | Dumps and disassembles AOF/ALF chunk files |
| `armlink/` | ARM Linker v5.20 | Links AOF objects into AIF executables |
| `armasm/` | ARM AOF Macro Assembler v2.50 | Assembles ARM source into AOF objects |
| `armcc/` | ARM C Compiler | Compiles C source into AOF objects |
| `armcpp/` | ARM C++ Compiler | Compiles C++ source into AOF objects |

All tools are from ARM SDT 2.51, targeting ARMv3 (ARM60 CPU) with all big-endian AOF, AIF, and ALF behavior present in the original binaries.

## Three-step workflow

| Step | Goal | Primary output | Shared doc |
| --- | --- | --- | --- |
| 1 | Reverse engineer and recompile the original logic in C89 while preserving likely original source structure rather than redesigning it. | `<tool>/recompiled/` | [decomp-docs/generic_step1.md](decomp-docs/generic_step1.md) |
| 2 | Write the exact-original technical behavior specification. | `<tool>/technical_specification.md` | [decomp-docs/generic_step2.md](decomp-docs/generic_step2.md) |
| 3 | Create the clean-room C11 recreation. | `<tool>/recreated/` | [decomp-docs/generic_step3.md](decomp-docs/generic_step3.md) |

Project-wide sequencing rules:

1. Recompiled work is always the first implementation priority for a tool.
2. Step 2 is mandatory between recompiled and recreated work.
3. Recreated work does not begin until step 1 outputs exist and `<tool>/technical_specification.md` is current.
4. Prefer finishing near-complete work before starting another tool.

## Shared workflow documents

| Step | Shared doc | Purpose |
| --- | --- | --- |
| Step 1 | [decomp-docs/generic_step1.md](decomp-docs/generic_step1.md) | Shared reverse-engineering, recompilation, testing, portability, and parity rules. |
| Step 2 | [decomp-docs/generic_step2.md](decomp-docs/generic_step2.md) | Shared technical-specification, evidence, traceability, and uncertainty rules. |
| Step 3 | [decomp-docs/generic_step3.md](decomp-docs/generic_step3.md) | Shared clean-room recreation, three-way validation, and replacement rules. |

## Operational status tracking

- Maintain `decomp-docs/workflow_status.md` as the concise, repository-visible matrix for per-tool step readiness, baseline coverage, and known blockers.
- Keep status values aligned to `confirmed`, `open`, and `blocked`.
- When readiness or blocker state changes, update `workflow_status.md` in the same batch as the related workflow artifact change.

## Tool order and step docs

| Tool | Role | Recompiled priority | Recreated priority | Step 1 | Step 2 | Step 3 | Step 2 spec path |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `armlib` | ARM Library Manager | 1 | 7 | [step 1](decomp-docs/armlib_step1.md) | [step 2](decomp-docs/armlib_step2.md) | [step 3](decomp-docs/armlib_step3.md) | `armlib/technical_specification.md` |
| `decaof` | AOF Decoder v4.20 | 2 | 8 | [step 1](decomp-docs/decaof_step1.md) | [step 2](decomp-docs/decaof_step2.md) | [step 3](decomp-docs/decaof_step3.md) | `decaof/technical_specification.md` |
| `armlink` | ARM Linker v5.20 | 3 | 9 | [step 1](decomp-docs/armlink_step1.md) | [step 2](decomp-docs/armlink_step2.md) | [step 3](decomp-docs/armlink_step3.md) | `armlink/technical_specification.md` |
| `armasm` | ARM AOF Macro Assembler v2.50 | 4 | 10 | [step 1](decomp-docs/armasm_step1.md) | [step 2](decomp-docs/armasm_step2.md) | [step 3](decomp-docs/armasm_step3.md) | `armasm/technical_specification.md` |
| `armcc` | ARM C Compiler | 5 | 11 | [step 1](decomp-docs/armcc_step1.md) | [step 2](decomp-docs/armcc_step2.md) | [step 3](decomp-docs/armcc_step3.md) | `armcc/technical_specification.md` |
| `armcpp` | ARM C++ Compiler | 6 | 12 | [step 1](decomp-docs/armcpp_step1.md) | [step 2](decomp-docs/armcpp_step2.md) | [step 3](decomp-docs/armcpp_step3.md) | `armcpp/technical_specification.md` |

## Authority model

When workflow documents conflict, use this order:

1. Original binary runtime behavior.
2. `decomp-docs/README.md`
3. `decomp-docs/workflow_manifest.json`
4. `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, `decomp-docs/generic_step3.md`
5. Per-tool step docs
6. This overview file

## Independent agent rules

- Recompute the next action from repository state rather than from prior chat context.
- Use the manifest to pick the first ready tool and step in priority order.
- Treat missing parity evidence as incomplete work even when output files already exist.
- Keep blocker notes and closure experiments in the touched workflow artifact, not in detached notes.
- After each material implementation change, make an ASCII-only git commit that summarizes the change.
- For touched implementation `.c` files under `recompiled/src/` or `recreated/src/`, keep recoverable work state in an ASCII `HISTORY:` block plus current status notes; the shared step docs define the exact format.
- Keep this file high-level; detailed shared instructions belong in the generic step docs and tool-specific instructions belong in the per-tool step docs.

## Validation and maintenance

Run this after editing workflow docs:

```bash
python3 decomp-docs/validate_docs.py
```

Keep the step 2 output path stable at `<tool>/technical_specification.md` so agents can route from step 2 into step 3 without guessing.
