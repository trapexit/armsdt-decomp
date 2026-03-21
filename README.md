# decomp-docs

Repository for reconstructing ARM SDT toolchain components from decompiled inputs into:

1) faithful C99 `recompiled/` implementations
2) exact behavior specifications
3) clean-room C11 `recreated/` implementations

## Start here

Use these entrypoints in order:

1. [decomp-docs/README.md](decomp-docs/README.md) (canonical human workflow)
2. [decomp-docs/workflow_manifest.json](decomp-docs/workflow_manifest.json) (canonical machine routing)
3. [decomp-docs/execution_index.md](decomp-docs/execution_index.md) (quick execution routing)
4. [decomp-docs/workflow_status.md](decomp-docs/workflow_status.md) (current readiness/blockers)
5. [decomp-docs/state_recovery.md](decomp-docs/state_recovery.md) (evidence freshness and resume rules)
6. [decomp-docs/workflow_diagram.md](decomp-docs/workflow_diagram.md) (state and routing diagram)
7. [HOW_TO_PROCESS_DECOMP_C.md](HOW_TO_PROCESS_DECOMP_C.md) (repository overview)
8. [AGENTS.md](AGENTS.md) (agent startup contract)

## Tool targets

The primary SDT tools in scope are:

- `armlib/` (ARM Library Manager)
- `decaof/` (AOF Decoder)
- `armlink/` (ARM Linker)
- `armasm/` (ARM Assembler)
- `armcc/` (ARM C Compiler)
- `armcpp/` (ARM C++ Compiler)

Each tool follows the same three-step lifecycle:

1. Step 1: build/close `recompiled/`
2. Step 2: produce `<tool>/technical_specification.md`
3. Step 3: build/close `recreated/`

## Repository layout

| Path | Purpose |
| --- | --- |
| `decomp-docs/` | Canonical workflow docs, manifests, status, and templates |
| `docs/` | ARM/AIF/AOF/ALF and related reference material |
| `agents/` | Reusable runbooks for agent execution flow |
| `skills/` | Reusable workflow skills |
| `prompts/` | Prompt templates and shared prompt assets |
| `3do-devkit/` | Embedded 3DO development kit resources |

## Validation

When editing workflow documents, run:

```bash
python3 decomp-docs/validate_docs.py
```
