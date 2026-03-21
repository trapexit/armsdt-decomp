# Skills index

Skills are reusable, workflow-scoped instructions for recurring operations in this repository.

They are orchestration helpers and must always defer to canonical workflow authority:

1. `decomp-docs/README.md`
2. `decomp-docs/workflow_manifest.json`
3. `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, `decomp-docs/generic_step3.md`
4. Per-tool `decomp-docs/*_step*.md`

## Available skills

- `select-next-ready-step/`: choose tool + step from repo state.
- `step1-recompiled/`: execute and close step 1 work.
- `step2-specification/`: execute and close step 2 specification work.
- `step3-recreated/`: execute and close step 3 recreation work.
- `parity-evidence-and-status/`: collect parity evidence and maintain status vocabulary.
