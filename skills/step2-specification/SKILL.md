# Skill: Execute step 2 (technical specification)

## Purpose

Produce and maintain `<tool>/technical_specification.md` as an evidence-backed exact behavior contract.

## Inputs

- `decomp-docs/generic_step2.md`
- `decomp-docs/<tool>_step2.md`
- Step 1 outputs and parity captures

## Procedure

1. Build complete feature inventory coverage for original behavior.
2. Start from `decomp-docs/templates/step2_specification_scaffold.md`.
3. Link each requirement to runtime/static evidence.
4. Mark unresolved items explicitly with closure experiments.
5. Keep status vocabulary aligned to `confirmed`, `open`, `blocked`.
6. Ensure spec content supports direct step 3 implementation.

## Output

Updated `<tool>/technical_specification.md` with traceability, evidence, inventory status, and clear closure state.
