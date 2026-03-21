# Skill: Execute step 3 (recreated)

## Purpose

Implement clean-room C11 recreation in `<tool>/recreated/` with exact-original externally visible behavior.

## Inputs

- `decomp-docs/generic_step3.md`
- `decomp-docs/<tool>_step3.md`
- `<tool>/technical_specification.md`
- Step 1 test harness and fixtures

## Procedure

1. Verify step 1 and step 2 start gates are satisfied.
2. Implement modular recreated code without copying recompiled implementation code.
3. Run the shared three-way harness across original, recompiled, recreated binaries.
4. Refresh parity evidence for compatibility-sensitive outputs.
5. Track unresolved differences as explicit blockers with closure experiments.

## Output

Updated `<tool>/recreated/` implementation and parity evidence satisfying step 3 closeout requirements.
