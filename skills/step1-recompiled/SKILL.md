# Skill: Execute step 1 (recompiled)

## Purpose

Drive reverse-engineering and recompilation work in `<tool>/recompiled/` with exact-original parity goals.

## Inputs

- `decomp-docs/generic_step1.md`
- `decomp-docs/<tool>_step1.md`
- Tool references (`<tool>/<tool>_decomp_ghidra.c`, `_decomp_retdec.c`, `_objdump.txt`, `_readelf.txt`, `_usage.txt`)

## Procedure

1. Follow bootstrap requirements from generic/tool step docs.
2. Keep reconstruction aligned to likely original C89 structure.
3. Use shared tests across original and recompiled binaries.
4. Capture parity evidence for behavior under change.
5. Record uncertainty and blockers in repository artifacts using `confirmed`, `open`, `blocked`.

## Output

Updated `<tool>/recompiled/` artifacts and refreshed parity evidence consistent with step 1 closeout criteria.
