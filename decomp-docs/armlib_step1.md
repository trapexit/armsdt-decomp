# armlib Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `armlib/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlib-step1
  step: 1
  applies_to: armlib
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armlib/armlib
    - armlib/armlib_decomp_ghidra.c
    - armlib/armlib_decomp_retdec.c
    - armlib/armlib_objdump.txt
    - armlib/armlib_readelf.txt
    - armlib/armlib_usage.txt
  must_outputs:
    - armlib/recompiled/Makefile
    - armlib/recompiled/src/
    - armlib/recompiled/tests/
    - armlib/recompiled/build/armlib
  status_values:
    - confirmed
    - open
    - blocked
  closeout_requirements:
    - no externally visible mismatch
    - tests pass with parity evidence
    - unresolved items remain only as blocked with closure experiments
```

## Tool profile

- Directory: `armlib/`
- Tool: ARM Library Manager
- Description: Creates, modifies, and lists ALF library archives.
- Original binary size: 20 KB
- Recompiled priority: 1

## Shared step 1 guidance

Use [generic_step1.md](generic_step1.md) for shared step 1 requirements:
- Required references and inputs
- Required outputs
- Bootstrap-from-Ghidra baseline and initial commit order
- Build and test workflow, including two-way testing
- Analysis workflow, portability rules, source recovery rules, and verification strategy
- Commit and artifact rules

## armlib-specific focus

Prioritize archive member add/remove/replace/list behavior; preserve member ordering and metadata handling in ALF outputs; keep state-machine style traversal intact where refactoring risks behavior drift.

## Tool-specific constraints and priorities

- Prioritize member add/remove/replace/list behavior over low-value paths.
- Preserve deterministic member ordering and archive metadata semantics.
- Keep traversal logic stable until behavior is fully characterized.

## Tool-specific examples

- Replacing duplicate member names with ordering-sensitive updates.
- Create/update cycles that touch timestamp and metadata fields.
- List operations that expose ordering and formatting rules.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 1 completion criteria

Step 1 for `armlib` is complete when:

1. Recompiled `armlib` builds repeatably and performs core archive operations.
2. Shared tests match original behavior for member ordering, replacement, and listing.
3. Parity checks cover ALF archive bytes and compatibility-sensitive metadata fields.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original archive features are excluded.
