# armlink Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `armlink/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlink-step3
  step: 3
  applies_to: armlink
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - armlink/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - armlink/recreated/Makefile
    - armlink/recreated/src/
    - armlink/recreated/tests/
    - armlink/recreated/build/armlink
  status_values:
    - confirmed
    - open
    - blocked
  closeout_requirements:
    - no externally visible mismatch
    - tests pass with parity evidence
    - unresolved items remain only as blocked with closure experiments
```

## Inputs

- `armlink/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `armlink/recreated/Makefile`
- `armlink/recreated/src/` modular C11 implementation
- `armlink/recreated/tests/` shared tests that also run against original and recompiled binaries
- `armlink/recreated/build/armlink`

## Shared step 3 guidance

Use [generic_step3.md](generic_step3.md) for shared step 3 requirements:
- Start gate and authority order
- Clean-room implementation rules
- Recommended project structure and module boundaries
- Build and testing requirements
- Verification strategy and unresolved-difference handling
- Integration expectations and generic completion checks
- Three-way harness protocol and scenario artifact requirements

### Scope card (agent execution)

**In scope**
- Recreated modular linker stages with preserved stage contracts.
- Three-way validation for symbol resolution, relocations, layout, and diagnostics.
- Replacement readiness for all original link workflow paths and edge-case classes.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## armlink-specific focus

Implement explicit pipeline stages: load, resolve, relocate, layout, emit; keep invariants and deterministic output rules encoded in tests.

## Tool-specific constraints and priorities

- Implement explicit pipeline modules for load, resolve, relocate, layout, and emit.
- Encode layout and relocation invariants directly in tests.
- Lock deterministic output classes while maintaining full original-feature parity.

## Tool-specific examples

- Link scenarios with competing symbols and relocation conflicts.
- Byte-level checks for headers, section order, and padding.
- Diagnostics parity checks when multiple link failures are present.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `armlink` is complete when:

1. Recreated `armlink` builds warning-clean and performs all original link workflows and edge-case classes.
2. Three-way tests pass for stage contracts, symbol resolution, relocations, and diagnostics.
3. Parity checks validate headers, section order, padding, and relocation content.
4. Replacement validation succeeds for all original link workflow classes.
5. No externally visible mismatch remains.
