# armlib Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `armlib/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlib-step3
  step: 3
  applies_to: armlib
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - armlib/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - armlib/recreated/Makefile
    - armlib/recreated/src/
    - armlib/recreated/tests/
    - armlib/recreated/build/armlib
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

- `armlib/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `armlib/recreated/Makefile`
- `armlib/recreated/src/` modular C11 implementation
- `armlib/recreated/tests/` shared tests that also run against original and recompiled binaries
- `armlib/recreated/build/armlib`

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
- Recreated ALF create/update/list/remove flows validated by three-way tests.
- Deterministic ordering and metadata parity for all required fixture classes.
- Replacement readiness for all original archive workflow paths and edge-case classes.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## armlib-specific focus

Use small explicit modules for archive IO, command dispatch, and diagnostics; lock deterministic archive ordering and metadata writing behavior.

## Tool-specific constraints and priorities

- Keep explicit modules for archive IO, command dispatch, and diagnostics.
- Enforce deterministic member ordering and metadata writes.
- Expand adversarial tests around update/replace edge cases before widening scope.

## Tool-specific examples

- Operation sequences that combine create, add, replace, and remove.
- Archive listings compared for stable ordering and formatting.
- Byte-level checks of produced archive metadata blocks.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `armlib` is complete when:

1. Recreated `armlib` builds warning-clean and executes all original archive workflows and edge-case classes.
2. Three-way tests pass for create/update/list/replace/remove behavior and diagnostics.
3. Parity checks confirm deterministic member ordering and compatibility-sensitive metadata bytes.
4. Replacement validation succeeds for all original archive workflow classes.
5. No externally visible mismatch remains.
