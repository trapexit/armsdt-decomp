# armcc Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `armcc/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcc-step3
  step: 3
  applies_to: armcc
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - armcc/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - armcc/recreated/Makefile
    - armcc/recreated/src/
    - armcc/recreated/tests/
    - armcc/recreated/build/armcc
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

- `armcc/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `armcc/recreated/Makefile`
- `armcc/recreated/src/` modular C11 implementation
- `armcc/recreated/tests/` shared tests that also run against original and recompiled binaries
- `armcc/recreated/build/armcc`

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
- Recreated modular compile pipeline for all original end-to-end workflows.
- Three-way parity for driver behavior, stage transitions, diagnostics, and key output classes.
- Replacement readiness for all original compile workflow paths and edge-case classes.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## armcc-specific focus

Recreate with modular boundaries between driver, front end, backend, and emitter; lock behavioral parity for core compile workflows before expanding coverage.

## Tool-specific constraints and priorities

- Implement clear modules for driver, front end, backend, and emitter.
- Lock core compile-workflow parity before extending marginal options.
- Keep deterministic diagnostics and output metadata in scope.

## Tool-specific examples

- Compile workflows that exercise preprocessing through emit.
- Conflicting flag combinations that verify precedence and exit behavior.
- Byte-level checks on generated object-output classes.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `armcc` is complete when:

1. Recreated `armcc` builds warning-clean and runs all original compile workflows and edge-case classes.
2. Three-way tests pass for driver parsing, pipeline stages, and diagnostic behavior.
3. Parity checks pass for compatibility-sensitive output metadata and key object artifacts.
4. Replacement validation works for all original compile workflow classes.
5. No externally visible mismatch remains.
