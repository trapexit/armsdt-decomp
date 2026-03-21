# armcpp Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `armcpp/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcpp-step3
  step: 3
  applies_to: armcpp
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - armcpp/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - armcpp/recreated/Makefile
    - armcpp/recreated/src/
    - armcpp/recreated/tests/
    - armcpp/recreated/build/armcpp
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

- `armcpp/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `armcpp/recreated/Makefile`
- `armcpp/recreated/src/` modular C11 implementation
- `armcpp/recreated/tests/` shared tests that also run against original and recompiled binaries
- `armcpp/recreated/build/armcpp`

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
- Recreated modular driver/front-end/backend integration for all original C++ flows.
- Three-way parity on language-mode behavior, semantic outcomes, diagnostics, and key outputs.
- Replacement readiness for all original C++ workflow paths and edge-case classes.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## armcpp-specific focus

Recreate with clean subsystem boundaries and test-locked C++ semantics; enforce deterministic output and diagnostics parity for supported corpus inputs.

## Tool-specific constraints and priorities

- Implement modular boundaries for driver, parser/semantic engine, and emitter integration.
- Prioritize deterministic behavior for all original C++ semantics before any feature expansion.
- Use adversarial tests to lock diagnostic and precedence behavior.

## Tool-specific examples

- Inputs that exercise overload resolution and namespace lookup.
- Flag combinations that alter parse mode and warning/error outcomes.
- Byte-level object comparisons for all original compile-output classes.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `armcpp` is complete when:

1. Recreated `armcpp` builds warning-clean and handles all original C++ compile workflows and edge-case classes.
2. Three-way tests pass for language-mode parsing, semantic resolution, and diagnostics.
3. Parity checks confirm compatibility-sensitive output metadata and error-reporting behavior.
4. Replacement validation succeeds for all original C++ workflow classes.
5. No externally visible mismatch remains.
