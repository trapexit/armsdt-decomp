# armasm Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `armasm/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armasm-step3
  step: 3
  applies_to: armasm
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - armasm/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - armasm/recreated/Makefile
    - armasm/recreated/src/
    - armasm/recreated/tests/
    - armasm/recreated/build/armasm
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

- `armasm/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `armasm/recreated/Makefile`
- `armasm/recreated/src/` modular C11 implementation
- `armasm/recreated/tests/` shared tests that also run against original and recompiled binaries
- `armasm/recreated/build/armasm`

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
- Recreated modular assembler pipeline (lexer, parser, macro engine, semantic passes, emitter).
- Three-way parity for encoding bytes, relocations, directive semantics, and diagnostics.
- Replacement readiness for all original assembly workflow paths and edge-case classes.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## armasm-specific focus

Partition recreation into lexer, parser, macro engine, semantic passes, and emitter; protect encoding and diagnostics parity with adversarial tests.

## Tool-specific constraints and priorities

- Keep lexer, parser, macro engine, semantic passes, and emitter as separate modules.
- Preserve deterministic encoding and diagnostics for all original assembly paths.
- Expand adversarial tests before broadening non-core directive support.

## Tool-specific examples

- Assemble inputs that mix macros, expressions, and forward labels.
- Compare emitted object bytes and relocation entries against original output.
- Exercise conflicting directives to confirm error-precedence parity.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `armasm` is complete when:

1. Recreated `armasm` builds warning-clean and assembles all original fixtures end-to-end.
2. Three-way tests pass for macro expansion, label resolution, directive semantics, and diagnostics.
3. Parity checks confirm compatibility-sensitive encoding bytes, relocation data, and output ordering.
4. Assembler replacement validation succeeds for all required build scenario classes.
5. No externally visible mismatch remains.
