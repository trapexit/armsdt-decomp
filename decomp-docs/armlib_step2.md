# armlib Step 2 - Create the technical behavior specification

## Objective

Produce an evidence-backed technical specification of exact-original `armlib` behavior for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlib-step2
  step: 2
  applies_to: armlib
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - armlib/armlib original runtime behavior
    - armlib decompilation/disassembly/readelf artifacts
    - armlib usage capture and format docs
  must_outputs:
    - armlib/technical_specification.md
    - traceability matrix with evidence IDs
    - feature inventory with status values
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

- Step 1 artifacts from `armlib/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `armlib/armlib`.
- `armlib_decomp_ghidra.c`, `armlib_decomp_retdec.c`, `armlib_objdump.txt`, and `armlib_readelf.txt`.
- Usage and options from `armlib_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `armlib/technical_specification.md`, the canonical step 2 technical specification for `armlib`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `armlib/technical_specification.md`

## Shared step 2 guidance

Use [generic_step2.md](generic_step2.md) for shared step 2 requirements:
- Required documentation scope
- Evidence collection and conflict resolution
- Traceability matrix and uncertainty handling
- Verification and parity documentation
- Documentation standards and generic completion checks
- Step 2 scaffold: [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md)

## Requirement ID prefix

Use `armlib-REQ-###` in the traceability matrix for this tool.

### Scope card (agent execution)

**In scope**
- ALF archive create, add, replace, remove, and list behavior.
- Deterministic member ordering, duplicate-name handling, and metadata writing rules.
- Exact-parity diagnostics, exit semantics, and option precedence across all original operations.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Original feature inventory checklist

Maintain a living checklist that enumerates all original feature families and tracks parity status using only `confirmed`, `open`, or `blocked`.

- [ ] CLI surface: options, aliases, defaults, precedence, repeats, invalid combinations.
- [ ] Inputs and modes accepted by the original binary.
- [ ] Outputs: structure, ordering, padding, metadata, and text formatting.
- [ ] Diagnostics and exits: stderr text, precedence, exit-code behavior.
- [ ] Pipeline stage behavior and externally visible side effects.
- [ ] Edge cases and failure paths covered by adversarial fixtures.

Do not close step 2 until every checklist row is `confirmed` or `blocked` with evidence IDs and closure experiments.

## armlib-specific emphasis

Focus on archive create, update, and list command semantics, including member ordering, duplicate-name handling, replacement rules, and archive metadata writing behavior.

## Tool-specific constraints and priorities

- Document command semantics for create, update, replace, remove, and list operations.
- Capture deterministic ordering and duplicate-name resolution rules.
- Mark compatibility-critical metadata writing behavior and fully specify all archive features present in the original binary.

## Tool-specific examples to document

- Archives containing duplicate names across update and replace commands.
- Mixed operation sequences that test ordering stability.
- Error cases for missing members and malformed archive input.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 for `armlib` is complete when:

1. Specification defines implementation-ready contracts for command dispatch and archive IO semantics.
2. The must-match list includes outputs, diagnostics, exit behavior, option semantics, member ordering, duplicate handling, metadata writes, and required edge cases.
3. Traceability entries use `armlib-REQ-###` with runtime captures and shared tests.
4. Any unresolved behaviors are explicit with supporting evidence, parity impact, and closure plans for ambiguous cases, and must be resolved before closeout.
5. The document remains ASCII-only with valid links.
