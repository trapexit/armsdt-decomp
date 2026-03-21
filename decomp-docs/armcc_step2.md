# armcc Step 2 - Create the technical behavior specification

## Objective

Produce an evidence-backed technical specification of exact-original `armcc` behavior for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcc-step2
  step: 2
  applies_to: armcc
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - armcc/armcc original runtime behavior
    - armcc decompilation/disassembly/readelf artifacts
    - armcc usage capture and format docs
  must_outputs:
    - armcc/technical_specification.md
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

- Step 1 artifacts from `armcc/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `armcc/armcc`.
- `armcc_decomp_ghidra.c`, `armcc_decomp_retdec.c`, `armcc_objdump.txt`, and `armcc_readelf.txt`.
- Usage and options from `armcc_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `armcc/technical_specification.md`, the canonical step 2 technical specification for `armcc`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `armcc/technical_specification.md`

## Shared step 2 guidance

Use [generic_step2.md](generic_step2.md) for shared step 2 requirements:
- Required documentation scope
- Evidence collection and conflict resolution
- Traceability matrix and uncertainty handling
- Verification and parity documentation
- Documentation standards and generic completion checks
- Step 2 scaffold: [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md)

## Requirement ID prefix

Use `armcc-REQ-###` in the traceability matrix for this tool.

### Scope card (agent execution)

**In scope**
- Driver option parsing/forwarding and stage-boundary behavior across all original compile flows.
- Contracts for preprocessing, parsing, semantics, codegen, and diagnostics across all original compile paths and edge cases.
- Exact-parity requirements for emitted outputs, diagnostics, exit behavior, and option precedence.

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

## armcc-specific emphasis

Focus on compiler driver and pipeline stage contracts: option forwarding, preprocessing and codegen stage boundaries, diagnostic behavior, and evidence-backed scope boundaries.

## Tool-specific constraints and priorities

- Document driver option parsing and forwarding contracts before complete internal coverage.
- Capture stage boundary contracts between preprocessing, parsing, semantic analysis, and code generation.
- Mark target-scope constraints for runtime-validated architecture and workflow coverage.

## Tool-specific examples to document

- Options that are positional, repeatable, or mutually exclusive.
- Inputs that trigger stage-specific diagnostics and exit precedence.
- Workflows where defaults influence emitted object metadata.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 for `armcc` is complete when:

1. Implementation-ready contracts exist for driver behavior, pipeline stage boundaries, and diagnostics across all original compile paths.
2. The must-match list includes outputs, diagnostics, exit behavior, option semantics, emitted metadata, and required edge cases.
3. Traceability entries use `armcc-REQ-###` with runtime evidence and shared-test linkage.
4. Any unresolved items are explicit with supporting evidence, parity impact, risk notes, and closure actions.
5. The specification remains ASCII-only and link-valid.
