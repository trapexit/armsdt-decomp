# armcpp Step 2 - Create the technical behavior specification

## Objective

Produce an evidence-backed technical specification of exact-original `armcpp` behavior for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcpp-step2
  step: 2
  applies_to: armcpp
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - armcpp/armcpp original runtime behavior
    - armcpp decompilation/disassembly/readelf artifacts
    - armcpp usage capture and format docs
  must_outputs:
    - armcpp/technical_specification.md
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

- Step 1 artifacts from `armcpp/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `armcpp/armcpp`.
- `armcpp_decomp_ghidra.c`, `armcpp_decomp_retdec.c`, `armcpp_objdump.txt`, and `armcpp_readelf.txt`.
- Usage and options from `armcpp_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `armcpp/technical_specification.md`, the canonical step 2 technical specification for `armcpp`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `armcpp/technical_specification.md`

## Shared step 2 guidance

Use [generic_step2.md](generic_step2.md) for shared step 2 requirements:
- Required documentation scope
- Evidence collection and conflict resolution
- Traceability matrix and uncertainty handling
- Verification and parity documentation
- Documentation standards and generic completion checks
- Step 2 scaffold: [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md)

## Requirement ID prefix

Use `armcpp-REQ-###` in the traceability matrix for this tool.

### Scope card (agent execution)

**In scope**
- C++ front-end contracts for language mode, parsing, lookup, overload behavior, and diagnostics.
- Backend-coupling points that affect emitted object semantics in original workflows.
- Exact-parity requirements for semantic outcomes, diagnostics, exit behavior, and option semantics across required corpus cases.

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

## armcpp-specific emphasis

Focus on C++ front-end behavior and backend coupling: language-mode switches, preprocessing and parsing edge cases, emitted object semantics, and compatibility-sensitive diagnostics.

## Tool-specific constraints and priorities

- Specify front-end contracts for parsing, name lookup, overload resolution, and diagnostics.
- Document coupling points between C++ semantics and backend emission.
- Specify language behavior comprehensively across all original feature paths.

## Tool-specific examples to document

- Option combinations that switch language dialect or warning behavior.
- Inputs that stress namespace lookup, overloads, and conversion rules.
- Diagnostics where multiple parse or semantic failures compete.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 for `armcpp` is complete when:

1. Specification is implementation-ready for front-end behavior and backend-coupling contracts.
2. The must-match list captures outputs, diagnostics, exit behavior, option semantics, language-mode switches, overload outcomes, and required edge cases.
3. Traceability entries use `armcpp-REQ-###` mapped to evidence and shared tests.
4. Any unresolved language features include supporting evidence, rationale, parity impact, and recreation-impact notes, and must be resolved before closeout.
5. The document is ASCII-only with valid internal links.
