# armasm Step 2 - Create the technical behavior specification

## Objective

Produce an evidence-backed technical specification of exact-original `armasm` behavior for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armasm-step2
  step: 2
  applies_to: armasm
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - armasm/armasm original runtime behavior
    - armasm decompilation/disassembly/readelf artifacts
    - armasm usage capture and format docs
  must_outputs:
    - armasm/technical_specification.md
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

- Step 1 artifacts from `armasm/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `armasm/armasm`.
- `armasm_decomp_ghidra.c`, `armasm_decomp_retdec.c`, `armasm_objdump.txt`, and `armasm_readelf.txt`.
- Usage and options from `armasm_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `armasm/technical_specification.md`, the canonical step 2 technical specification for `armasm`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `armasm/technical_specification.md`

## Shared step 2 guidance

Use [generic_step2.md](generic_step2.md) for shared step 2 requirements:
- Required documentation scope
- Evidence collection and conflict resolution
- Traceability matrix and uncertainty handling
- Verification and parity documentation
- Documentation standards and generic completion checks
- Step 2 scaffold: [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md)

## Tool documentation references

- [ARM SDT 2.50 Reference Guide](../docs/ARM_DUI0041C_Reference_Guide.md)
- [ARM SDT 2.50 User Guide](../docs/ARM Software Development Toolkit Version 2.50 User Guide - ARM DUI 0040D.pdf)
- [ARM SDT 2.50 Errata](../docs/ARM SDT 2.50 User and Reference Guides Errata 01 - ARM DEI 0002A.pdf)
- [ARM SDT Suite Overview](../docs/norcroft_c/02_arm_sdt_suite_overview.md)
- [ARM SDT Command-Line Reference](../docs/norcroft_c/03_command_line_reference.md)
- [ARM SDT File Formats Reference](../docs/norcroft_c/04_file_formats_reference.md)
- [ARM SDT Platform and Target Support](../docs/norcroft_c/05_platform_and_target_support.md)
- [Norcroft C History and Overview](../docs/norcroft_c/01_norcroft_c_history_and_overview.md)
- [Norcroft Additional Resources and Archives](../docs/norcroft_c/07_additional_resources_and_archives.md)
- [Reverse Engineering Guide](../docs/norcroft_c/06_reverse_engineering_guide.md)
- [3DO SDK - ARM Assembly Language](../docs/3DO SDK - ARM Assembly Language.md)
- [3DO SDK - ARM Cookbook](../docs/3DO SDK - ARM Cookbook.md)
- [3DO SDK - ARM Object Format](../docs/3DO SDK - ARM Object Format.md)
- [3DO SDK - ARM Procedure Call Standard](../docs/3DO SDK - ARM Procedure Call Standard.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [AOF-2002](../docs/AOF-2002.md)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)

## Requirement ID prefix

Use `armasm-REQ-###` in the traceability matrix for this tool.

### Scope card (agent execution)

**In scope**
- Lexer/parser, macro expansion, expression evaluation, label resolution, and emission contracts.
- Architecture encoding semantics and compatibility-critical diagnostics across all modes supported by the original binary.
- Exact-parity requirements for emitted outputs, diagnostics, exit behavior, and option/directive semantics across original workflows.

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

## armasm-specific emphasis

Focus on source language and directive semantics: macro expansion behavior, expression evaluation, label resolution, and diagnostic precedence for conflicting directives and option combinations.

## Tool-specific constraints and priorities

- Specify directive grammar boundaries and precedence for macros, expressions, and labels.
- Treat diagnostic wording and precedence for conflicting directives as compatibility-critical.
- Document assembler behavior comprehensively across all original modes and directive families.

## Tool-specific examples to document

- Macro recursion and parameter substitution corner cases.
- Forward and backward local-label resolution collisions.
- Option combinations that alter listing, diagnostics, or emission mode.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 for `armasm` is complete when:

1. Specification defines implementation-ready contracts for lexer/parser, macro expansion, expression evaluation, and emission.
2. The must-match list explicitly covers outputs, diagnostics, exit behavior, directive/option precedence, label resolution, and required edge cases.
3. Traceability entries use `armasm-REQ-###` and link each high-risk claim to runtime evidence and shared tests.
4. Unresolved items are bounded with evidence-backed closure experiments and explicit parity impact for ambiguous directive behavior, and must be resolved before closeout.
5. The document remains ASCII-only with valid links to shared and tool-specific references.
