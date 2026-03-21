# decaof Step 2 - Create the technical behavior specification

## Objective

Produce an evidence-backed technical specification of exact-original `decaof` behavior for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: decaof-step2
  step: 2
  applies_to: decaof
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - decaof/decaof original runtime behavior
    - decaof decompilation/disassembly/readelf artifacts
    - decaof usage capture and format docs
  must_outputs:
    - decaof/technical_specification.md
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

- Step 1 artifacts from `decaof/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `decaof/decaof`.
- `decaof_decomp_ghidra.c`, `decaof_decomp_retdec.c`, `decaof_objdump.txt`, and `decaof_readelf.txt`.
- Usage and options from `decaof_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `decaof/technical_specification.md`, the canonical step 2 technical specification for `decaof`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `decaof/technical_specification.md`

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
- [3DO SDK - ARM Object Format](../docs/3DO SDK - ARM Object Format.md)
- [3DO SDK - ARM Object Library Format](../docs/3DO SDK - ARM Object Library Format.md)
- [3DO SDK - ARM Image Format](../docs/3DO SDK - ARM Image Format.md)
- [3DO SDK - The ARM Linker](../docs/3DO SDK - The ARM Linker.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [ARM DUI0041C Reference Guide - ARM Object Library Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Library_Format.md)
- [ARM DUI0041C Reference Guide - ARM Image Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Image_Format.md)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [AOF-2002](../docs/AOF-2002.md)
- [ALF Specification](../docs/ALF_Specification.md)
- [ALF-1989](../docs/ALF-1989.md)
- [ALF-1993](../docs/ALF-1993.md)
- [AIF Specification](../docs/AIF_Specification.md)
- [AIF-1989](../docs/AIF-1989.md)
- [AIF-1993](../docs/AIF-1993.md)
- [aif.h](../docs/aif.h)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS ARM AIF Format](../docs/RISC_OS_ARM_AIF_Format.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)

## Requirement ID prefix

Use `decaof-REQ-###` in the traceability matrix for this tool.

### Scope card (agent execution)

**In scope**
- Core chunk parse/decode and render behavior for AOF/ALF-oriented workflows.
- Traversal order, label text, spacing, and formatting rules marked compatibility-critical.
- Exact-parity rules for output text, diagnostics, exit behavior, and option interactions across original workflows.

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

## decaof-specific emphasis

Focus on decode and render behavior: chunk traversal order, disassembly formatting, spacing, section labeling, and option interactions for core output and debug/disassembly paths across all original modes.

## Tool-specific constraints and priorities

- Document decode and render contracts, including traversal order and formatting invariants.
- Capture option-interaction rules that change rendered output.
- Specify core and debug/disassembly behavior comprehensively across all original feature paths.

## Tool-specific examples to document

- Fixtures where chunk ordering affects rendered section output.
- Formatting-sensitive outputs with strict spacing and label expectations.
- Error cases for malformed chunks and unsupported sections.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 for `decaof` is complete when:

1. Specification is implementation-ready for parse/decode and render behavior contracts.
2. The must-match list covers outputs, diagnostics, exit behavior, option semantics, traversal order, formatting, and required edge cases.
3. Traceability entries use `decaof-REQ-###` tied to runtime captures and tests.
4. Any unresolved debug or disassembly behavior is explicit with supporting evidence, parity impact, and closure plans, and must be resolved before closeout.
5. The document remains ASCII-only with valid links.
