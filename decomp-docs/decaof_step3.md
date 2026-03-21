# decaof Step 3 - Recreate from specification

## Objective

Implement a clean-room C11 recreation in `decaof/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for all original paths, features, option semantics, diagnostics, exit behavior, and edge cases.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: decaof-step3
  step: 3
  applies_to: decaof
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - decaof/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - decaof/recreated/Makefile
    - decaof/recreated/src/
    - decaof/recreated/tests/
    - decaof/recreated/build/decaof
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

- `decaof/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Required outputs

- `decaof/recreated/Makefile`
- `decaof/recreated/src/` modular C11 implementation
- `decaof/recreated/tests/` shared tests that also run against original and recompiled binaries
- `decaof/recreated/build/decaof`

## Shared step 3 guidance

Use [generic_step3.md](generic_step3.md) for shared step 3 requirements:
- Start gate and authority order
- Clean-room implementation rules
- Recommended project structure and module boundaries
- Build and testing requirements
- Verification strategy and unresolved-difference handling
- Integration expectations and generic completion checks
- Three-way harness protocol and scenario artifact requirements

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

### Scope card (agent execution)

**In scope**
- Recreated parse/decode/render pipeline for all original options and fixtures.
- Deterministic text output parity on formatting-sensitive cases.
- Three-way validation for diagnostics and output ordering.

**Full-original coverage requirement**
- All behavior modes and features present in the original binary are in scope and must be specified, implemented, and validated.
- Treat unknown behavior as investigation backlog to be resolved; do not exclude original behavior from parity.


## Feature inventory closeout gate

Use the step 2 feature inventory as the step 3 closeout checklist.

- Revalidate every `confirmed` item with three-way tests.
- Resolve every `open` item before closeout.
- Keep `blocked` items explicit with owner, blocker, and closure experiment.

## decaof-specific focus

Split recreation into parse/decode, render, and CLI modules; keep output formatting deterministic and test-locked for compatibility.

## Tool-specific constraints and priorities

- Split recreation into parse/decode, render, and CLI modules.
- Protect deterministic text formatting and traversal order with tests.
- Prioritize core output parity before optional debug-path expansion.

## Tool-specific examples

- Render comparisons for fixtures with mixed chunk types.
- Option combinations that alter displayed sections or formatting.
- Diagnostics checks for malformed-input decode failures.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 for `decaof` is complete when:

1. Recreated `decaof` builds warning-clean and handles all required decode workflows and edge-case classes.
2. Three-way tests pass for chunk traversal, rendering, option handling, and diagnostics.
3. Parity checks confirm compatibility-sensitive text output formatting and ordering.
4. Replacement validation succeeds for all required downstream workflow classes that consume `decaof` output.
5. No externally visible mismatch remains.
