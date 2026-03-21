# armlib Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `armlib/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlib-step1
  step: 1
  applies_to: armlib
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armlib/armlib
    - armlib/armlib_decomp_ghidra.c
    - armlib/armlib_decomp_retdec.c
    - armlib/armlib_objdump.txt
    - armlib/armlib_readelf.txt
    - armlib/armlib_usage.txt
  must_outputs:
    - armlib/recompiled/Makefile
    - armlib/recompiled/src/
    - armlib/recompiled/tests/
    - armlib/recompiled/build/armlib
  status_values:
    - confirmed
    - open
    - blocked
  closeout_requirements:
    - no externally visible mismatch
    - tests pass with parity evidence
    - unresolved items remain only as blocked with closure experiments
```

## Tool profile

- Directory: `armlib/`
- Tool: ARM Library Manager
- Description: Creates, modifies, and lists ALF library archives.
- Original binary size: 20 KB
- Recompiled priority: 1

## Shared step 1 guidance

Use [generic_step1.md](generic_step1.md) for shared step 1 requirements:
- Required references and inputs
- Required outputs
- Bootstrap-from-Ghidra baseline and initial commit order
- Build and test workflow, including two-way testing
- Analysis workflow, portability rules, source recovery rules, and verification strategy
- Commit and artifact rules

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
- [3DO SDK - The ARM Librarian](../docs/3DO SDK - The ARM Librarian.md)
- [3DO SDK - The ARM Linker](../docs/3DO SDK - The ARM Linker.md)
- [3DO SDK - ARM Object Format](../docs/3DO SDK - ARM Object Format.md)
- [3DO SDK - ARM Object Library Format](../docs/3DO SDK - ARM Object Library Format.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [ARM DUI0041C Reference Guide - ARM Object Library Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Library_Format.md)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [AOF-2002](../docs/AOF-2002.md)
- [ALF Specification](../docs/ALF_Specification.md)
- [ALF-1989](../docs/ALF-1989.md)
- [ALF-1993](../docs/ALF-1993.md)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)
- [3DO SDK - ARM Image Format](../docs/3DO SDK - ARM Image Format.md)
- [3DO SDK - ARM Procedure Call Standard](../docs/3DO SDK - ARM Procedure Call Standard.md)
- [3DO SDK - ARM Cookbook](../docs/3DO SDK - ARM Cookbook.md)


## armlib-specific focus

Prioritize archive member add/remove/replace/list behavior; preserve member ordering and metadata handling in ALF outputs; keep state-machine style traversal intact where refactoring risks behavior drift.

## Tool-specific constraints and priorities

- Prioritize member add/remove/replace/list behavior over low-value paths.
- Preserve deterministic member ordering and archive metadata semantics.
- Keep traversal logic stable until behavior is fully characterized.

## Tool-specific examples

- Replacing duplicate member names with ordering-sensitive updates.
- Create/update cycles that touch timestamp and metadata fields.
- List operations that expose ordering and formatting rules.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `armlib/recompiled/tests/` using the existing `test_basic.c` CLI parity pattern as the harness template. Each test runs operations through both `../../armlib` (original) and `../build/armlib` (recompiled), comparing exit codes, stdout/stderr, and output file bytes.

### Fixture strategy

- **Copy from 3do-devkit**: Pre-built `.lib` ALF archives from `3do-devkit/lib/3do/` (e.g., `DSShuttle.lib`, `clib.lib`, `exampleslib.lib`, `graphics.lib`). These provide real-world archive structures with multiple members, varied sizes, and complex metadata.
- **Generate minimal fixtures**: Hand-crafted ALF archives at various stages of modification. Start with empty archive, add members one at a time, replace, delete, verify state at each step. Use `.o` files from armcc test fixtures as realistic archive members. Produce reference `.lib` files at each stage with the original binary for byte-level comparison.

### Suggested test types

- **CLI parity** — `-help`, `-vsn`, no-args error, unrecognised options. (Rename existing `test_basic.c` to `test_cli.c` for consistency.)
- **Create archive** — `-c` option: create new empty ALF archive, verify output file bytes match original.
- **Add members** — `-a` option: add `.o` files to archive, verify member count, ordering, and archive bytes match original.
- **Replace members** — `-r` option: replace existing members, verify updated archive bytes and metadata match original.
- **Delete members** — `-d` option: remove members from archive, verify resulting archive bytes match original.
- **List contents** — `-l` option: list archive members, verify output text (ordering, formatting, metadata fields) matches original exactly.
- **Extract members** — `-x` option: extract members from archive, verify extracted file bytes match originals.
- **Ordering stability** — Add members in various sequences, verify list output order is deterministic and matches original. Test duplicate member names and replacement ordering.
- **Metadata parity** — Timestamps, member sizes, archive headers. Compare field-by-field against original output.
- **Adversarial inputs** — Operations on non-existent files, empty archive operations, adding duplicate-named members, replacing non-existent members.

## Step 1 completion criteria

Step 1 for `armlib` is complete when:

1. Recompiled `armlib` builds repeatably and performs core archive operations.
2. Shared tests match original behavior for member ordering, replacement, and listing.
3. Parity checks cover ALF archive bytes and compatibility-sensitive metadata fields.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original archive features are excluded.
