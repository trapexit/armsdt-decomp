# armlink Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `armlink/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armlink-step1
  step: 1
  applies_to: armlink
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armlink/armlink
    - armlink/armlink_decomp_ghidra.c
    - armlink/armlink_decomp_retdec.c
    - armlink/armlink_objdump.txt
    - armlink/armlink_readelf.txt
    - armlink/armlink_usage.txt
  must_outputs:
    - armlink/recompiled/Makefile
    - armlink/recompiled/src/
    - armlink/recompiled/tests/
    - armlink/recompiled/build/armlink
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

- Directory: `armlink/`
- Tool: ARM Linker v5.20
- Description: Links AOF objects into AIF executables.
- Original binary size: 134 KB
- Recompiled priority: 3

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
- [3DO SDK - The ARM Linker](../docs/3DO SDK - The ARM Linker.md)
- [3DO SDK - ARM Image Format](../docs/3DO SDK - ARM Image Format.md)
- [3DO SDK - ARM Object Format](../docs/3DO SDK - ARM Object Format.md)
- [3DO SDK - ARM Object Library Format](../docs/3DO SDK - ARM Object Library Format.md)
- [3DO SDK - ARM Procedure Call Standard](../docs/3DO SDK - ARM Procedure Call Standard.md)
- [3DO SDK - ARM Cookbook](../docs/3DO SDK - ARM Cookbook.md)
- [ARM DUI0041C Reference Guide - ARM Image Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Image_Format.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [ARM DUI0041C Reference Guide - ARM Object Library Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Library_Format.md)
- [AIF Specification](../docs/AIF_Specification.md)
- [AIF-1989](../docs/AIF-1989.md)
- [AIF-1993](../docs/AIF-1993.md)
- [aif.h](../docs/aif.h)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [ALF Specification](../docs/ALF_Specification.md)
- [ALF-1989](../docs/ALF-1989.md)
- [ALF-1993](../docs/ALF-1993.md)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS ARM AIF Format](../docs/RISC_OS_ARM_AIF_Format.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)
- [AOF-2002](../docs/AOF-2002.md)


## armlink-specific focus

Prioritize data model recovery for areas, symbols, relocations, and link state; preserve area ordering, alignment padding, relocation resolution, and header fields; document unresolved non-core modules with explicit rationale and closure experiments.

## Tool-specific constraints and priorities

- Prioritize recovery of area, symbol, relocation, and link-state data models.
- Treat area ordering, alignment/padding, and relocation application as compatibility-critical.
- Document unresolved non-core modules with explicit rationale and closure experiments.

## Tool-specific examples

- Multi-object links that stress symbol-resolution precedence.
- Relocation sequences where application order changes output bytes.
- Layout cases that expose padding and alignment rules.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `armlink/recompiled/tests/` using the armlib `test_basic.c` CLI parity pattern as the harness template. Each test runs inputs through both `../../armlink` (original) and `../build/armlink` (recompiled), comparing exit codes, stdout/stderr, and output file bytes.

### Fixture strategy

- **Copy from 3do-devkit**: Pre-built `.o` object files from `3do-devkit/lib/3do/` (e.g., `subroutinestartup.o`, `cstartup.o`, `copyright.o`) and `.lib` archives for library-linking tests. These provide real-world object structures with actual relocation records, symbol tables, and section layouts.
- **Generate minimal fixtures**: Compile small `.c` sources with the original armcc to produce `.o` fixtures with deliberate properties: symbol conflicts across objects, specific relocation types, alignment requirements, inter-section references. Link each fixture set with the original binary to produce reference `.aif` files for byte-level comparison.

### Suggested test types

- **CLI parity** — `-help`, `-vsn`, no-args error, unrecognised options. Verify exit codes and output strings match original.
- **Basic linking** — Link AOF object fixtures (both 3do-devkit `.o` files and generated fixtures) into AIF executables through both binaries, compare output binary bytes with `cmp`.
- **Symbol resolution** — Multi-object links with duplicate symbol definitions, weak vs strong symbols, undefined symbol handling, extern resolution. Compare link-time diagnostics and symbol table output.
- **Relocation application** — PC-relative relocations, absolute relocations, inter-section references. Link fixtures that exercise each relocation type and compare output bytes. Test cases where application order changes output.
- **Layout rules** — Area ordering, alignment padding, section placement order, padding bytes between sections, header field values. Compare output binary structure byte-for-byte.
- **Library linking** — Link against `.lib` archives from 3do-devkit, verify symbol extraction and member selection match original behavior.
- **Entry point handling** — Custom entry point specification, default entry point selection, missing entry point errors.
- **Adversarial inputs** — Linking with unresolved symbols, duplicate strong symbol definitions, circular references, empty object files, incompatible object formats.

## Step 1 completion criteria

Step 1 for `armlink` is complete when:

1. Recompiled `armlink` builds repeatably and links all required input classes.
2. Shared tests match original behavior for symbol resolution, relocation application, and layout.
3. Parity checks cover output headers, section ordering, and padding-sensitive bytes.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
