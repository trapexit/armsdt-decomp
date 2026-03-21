# decaof Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `decaof/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: decaof-step1
  step: 1
  applies_to: decaof
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - decaof/decaof
    - decaof/decaof_decomp_ghidra.c
    - decaof/decaof_decomp_retdec.c
    - decaof/decaof_objdump.txt
    - decaof/decaof_readelf.txt
    - decaof/decaof_usage.txt
  must_outputs:
    - decaof/recompiled/Makefile
    - decaof/recompiled/src/
    - decaof/recompiled/tests/
    - decaof/recompiled/build/decaof
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

- Directory: `decaof/`
- Tool: AOF Decoder v4.20
- Description: Dumps and disassembles AOF and ALF chunk files.
- Original binary size: 93 KB
- Recompiled priority: 2

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

## decaof-specific focus

Prioritize stable chunk parsing and text output for core AOF and ALF paths; treat -g debug and -c disassembly as original-feature paths during early reconstruction; preserve output formatting exactly where tests require byte-for-byte text parity, meaning the emitted outputs are compared directly with `cmp`.

## Tool-specific constraints and priorities

- Prioritize stable chunk parsing and core text-rendering paths.
- Treat formatting, spacing, and label text as compatibility-critical where byte-for-byte parity is checked with `cmp`.
- Cover debug and disassembly paths to exact-original parity with explicit evidence.

## Tool-specific examples

- Chunk traversal cases that mix AOF and ALF sections.
- Formatting checks for alignment, spacing, and line breaks in rendered output.
- Option interactions between core output and debug/disassembly paths across all original modes.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `decaof/recompiled/tests/` using the armlib `test_basic.c` CLI parity pattern as the harness template. Each test runs inputs through both `../../decaof` (original) and `../build/decaof` (recompiled), comparing exit codes, stdout/stderr, and output text with `cmp`.

### Fixture strategy

- **Copy from 3do-devkit**: Pre-built `.o` and `.lib` files from `3do-devkit/lib/3do/` (e.g., `subroutinestartup.o`, `DSShuttle.lib`, `clib.lib`, `graphics.lib`). These provide real-world AOF/ALF structures with complex chunk hierarchies, multiple sections, and varied metadata.
- **Generate minimal fixtures**: Produce minimal AOF/ALF files by compiling simple sources with armcc and archiving with armlib. Create fixtures targeting specific decode scenarios: single-section objects, multi-section objects, archives with few vs many members, objects with debug info. Run each through the original decaof to capture reference `.txt` output for `cmp` comparison.

### Suggested test types

- **CLI parity** — `-help`, `-vsn`, no-args error, unrecognised options. Verify exit codes and output strings match original.
- **Basic decode** — Decode AOF and ALF fixtures (both 3do-devkit artifacts and generated minimal files) through both binaries, compare text output with `cmp`.
- **Chunk traversal** — Mixed AOF/ALF section traversal: files with multiple section types, interleaved code and data chunks, nested chunk structures. Verify traversal order and content rendering match original exactly.
- **Output formatting** — Alignment, spacing, line breaks, hex dump formatting, label text rendering. Every whitespace character must match original output.
- **Debug info (`-g`)** — Debug symbol extraction, source line mapping, variable info. Compare output text exactly against original.
- **Disassembly (`-c`)** — Instruction disassembly, register name rendering, operand formatting. Compare output text exactly against original for all supported modes.
- **Symbol table dump** — Symbol enumeration, address formatting, type classification, scope indicators. Verify output matches original.
- **Relocation record display** — Relocation type names, target addresses, addend formatting. Compare output text exactly.
- **Adversarial inputs** — Empty files, truncated files, corrupted headers, non-AOF/ALF files, mixed valid/invalid chunks.

## Step 1 completion criteria

Step 1 for `decaof` is complete when:

1. Recompiled `decaof` builds repeatably and decodes all original inputs.
2. Shared tests match original behavior for chunk traversal and core render behavior.
3. Parity checks cover compatibility-sensitive text formatting and decoded output structure.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original debug/disassembly behavior is excluded.
