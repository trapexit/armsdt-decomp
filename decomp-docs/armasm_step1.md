# armasm Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `armasm/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armasm-step1
  step: 1
  applies_to: armasm
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armasm/armasm
    - armasm/armasm_decomp_ghidra.c
    - armasm/armasm_decomp_retdec.c
    - armasm/armasm_objdump.txt
    - armasm/armasm_readelf.txt
    - armasm/armasm_usage.txt
  must_outputs:
    - armasm/recompiled/Makefile
    - armasm/recompiled/src/
    - armasm/recompiled/tests/
    - armasm/recompiled/build/armasm
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

- Directory: `armasm/`
- Tool: ARM AOF Macro Assembler v2.50
- Description: Assembles ARM source into AOF objects.
- Original binary size: 212 KB
- Recompiled priority: 4

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

## armasm-specific focus

Prioritize scanner and parser state, macro expansion, expression evaluation, and emission; preserve all architecture modes supported by the original binary encoding and big-endian object emission semantics; keep behavior-critical parser state-machine flows stable when uncertain.

## Tool-specific constraints and priorities

- Preserve parser state-machine behavior when simplifying control flow.
- Treat all architecture modes supported by the original binary instruction encoding and big-endian emission as compatibility-critical.
- Prioritize macro expansion and expression evaluator correctness before less-used directives.

## Tool-specific examples

- Nested macro expansion with forward label references.
- Conflicting directive combinations that trigger diagnostic precedence paths.
- Encoding edge cases for all architecture modes supported by the original binary condition codes and relocation records.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `armasm/recompiled/tests/` using the armlib `test_basic.c` CLI parity pattern as the harness template. Each test runs inputs through both `../../armasm` (original) and `../build/armasm` (recompiled), comparing exit codes, stdout/stderr, and output file bytes.

### Fixture strategy

- **Copy from 3do-devkit**: Representative `.s` sources from `3do-devkit/examples/original/` (e.g., `FontBlit3To8_.s`, `math.s`, `viewmatrix.s`, `gmemtest.s`) and pre-built `.o`/`.lib` from `3do-devkit/lib/3do/`. These provide real-world inputs with non-trivial structure.
- **Generate minimal fixtures**: Small hand-written `.s` files (5-10 lines each, deterministic) targeting specific edge cases. Assemble each with the original binary to produce reference `.o` files for byte-level comparison.

### Suggested test types

- **CLI parity** — `-help`, `-vsn`, no-args error, unrecognised options. Verify exit codes and output text match original exactly.
- **Basic assembly** — Compile `.s` fixtures (both generated minimal and 3do-devkit sources) through both binaries, compare output AOF objects with `cmp`.
- **Macro expansion** — Nested macro invocations, forward label references inside macro bodies, macro argument substitution, recursive macro edge cases.
- **Directive semantics** — Conflicting directive combinations, conditional assembly (`IF`/`ELSE`/`ENDIF`), alignment directives, section attributes. Verify diagnostic messages match original for invalid sequences.
- **Instruction encoding** — All architecture modes the original supports, condition code encoding, relocation record generation, big-endian object emission. Compare raw output bytes.
- **Label resolution** — Forward references, backward references, local labels, label shadowing, undefined label errors.
- **Adversarial inputs** — Empty files, files with only whitespace, malformed instructions, oversized operands, unterminated macro definitions.

### Suggested algorithmic assembly fixtures

Generate pure ARM assembly (`.s`) files implementing self-contained algorithms. Each fixture should be a complete, assemble-and-linkable program or object module with no external dependencies beyond the ARM instruction set. Assemble with the original binary to produce reference `.o` files, then verify the recompiled binary produces identical output.

- **CRC32** — Table-driven CRC32 with lookup table in a data section, byte-at-a-time processing loop, polynomial `0xEDB88320`. Tests: data section layout, LDR/STR patterns, loop encoding, table relocation.
- **MD5** — Full MD5 implementation with round constants, four-round loop structure, bit-padding logic. Tests: large function encoding, constant pool generation, complex control flow, multiple data sections.
- **Fibonacci** — Iterative and recursive fibonacci (two separate fixtures). Tests: simple function prologue/epilogue, register allocation patterns, branch encoding, stack frame layout.
- **Prime sieve** — Sieve of Eratosthenes with array in BSS section. Tests: BSS section handling, indexed array access, nested loops, conditional branches.
- **Integer square root** — Newton's method or binary search sqrt. Tests: division/multiply instruction encoding, loop termination conditions.
- **Bit manipulation** — Population count (popcount), bit reversal, find-first-set, rotate-based algorithms. Tests: ROR/RORR/RRX usage, barrel shifter patterns, carry flag handling.
- **String algorithms** — strcpy, strlen, strcmp, memcpy, memset in assembly. Tests: byte-level load/store, loop unrolling, alignment edge cases.
- **Sorting** — Bubble sort, insertion sort, quicksort on integer arrays. Tests: array indexing, swap logic, recursive call stack frames (quicksort).
- **Matrix multiply** — Fixed-size matrix multiplication. Tests: nested loop encoding, register pressure, instruction scheduling.
- **UB / edge cases** — Division by zero (trap), signed overflow patterns, unaligned access attempts, self-modifying code patterns, branch-to-NULL, stack underflow scenarios. Tests: diagnostic generation, encoding of edge-case instructions, assembler rejection of invalid constructs.

### Suggested structural assembly fixtures

Generate `.s` files that exercise specific assembler and encoding features beyond algorithmic correctness. These target how armasm handles instruction categories, section management, and edge-case syntax.

- **Conditional execution heavy** — Code using ARM predicated execution extensively (`ADDEQ`, `MOVNE`, `BLEQ`, `CMP` chains). Tests encoding of condition codes on every instruction, branch prediction hints.
- **Load/store multiple** — `LDMIA`/`STMDB` patterns for block memory operations, register save/restore in function prologues/epilogues. Tests multi-register encoding, writeback semantics, register list ordering.
- **Position-independent code** — PC-relative addressing, `ADR`/`ADRL` usage, GOT-style patterns. Tests relocation types, position-independent object emission.
- **Exception vectors** — Reset/IRQ/FIQ/SWI/Abort/Undefined vector table with handler stubs. Tests section placement, alignment, branch-to-offset encoding.
- **Inline data in code** — `DCD`, `DCB`, `DCW` interspersed with instructions, literal pools. Tests code/data section boundaries, literal pool generation, alignment padding.
- **SWI/syscall interfaces** — Software interrupt handlers with parameter passing through registers. Tests SWI number encoding, register convention preservation.
- **Coprocessor instructions** — `CDP`, `LDC`, `STC`, `MCR`, `MRC` patterns. Tests coprocessor opcode encoding, ARM vs Thumb coprocessor differences.
- **DSP/SIMD extensions** — `SMULL`, `SMLAL`, `QADD`, `QSUB`, saturation arithmetic (if supported by original). Tests extended instruction encoding, architecture mode flags.
- **Macro-generated code** — A macro that emits a full function (prologue, body, epilogue) parameterized by register choices. Tests macro-to-instruction expansion fidelity.
- **Thumb interworking** — ARM-to-Thumb and Thumb-to-ARM transitions, `BX`/`BLX` encoding, interworking veneers. Tests mode-switch encoding, relocation for interworking.

## Step 1 completion criteria

Step 1 for `armasm` is complete when:

1. Recompiled `armasm` builds repeatably and assembles representative all architecture modes supported by the original binary fixtures end-to-end.
2. Shared tests match original behavior for macro expansion, label resolution, and directive handling.
3. Compatibility-sensitive object output (encoding bytes, relocation records, and section ordering) is parity-checked.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
