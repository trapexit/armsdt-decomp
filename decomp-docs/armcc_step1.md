# armcc Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C99 reconstruction in `armcc/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcc-step1
  step: 1
  applies_to: armcc
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armcc/armcc
    - armcc/armcc_decomp_ghidra.c
    - armcc/armcc_decomp_retdec.c
    - armcc/armcc_objdump.txt
    - armcc/armcc_readelf.txt
    - armcc/armcc_usage.txt
  must_outputs:
    - armcc/recompiled/Makefile
    - armcc/recompiled/src/
    - armcc/recompiled/tests/
    - armcc/recompiled/build/armcc
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

- Directory: `armcc/`
- Tool: ARM C Compiler
- Description: Compiles C source into AOF objects.
- Original binary size: 781 KB
- Recompiled priority: 5

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
- [3DO SDK - ARM Procedure Call Standard](../docs/3DO SDK - ARM Procedure Call Standard.md)
- [3DO SDK - ARM Cookbook](../docs/3DO SDK - ARM Cookbook.md)
- [ARM DUI0041C Reference Guide - ARM Object Format](../docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md)
- [AOF Specification](../docs/AOF_Specification.md)
- [AOF-1989](../docs/AOF-1989.md)
- [AOF-2002](../docs/AOF-2002.md)
- [APCS](../docs/APCS.md)
- [ASDTF](../docs/ASDTF.md)
- [RISC OS PRMs Appendix D - Code file formats](../docs/RISC OS Programmers Reference Manual - Appendix D - Code file formats.md)
- [RISC OS PRMs Code file formats](../docs/RISC_OS_PRMs_Code_file_formats.md)

## armcc-specific focus

Prioritize driver behavior and core compile pipeline first; recover subsystem boundaries for front end, semantics, backend, and emit incrementally; preserve compatibility-critical defaults, diagnostics, and output semantics.

## Tool-specific constraints and priorities

- Prioritize driver behavior before deeper backend cleanup.
- Keep front-end, semantic, backend, and emitter boundaries recoverable for later modularization.
- Treat default option behavior and diagnostics as compatibility-critical.

## Tool-specific examples

- Option-forwarding cases that change preprocessing or code-generation paths.
- Diagnostic precedence when multiple command-line faults occur.
- Output comparisons for representative compile invocations.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Suggested tests to generate

Create tests under `armcc/recompiled/tests/` using the armlib `test_basic.c` CLI parity pattern as the harness template. Each test runs inputs through both `../../armcc` (original) and `../build/armcc` (recompiled), comparing exit codes, stdout/stderr, and output file bytes.

### Fixture strategy

- **Copy from 3do-devkit**: Representative `.c` sources from `3do-devkit/src/` (e.g., `abort.c`, `3d_3do_logo.c`) and `3do-devkit/examples/` (e.g., `colorecho.c`, `perftest.c`). These provide real-world compilation inputs with non-trivial control flow and platform-specific patterns.
- **Generate minimal fixtures**: Small hand-written `.c` files (deterministic, no external dependencies) targeting specific compiler behaviors. Compile each with the original binary to produce reference `.o` files for comparison.

### Suggested test types

- **CLI parity** — `-help`, no-args error, unrecognised options. Verify exit codes and error message text match original.
- **Basic compilation** — Compile `.c` fixtures (both generated minimal and 3do-devkit sources) through both binaries, compare output AOF objects with `cmp`.
- **Diagnostic parity** — Warning and error message text: unused variables, type mismatches, unreachable code, implicit declarations. Output must match original exactly.
- **Multi-error precedence** — Files with multiple simultaneous faults; verify error/warning order and count match original.
- **Option forwarding** — `-c` (compile only), `-o` output naming, optimization level switches, preprocessing-only mode, include path handling. Verify each option produces the same stage transition and output as original.
- **Version string** — `-vsn` output exact byte-for-byte match (compatibility-critical).
- **Preprocessor behavior** — Macro expansion, `#include` resolution, conditional compilation (`#ifdef`/`#ifndef`), `#pragma` handling.
- **Adversarial inputs** — Empty files, files with only comments, syntax errors at various positions, oversized literals, unterminated strings/comments.

### Suggested algorithmic C89 fixtures

Generate pure C89 (ANSI C, no C99/C11 features) source files implementing self-contained algorithms. Each fixture must compile with `-A` (ANSI mode) and have no external dependencies beyond the standard library. Compile with the original binary to produce reference `.o` files, then verify the recompiled binary produces identical output.

- **CRC32** — Table-driven CRC32 with static lookup table, byte-at-a-byte processing. Tests: static array initialization, loop optimization, constant folding, code generation for table lookups.
- **MD5** — Full MD5 with round constants as static arrays, four-round macro expansion, bit-padding. Tests: large function code generation, struct handling, inline arithmetic complexity, register allocation under pressure.
- **Fibonacci** — Iterative and recursive implementations (separate files). Tests: function call overhead, tail-call detection, stack frame generation, simple loop optimization.
- **Prime sieve** — Sieve of Eratosthenes with static array. Tests: array initialization, nested loop optimization, branch prediction hints, BSS vs data section placement.
- **Integer square root** — Newton's method and binary search variants. Tests: integer division code generation, loop invariant detection.
- **Bit manipulation** — Popcount (K&R algorithm), bit reversal, De Bruijn sequence find-first-set. Tests: shift/rotate optimization, constant folding, expression tree flattening.
- **String algorithms** — K&R-style strcpy, strlen, strcmp, memcpy, memset, strstr. Tests: pointer arithmetic, char vs int promotion, loop unrolling decisions.
- **Sorting** — Bubble sort, insertion sort, mergesort (array-based), quicksort. Tests: array indexing code gen, function pointer usage (qsort-style comparator), recursion depth.
- **Matrix multiply** — Fixed-size and variable-size variants. Tests: nested loop optimization, common subexpression elimination, register allocation.
- **UB / edge cases** — Signed integer overflow, null pointer dereference, use-after-free patterns (static analysis), strict aliasing violations, sequence point violations, shift-by-width-or-greater, out-of-bounds array access. Tests: warning/diagnostic generation, optimization behavior differences, code generation correctness at UB boundaries.
- **Preprocessor stress** — Heavy macro usage, token pasting, stringification, multi-level macro expansion, `#line` directives. Tests: preprocessing pipeline correctness, diagnostic location reporting.
- **Struct/union layout** — Packed structs, bitfields, union aliasing, nested structs, flexible array member emulation. Tests: data layout, alignment padding, field access code generation.

### Suggested structural C89 fixtures

Generate `.c` files that exercise specific compiler code-generation and analysis features beyond algorithmic correctness. These target how armcc handles language constructs, optimization decisions, and diagnostic behavior.

- **Function pointer dispatch** — Jump tables, callback registries, state machine dispatch via function pointer arrays. Tests indirect call generation, function pointer type handling, constant pool placement of addresses.
- **State machines** — Switch-based protocol parsers, lexer state machines with many states. Tests large switch code generation (jump table vs if-else chain decisions), case label ordering.
- **Variadic functions** — `printf`-style formatting, `va_list` traversal, variable argument counting. Tests `stdarg.h` code generation, stack frame layout for variadic functions, argument promotion.
- **Setjmp/longjmp** — Non-local jump with stack cleanup, nested setjmp contexts. Tests stack frame preservation, register save/restore across setjmp boundary.
- **Fixed-point arithmetic** — Q-format number operations, multiplication with shift, saturation. Tests integer multiply-accumulate code generation, overflow detection patterns.
- **Memory allocator** — Simple bump allocator or free-list malloc/free. Tests pointer arithmetic, alignment enforcement, struct-with-flexible-array patterns.
- **Linked data structures** — Singly/doubly linked lists, binary search trees, hash tables with chaining. Tests pointer chasing code generation, NULL check optimization, struct field access patterns.
- **Volatile / memory-mapped I/O** — Hardware register access patterns, volatile struct pointers, memory barriers. Tests volatile load/store emission (no optimization), ordering guarantees.
- **Bitfield structs** — Hardware register layout definitions with mixed-width bitfields. Tests bitfield packing, access code generation (shift/mask sequences), endianness handling.
- **Lookup tables** — Sine/cosine tables, CRC tables, Huffman tables, log tables. Tests large constant array initialization, read-only section placement, alignment.
- **String formatting** — Minimal `printf`/`scanf` implementation. Tests format string parsing, type-specific output code, buffer management.

## Step 1 completion criteria

Step 1 for `armcc` is complete when:

1. Recompiled `armcc` builds repeatably and compiles all original inputs end-to-end.
2. Shared tests match original behavior for driver option handling and stage transitions.
3. Parity checks cover emitted objects plus compatibility-sensitive version and diagnostic text.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original compiler features are excluded.
