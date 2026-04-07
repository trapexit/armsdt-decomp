# Processing Decompiled C Code

This guide provides instructions for two parallel efforts to replace the
original ARM SDT 2.51 command-line tools.

## Tools

| Directory | Tool | Description | Binary | Ghidra |
|-----------|------|-------------|--------|--------|
| `armlib/` | ARM Library Manager | Creates, modifies, and lists ALF library archives | 20 KB | 82 KB |
| `decaof/` | AOF Decoder v4.20 | Dumps and disassembles AOF/ALF chunk files | 93 KB | 304 KB |
| `armlink/` | ARM Linker v5.20 | Links AOF objects into AIF executables | 134 KB | 537 KB |
| `armasm/` | ARM AOF Macro Assembler v2.50 | Assembles ARM source into AOF objects | 212 KB | 791 KB |
| `armcc/` | ARM C Compiler | Compiles C source into AOF objects | 781 KB | 3.1 MB |
| `armcpp/` | ARM C++ Compiler | Compiles C++ source into AOF objects | 902 KB | 3.6 MB |

Listed in order of complexity (simplest first). All are from ARM SDT 2.51,
targeting ARMv3 (ARM60 CPU) with big-endian AOF/AIF/ALF output for the 3DO.

## Project Goals

There are two goals for each tool in this project. **The recompiled version
is always the priority.** Complete the recompiled version first -- it serves
as the functional reference implementation and provides the deep understanding
of the original binary's logic needed to inform the recreated version.

### Goal 1: Recompiled -- Cleaned Decompilation (`toolname/recompiled/`) [DO FIRST]

Clean up the Ghidra decompilation output into human-readable, compilable,
maintainable C code. The aim is to produce a working replacement for the
original tool derived directly from the decompiled source. This is the
"faithful reproduction" path -- the code structure will closely mirror the
original binary's logic. Must be written in **C89** (ANSI C) to reflect
the era of the original codebase.

- Source: `toolname_decomp_ghidra.c` (primary), cross-referenced with
  `toolname_decomp_retdec.c` (secondary)
- Output directory: `toolname/recompiled/`
- Must include a Makefile (see [Build System](#build-system) below)
- Must include a full suite of unit tests (see [Unit Tests](#unit-tests) below)
- Verification: byte-for-byte output matching with original tool

### Goal 2: Recreated -- Clean-Room Reimplementation (`toolname/recreated/`) [DO SECOND]

Recreate the tool's functionality from scratch, informed by the reference
materials and behavioral analysis of the original binary. This is the
"clean design" path -- the code should use modern C practices, clear
architecture, and proper abstractions, without being constrained by the
original binary's internal structure. May use **C11** features.

**Do not start the recreated version until the recompiled version is
functional and passing tests.** The recompiled effort reveals critical
details about the original binary's behavior -- edge cases, undocumented
format quirks, and implicit assumptions -- that are essential for writing
a correct reimplementation.

- Source: behavioral analysis of the original `toolname` binary, format
  specifications in `docs/`, and understanding gained from the recompiled effort
- Output directory: `toolname/recreated/`
- Must include a Makefile (see [Build System](#build-system) below)
- Must include a full suite of unit tests (see [Unit Tests](#unit-tests) below)
- Verification: byte-for-byte output matching with original tool

### Work Priority

Work on tools in this order. Complete all recompiled versions first (they
are the reference implementations), then recreated versions. Within each
group, tools are listed from easiest to hardest based on binary size and
complexity.

**Phase 1 -- Recompiled versions (do these first):**

| Priority | Tool | Notes |
|----------|------|-------|
| 1 | `armlib/recompiled` | 20 KB binary, simplest tool |
| 2 | `decaof/recompiled` | 93 KB binary. -c disassembly is second lowest priority feature (after -g debug) |
| 3 | `armlink/recompiled` | 134 KB binary, ~307 Ghidra functions |
| 4 | `armasm/recompiled` | 212 KB binary, 597 Ghidra functions |
| 5 | `armcc/recompiled` | 781 KB binary, largest compilation pipeline |
| 6 | `armcpp/recompiled` | 902 KB binary. Most complex |

**Phase 2 -- Recreated versions (do these after recompiled is functional):**

| Priority | Tool | Notes |
|----------|------|-------|
| 7 | `armlib/recreated` | Simplest tool |
| 8 | `decaof/recreated` | -c disassembly is second lowest priority feature (after -g debug) |
| 9 | `armlink/recreated` | Medium complexity |
| 10 | `armasm/recreated` | Complex -- full macro assembler |
| 11 | `armcc/recreated` | Most complex -- full C compiler |
| 12 | `armcpp/recreated` | Shares armcc backend, adds C++ front-end |

Within each phase, prefer finishing near-complete tools before starting
new ones -- closing out remaining work is higher value than opening new
fronts.

### Build System

Each subproject (`recompiled/` and `recreated/`) must have its own Makefile
with the following properties:

- Simple and self-contained -- no recursive make, no autotools
- All `.o` files go in `build/`
- Final executable goes in `build/`
- Dependency `.d` files go in `build/`
- `make` builds the executable
- `make test` runs the full unit test suite
- `make clean` removes all build artifacts
- `make help` lists all targets

Example structure:
```
toolname/recompiled/
|-- Makefile
|-- src/
|   `-- *.c, *.h
|-- tests/
|   `-- test_*.c
`-- build/          (created by make)
    |-- *.o, *.d
    `-- toolname
```

### Unit Tests

Each subproject must include a comprehensive unit test suite:

- Test files live in a `tests/` subdirectory
- Tests are built and run via `make test`
- At minimum, test each public function for correct output, edge cases,
  and error handling
- Include integration tests that compare full tool output against the
  original binary for known inputs
- Use a simple test framework (e.g., a minimal assertion macro) -- no
  external test library dependencies
- **100% code coverage is required.** Unit tests must cover every function
  and every code path. Integration tests must exercise every command-line
  option, flag combination, and error condition supported by the original
  tool. Nothing should be skipped. Any change in behavior from the
  original -- no matter how minor -- is a bug and must be fixed.
- Do not leave any failed test unresolved.
- If at the end of working on the project all tests pass attempt to
  create more tests. Even "fuzz" like testing.

### Test-First, Adversarial Approach

**Write tests before implementing the feature.** The workflow is:

1. **Write tests first** -- before implementing a function or feature, write
   tests that exercise it against the original binary. Run them to confirm
   they pass against the original. These tests define the correct behavior.

2. **Expect failures** -- run the same tests against the recompiled or
   recreated build. They will fail. This is expected and desired -- the
   failing tests are your work list.

3. **Implement to pass** -- implement the feature, then run the tests again.
   Fix the implementation until all tests pass.

4. **Adversarial test writing** -- treat test creation and implementation as
   opposing efforts. When writing tests, actively try to break the
   implementation: test edge cases, boundary values, malformed inputs, empty
   inputs, maximum-length inputs, unusual flag combinations, and error
   conditions. Do not write tests that merely confirm the happy path. Think
   like an attacker trying to find differences between the original and the
   reimplementation.

5. **After passing, attack again** -- once all tests pass, write more tests
   specifically targeting areas where the implementation was difficult or
   where you made assumptions. Try to find inputs that produce different
   output between the original and your version. The goal is to discover
   bugs, not to confirm success.

The original binary is always the oracle. If a test passes against the
original but fails against your implementation, the implementation is wrong.
Never weaken a test to make it pass.

### Three-Way Testing (Critical)

Every test must be run against **all three versions** of the tool:

1. **Original** -- The reference binary in the tool directory (e.g., `armlib/armlib`)
2. **Recompiled** -- The cleaned decompilation build (e.g., `armlib/recompiled/build/armlib`)
3. **Recreated** -- The from-scratch reimplementation (e.g., `armlib/recreated/build/armlib`)

All three must produce identical output for the same inputs. The test script
should accept the tool path as a parameter or loop over all three binaries
automatically:

```bash
# Example: test script runs against all three versions
TOOLS=(
    "../../armlib"                    # Original binary
    "../recompiled/build/armlib"      # Recompiled version
    "../recreated/build/armlib"       # Recreated version
)

for TOOL in "${TOOLS[@]}"; do
    echo "=== Testing: $TOOL ==="
    run_tests "$TOOL"
done
```

This ensures that:
- The original binary serves as the ground truth
- The recompiled version faithfully reproduces the original logic
- The recreated version achieves behavioral equivalence independently
- Any regression in either implementation is caught immediately

Do **not** write separate test suites for recompiled and recreated. Write
one shared test suite that validates all three. If a test passes against the
original but fails against either implementation, that implementation has a
bug -- not the test.

## Tool Directory Contents

Each tool directory (`armasm/`, `armcc/`, `armcpp/`, `armlib/`, `armlink/`, `decaof/`)
has this layout:

```
toolname/
  toolname                    # Original 32-bit x86 Linux binary (NEVER modify)
  toolname_decomp_ghidra.c    # Primary decompilation reference
  toolname_decomp_retdec.c    # Secondary decompilation reference
  toolname_objdump.txt        # x86 disassembly
  toolname_readelf.txt        # ELF header info
  toolname_usage.txt          # -help output
  recompiled/                 # Cleaned decompilation (faithful to original logic)
    Makefile
    src/
    tests/
    build/                    # Created by make (in .gitignore)
  recreated/                  # From-scratch reimplementation (modern C)
    Makefile
    src/
    tests/
    build/                    # Created by make (in .gitignore)
```

Reference files in each tool directory:

| File | Description |
|------|-------------|
| `toolname` | Original 32-bit x86 Linux ELF binary. This is the reference executable used for behavioral verification and byte-for-byte output comparison. |
| `toolname_decomp_ghidra.c` | **Primary decompilation reference.** Ghidra decompilation output. Ghidra generally produces more accurate control flow recovery, better type inference, and more readable output than RetDec. Use this as the first source when analyzing function behavior. |
| `toolname_decomp_retdec.c` | **Secondary decompilation reference.** RetDec decompilation output. Larger than the Ghidra output but often contains more artifacts (`placeholder_g279`, redundant casts, incorrect types). Useful for cross-referencing when Ghidra output is unclear, and as a second opinion on ambiguous code. |
| `toolname_objdump.txt` | x86 disassembly from `objdump -d`. Raw instruction-level reference for when both decompilers produce questionable output. Use to verify instruction sequences, calling conventions, and jump targets. |
| `toolname_readelf.txt` | ELF header and section information from `readelf`. Shows the binary's symbol table, sections, and dynamic linking details. Useful for identifying global variables, imported functions, and section layout. |
| `toolname_usage.txt` | Command-line help text captured from running the tool with `-help`. Documents all supported flags, options, and usage patterns. Essential for understanding what functionality the reimplementation must support. |

Original files should NEVER be modified.

### Decompiler Priority: Ghidra First, RetDec Second

When analyzing a function, follow this workflow:

1. **Start with `toolname_decomp_ghidra.c`** - Ghidra's output is generally
   more compact, has better variable naming, and produces more accurate
   control flow structures (loops, if/else chains).
2. **Cross-reference with `toolname_decomp_retdec.c`** - RetDec sometimes
   captures details Ghidra misses, particularly around global variable
   initialization and string literal references.
3. **Fall back to `toolname_objdump.txt`** - When both decompilers disagree
   or produce obviously incorrect code, consult the raw disassembly.

## Important Context

The original ARM SDT executables were built for **32-bit x86 Linux**. The
decompiled code is x86 code. However, these tools *process and generate*
ARM code for the 3DO console. Keep this distinction in mind:

### Version String Extraction (Critical First Step)

Before starting cleanup, extract the version string from the original binary.
This is essential for binary compatibility:

```bash
# Extract version string from original binary
../bin/armlink -vsn
# Output: "ARM Linker vsn 5.20 (ARM Ltd SDT2.51) [Build number 130]"

../bin/armasm -vsn
# Output: "ARM AOF Macro Assembler vsn 2.50 (ARM Ltd SDT2.51) [Build number 110]"
```

Version strings:
- Must match exactly for binary compatibility
- Are embedded in OBJ_IDFN chunks in output files
- Serve as anchor points when searching decompiled code
- Help identify which decompiled functions handle version output

### Project Scope: What's Required vs Optional

The reimplemented tools only need to support 3DO development. This significantly
reduces scope:

**Required:**
- **ARMv3 ISA only** - The ARM60 CPU in the 3DO uses ARMv3. No need to support
  ARMv4, Thumb, or later instruction sets.
- **AOF object format** - ARM Object Format for `.o` files
- **AIF executable format** - ARM Image Format for final executables
- **ALF library format** - ARM Library Format for `.a` archives
- **Big-endian mode** - 3DO uses big-endian ARM

**Not required:**
- **ELF format** - Not used by 3DO toolchain; can be ignored entirely
- **DWARF debug info** - Not needed for 3DO builds; stub or skip these functions
- **Little-endian support** - 3DO is big-endian only
- **Later ARM features** - No Thumb, no ARMv4+, no VFP/NEON

When cleaning decompiled code, functions handling ELF or DWARF can be disabled
or stubbed out. Focus effort on AOF/AIF/ALF handling and ARMv3 instruction
encoding.

### Host vs Target Architecture

Keep this distinction in mind when reading decompiled code:

- **Host architecture (x86-32)**: The decompiled code itself, calling
  conventions, pointer sizes, struct layouts
- **Target architecture (ARM)**: Data structures describing ARM instructions,
  AOF/AIF file formats, relocation types, ARM register definitions

When you see constants like 0xE3A00000, these are ARM instruction encodings
being manipulated by x86 code, not x86 instructions.

## 32-bit to 64-bit Portability

The cleaned code will be compiled on a **64-bit host**, but the original
binaries were 32-bit. This creates important type considerations:

### Pointer vs Integer Ambiguity

In 32-bit code, `int32_t` and pointers are both 4 bytes. Decompilers often
represent pointers as `int32_t` since they cannot distinguish them. When
cleaning code, carefully evaluate whether a variable is:

- **Truly an integer**: Counters, sizes, flags, offsets, ARM constants
- **Actually a pointer**: Memory addresses, struct references, array bases

Signs that a variable is a pointer:
- Used as argument to malloc/free, fopen/fclose, fread/fwrite
- Dereferenced with `*(type *)var` or used with `->` operator
- Compared against NULL or 0 in pointer-like contexts
- Used in pointer arithmetic patterns (`base + offset`)

### Type Corrections

```c
// Before (decompiler 32-bit output):
int32_t buffer = malloc(size);
*(int32_t *)(buffer + 4) = value;

// After (64-bit clean):
char *buffer = malloc(size);
*(int32_t *)(buffer + 4) = value;
// Or better with struct:
header->field = value;
```

### Size-Sensitive Types

Use `size_t` and `ptrdiff_t` for sizes and pointer differences to ensure
portability:

```c
// Before:
int32_t len = strlen(str);
int32_t diff = ptr2 - ptr1;

// After:
size_t len = strlen(str);
ptrdiff_t diff = ptr2 - ptr1;
```

### Struct Layout Differences

The original binaries are 32-bit x86 Linux, so all decompiled struct offsets
assume 4-byte pointers and 32-bit alignment. When you recover a struct and
change pointer fields from `int32_t` to real pointer types, the 64-bit layout
**will differ** from the original. This is expected and correct for internal
structs -- but you must understand the implications.

**Two categories of structs:**

1. **File-format structs** (AOF headers, chunk entries, relocation records) --
   these represent on-disk binary layout. Use **only** fixed-size types
   (`uint32_t`, `int32_t`, `uint8_t`). Never put pointers in these structs.

2. **Internal structs** (symbol tables, area lists, parse state) -- these
   represent runtime data. Use real pointer types. Accept that the 64-bit
   layout will differ from the decompiled 32-bit offsets.

**Example: how layouts shift when pointers become 8 bytes:**

```
Original 32-bit layout:           Compiled 64-bit layout:
+0x00: char *name     (4 bytes)   +0x00: char *name     (8 bytes)
+0x04: uint32_t value (4 bytes)   +0x08: uint32_t value  (4 bytes)
+0x08: uint32_t flags (4 bytes)   +0x0C: uint32_t flags  (4 bytes)
+0x0C: node *next     (4 bytes)   +0x10: node *next      (8 bytes)
Total: 16 bytes                   Total: 24 bytes
```

**Critical rules for internal structs:**

- **Always use `sizeof()`** -- never hardcode allocation sizes like
  `malloc(16)`. Write `malloc(sizeof(symbol_t))`.
- **Never mix raw offsets with struct access** -- once you define a struct,
  all access must go through `->`. Do not use `*(int32_t *)(sym + 8)` and
  `sym->flags` in the same codebase for the same type.
- **Offset comments are for cross-referencing only** -- when you annotate
  struct fields with `/* +0x08 */`, these document the original 32-bit binary
  layout to help map back to the decompilation. They do NOT describe the
  compiled 64-bit layout.
- **Pointer fields change everything after them** -- inserting a pointer where
  the decompiler showed `int32_t` shifts all subsequent field offsets. Verify
  the struct against all access sites in the decompiled code.

```c
// Before (32-bit assumption):
struct node {
    int32_t data;
    int32_t next;  // Was a pointer in original
};

// After (64-bit correct):
struct node {
    int32_t data;
    struct node *next;  // 8 bytes on 64-bit; offsets after this shift
};
```

### Converting Struct Fields from int32_t to Pointers

When you identify that a struct field is actually a pointer (not an integer),
follow this procedure to convert it safely. Every step matters -- skipping
one creates silent 64-bit bugs.

**Step 1: Identify the field.** Use the signs from
[Pointer vs Integer Ambiguity](#pointer-vs-integer-ambiguity). Confirm by
checking every access site in the decompiled code.

**Step 2: Update the struct definition.** Change the field type and note
that the 64-bit layout shifts:

```c
// Before:
typedef struct symbol {
    int32_t name;       /* 32-bit +0x00: used with strcpy, strcmp */
    uint32_t value;     /* 32-bit +0x04 */
    uint32_t flags;     /* 32-bit +0x08 */
    int32_t next;       /* 32-bit +0x0C: compared to NULL, dereferenced */
} symbol_t;

// After:
typedef struct symbol {
    char *name;              /* 32-bit +0x00 */
    uint32_t value;          /* 32-bit +0x04 */
    uint32_t flags;          /* 32-bit +0x08 */
    struct symbol *next;     /* 32-bit +0x0C */
} symbol_t;
```

**Step 3: Fix all allocation sites.** Remove int32_t casts around malloc
and replace hardcoded sizes with sizeof:

```c
// Before (decompiler output):
int32_t sym = (int32_t)malloc(16);
*(int32_t *)(sym + 0) = (int32_t)strdup(name);
*(int32_t *)(sym + 0x0C) = 0;

// After:
symbol_t *sym = malloc(sizeof(symbol_t));
sym->name = strdup(name);
sym->next = NULL;
```

**Step 4: Fix all read/write access sites.** Replace every
`*(type *)(ptr + offset)` with struct field access:

```c
// Before:
if (*(int32_t *)(sym + 0x0C) != 0) {
    char *n = (char *)*(int32_t *)(sym + 0);
    uint32_t f = *(uint32_t *)(sym + 8);

// After:
if (sym->next != NULL) {
    char *n = sym->name;
    uint32_t f = sym->flags;
```

**Step 5: Fix pointer arithmetic and casts.** Remove all int32_t casts
around pointer values. These silently truncate on 64-bit:

```c
// Before (BROKEN on 64-bit -- truncates pointer):
*(int32_t *)(sym + 0x0C) = (int32_t)other_sym;
int32_t tmp = *(int32_t *)(sym + 0x0C);
if (tmp != 0) { process((void *)tmp); }

// After:
sym->next = other_sym;
if (sym->next != NULL) { process(sym->next); }
```

**Step 6: Fix function signatures.** Any function that takes or returns
this struct as int32_t must be updated:

```c
// Before:
int32_t find_symbol_804a234(int32_t head, int32_t name);

// After:
symbol_t *find_symbol_804a234(symbol_t *head, const char *name);
```

**Step 7: Fix linked list traversal.** The decompiler shows pointer
chasing as integer arithmetic:

```c
// Before:
int32_t cur = head;
while (cur != 0) {
    // ... use *(int32_t *)(cur + offset) ...
    cur = *(int32_t *)(cur + 0x0C);
}

// After:
for (symbol_t *cur = head; cur != NULL; cur = cur->next) {
    // ... use cur->field ...
}
```

**When you cannot convert all at once**, use `intptr_t` as a safe
intermediate type (see [Using intptr_t](#using-intptr_t-for-64-bit-safety)
below). Convert `int32_t` to `intptr_t` first to stop truncation, then
convert to proper pointer types as you understand more of the code.

### Using intptr_t for 64-bit Safety

When a variable holds a pointer but you need to preserve compatibility with
the original 32-bit integer operations, use `intptr_t`:

```c
// Mark pointer-width integers for 64-bit safety
intptr_t file_context;  // +16: pointer to file_chain_t

// Function signatures with pointer-width values
intptr_t hash_insert_804afc4(intptr_t a1, intptr_t a2);  // FIXED: 64-bit pointers

// Useful when gradually migrating from int32_t to proper pointers
// Can cast to actual pointer types when structure is understood:
file_chain_t *ctx = (file_chain_t *)file_context;
```

This pattern appears 200+ times in real cleanup work and provides a safe
intermediate step between raw `int32_t` and fully-typed pointers.

### Common Pitfalls

- `sizeof(pointer)` is 8 on 64-bit, not 4
- Casting pointers to/from `int32_t` truncates on 64-bit
- Array indexing with `int32_t` is fine; storing addresses in `int32_t` is not
- Function pointers are 8 bytes on 64-bit

### Testing Strategy: 32-bit First, Then 64-bit

During development, it can be useful to initially build and test in 32-bit
mode to confirm functional equivalence with the original binary, then
upgrade to 64-bit compatible types:

1. **Phase 1 - 32-bit verification**: Build with `-m32` to match original
   pointer sizes. This lets you verify behavior without worrying about
   type width issues:
   ```bash
   gcc -m32 -Wall -g -o test_32 FILENAME_cleaned.c
   # Compare output against original binary
   ```

2. **Phase 2 - 64-bit migration**: Once functionality is confirmed, update
   pointer types and rebuild for 64-bit:
   ```bash
   gcc -Wall -g -o test_64 FILENAME_cleaned.c
   ```

3. **Phase 3 - Verify both**: Ensure both builds produce identical output
   for the same inputs.

This approach isolates type-width bugs from logic bugs, making debugging
easier. Note: 32-bit builds require multilib support (`gcc-multilib` or
equivalent package).

### Comparing Against Original Executable

Once the cleaned code compiles, use the original ARM SDT executable in
`../bin/` (relative to each tool's decomp/ directory) as the reference for
correctness.

Run the original executable without arguments or with `-help` to obtain the
usage information. This reveals the tool's supported options, flags, and
input/output patterns. Then systematically compare behavior between the
original and cleaned versions across all usage patterns and flag permutations.

The goal is functional equivalence: identical output, exit codes, and error
messages for the same inputs across all supported options.

## Basic Rules

The original decompilation files must NEVER be modified. All cleanup work
goes in `toolname/recompiled/src/` and all from-scratch work goes in
`toolname/recreated/src/`.

For each function and variable evaluate the behavior and usage, write
a human readable description just before the definition in the code,
and rename the function or variable to match. When renaming keep the
unique identifier part of the function or variable as a suffix for
easy comparison to the original file.

If a variable is clearly a pointer modify the type accordingly. The
original application used 32bit pointers and integers.

Attempt to give names to any literal values that are not simply 0 or
null initializers. There should be no "magic numbers", unnamed
literals or constants.

## Processing Order

1. Start with leaf functions (those that call nothing or only stdlib)
2. Work up the call graph - clean callees before callers
3. Process related functions together (e.g., all chunk I/O functions)
4. Main/entry point functions last, after helpers are understood

## Structure Recovery

Identify patterns that suggest struct usage:
- Sequential memory accesses at fixed offsets from a base pointer
- Groups of related variables passed together to functions
- Create typedef struct definitions and replace offset arithmetic with field access

Example:
```c
// Before: *(int32_t *)(base + 8) = value;
// After:  header->entry_point = value;
```

### Do NOT Use Macros for Field Access

**Never** replace `*(type *)(ptr + offset)` patterns with `#define` accessor
macros. This is a common temptation but it is the wrong approach:

```c
/* BAD -- Do NOT do this */
#define SYM_NAME(s)   (*(char **)((s) + 0))
#define SYM_VALUE(s)  (*(uint32_t *)((s) + 4))
#define SYM_FLAGS(s)  (*(uint32_t *)((s) + 8))
#define SYM_NEXT(s)   (*(intptr_t *)((s) + 12))

flags = SYM_FLAGS(sym);  /* Looks clean but hides real problems */
```

Why macros are wrong:
- **No type safety** -- the compiler cannot check that `s` is the right kind of
  pointer, or that the offset matches the intended field
- **Defeats 64-bit porting** -- pointer fields still look like integer arithmetic,
  so sizeof(pointer) bugs remain hidden
- **Hides bugs** -- wrong offset or wrong cast silently compiles
- **Harder to maintain** -- every call site re-casts; changing a field type
  requires updating the macro AND every use, instead of just the struct

The correct approach is **always** a struct definition:

```c
/* GOOD -- define a struct, cast once, use -> */
typedef struct symbol {
    char *name;           /* 32-bit +0x00 */
    uint32_t value;       /* 32-bit +0x04 */
    uint32_t flags;       /* 32-bit +0x08 */
    struct symbol *next;  /* 32-bit +0x0C */
} symbol_t;

symbol_t *sym = (symbol_t *)raw_ptr;
flags = sym->flags;  /* Type-safe, 64-bit correct */
```

Even if you have not identified all fields yet, define the struct with
placeholder fields for the gaps. Offset comments document the **original
32-bit binary layout** for cross-referencing with the decompilation -- the
compiled 64-bit layout will differ wherever pointer fields appear (see
[Struct Layout Differences](#struct-layout-differences)):

```c
/* Offsets are from the original 32-bit binary (4-byte pointers).
 * On 64-bit, pointer fields are 8 bytes so compiled offsets will shift.
 * Always use sizeof() and -> access, never hardcoded offsets.
 */
typedef struct context {
    uint32_t unknown_00;   /* 32-bit +0x00: purpose TBD */
    uint32_t unknown_04;   /* 32-bit +0x04: purpose TBD */
    FILE *stream;          /* 32-bit +0x08: identified from fread() usage */
    uint32_t unknown_0c;   /* 32-bit +0x0C: purpose TBD */
    uint32_t flags;        /* 32-bit +0x10: identified from bitmask tests */
} context_t;
```

A partial struct with `unknown_XX` placeholders is always better than macros.
It gives you type safety on the fields you do understand, and clearly marks
what still needs analysis.

### Linked List Patterns

ARM SDT tools use linked lists throughout, NOT arrays. Recognizing this is
critical for understanding data flow:

```c
// Pattern to recognize in decompiled code:
v1 = head;
while (v1 != 0) {
    // process *(v1 + offset)
    v1 = *(int32_t *)(v1 + 12);  // next pointer at offset 12
}

// Clean version:
for (symbol_t *sym = head; sym != NULL; sym = sym->next) {
    // process sym->field
}
```

Common linked list structures in this codebase:
```c
struct symbol_t {
    char *name;
    uint32_t value;
    uint32_t flags;
    struct symbol_t *next;  // Chain to next symbol
};

struct area_t {
    char *name;
    uint32_t attributes;
    uint8_t *data;
    struct reloc_t *relocs;  // Linked list of relocations
    struct area_t *next;     // Chain to next area
};
```

### Cross-Tool Type Consistency

Similar types exist across tools. Cross-reference existing implementations
when recovering structs:
- `chunk_file_t` defined similarly in decaof, 3dolib, 3doasm, 3dolink
- `area_t`, `symbol_t`, `reloc_t` follow the same basic patterns
- Check `decaof/src/` and `3dolib/src/` for working definitions
- Consider the existing documentation in `docs/AOF_FORMAT_SPECIFICATION.md`

## Array Recognition

Look for patterns like `base + (index * element_size)` and convert to
proper array notation. Identify fixed-size arrays from loop bounds.

Example:
```c
// Before: *(int32_t *)(table + i * 4)
// After:  table[i]
```

## Control Flow Simplification

- Convert goto-based loops to while/for loops where pattern is clear
- Flatten deeply nested if-else chains into switch statements when appropriate
- Replace `if (cond) { return x; } return y;` with ternary or early returns
- Identify and label error handling paths vs normal execution

### State Machine Gotos

Some goto patterns should NOT be refactored. When gotos form a state machine
or complex control flow, they may be safer left as-is:

```c
// Example: 20+ gotos forming a state machine in armlib
// Mark with TODO explaining why they're retained:

/* TODO: These gotos form a state machine for library traversal.
 * Refactoring to structured control flow would require major
 * architectural changes. Left as-is for now.
 */
state_open:
    if (condition1) goto state_read;
    goto state_error;
state_read:
    // ...
```

Signs that gotos should be kept:
- Cleanup/resource release patterns (goto cleanup)
- State machine transitions between labeled states
- Error handling that needs to skip multiple cleanup steps
- Code where incorrect refactoring risks breaking behavior

### Dead Code Removal

Decompilers sometimes generate duplicated or unreachable code blocks. Safely
identify and remove them:

```c
// Pattern: Code after unconditional return
return result;
// Dead code below - RetDec artifact
v1 = something;  // Never executed
goto label_123;  // Never reached
```

Before removing dead code:
1. Verify the code is truly unreachable (not reached by goto from elsewhere)
2. Check that removal doesn't affect other code paths
3. Document what was removed in a comment:

```c
/* REMOVED: Duplicated unreachable block from lines 2440-2450.
 * Original decompiler output had identical code after return statement.
 */
```

## Named Constants and Enums

Beyond non-zero literals, also consider:
- Create enums for related flag values
- Use #define for bit masks with descriptive names
- Reference existing definitions from docs/ where applicable

Example:
```c
// Before: if ((flags & 0x100) != 0)
// After:  if (flags & AREA_FLAG_CODE)
```

## ARM Target Patterns (Data Processed by These Tools)

These patterns appear in the data structures and constants that the tools
manipulate, not in the x86 decompiled code flow itself. **Only ARMv3 needs
to be supported** (ARM60 CPU in 3DO):

- APCS calling convention: r0-r3 are arguments, r0 is return value
- ARMv3 instruction encodings (condition codes in bits 28-31, opcodes, etc.)
- BL (branch-link) instruction encoding: 0xEB000000 | offset
- Relocation types for ARM: PC-relative, absolute, based
- 32-bit ARM pointers and addresses in AOF/AIF structures
- Big-endian byte order for all ARM data

**Not needed:** Thumb instructions, ARMv4+ extensions, coprocessor instructions
beyond basic FPU stubs, or any features added after ARMv3.

## 3DO/AOF-Specific Patterns

- Chunk file magic: 0xC3CBC6C5 - recognize chunk parsing loops
- Symbol flags follow AOF specification (see docs/AOF_FORMAT_SPECIFICATION.md)
- Big-endian byte swapping patterns: `(x >> 24) | ((x >> 8) & 0xFF00) | ...`

### DWARF Debug Format (Not Required)

The decaof tool has 12+ functions for DWARF debug information handling:
- DWARF tags (DW_TAG_*), attributes (DW_AT_*), forms (DW_FORM_*)
- Location expression parsing
- Line number information

**DWARF is not needed for 3DO development.** The 3DO toolchain builds with
`-nodebug` and DWARF sections are stripped. These functions can be stubbed
out or disabled entirely. Mark them clearly:

```c
/* DWARF: decode_location_804f234
 * Handles DWARF location expressions for debug info.
 * Not needed for basic AOF dump - stub returns empty string.
 * TODO: Implement if full -d debug output is needed.
 */
static const char *decode_location_804f234(uint8_t *data, size_t len) {
    return "<location>";  // Stub
}
```

## Ghidra-Specific Cleanup

Since Ghidra is the primary decompilation reference, understanding its
artifacts is critical.

### Ghidra Naming Conventions

Ghidra generates systematic but meaningless names that all need replacement:

- **Functions**: `FUN_XXXXXXXX` (e.g., `FUN_0804a988`) -- rename based on
  behavior, keeping address suffix (e.g., `parse_chunk_804a988`)
- **Globals**: `DAT_XXXXXXXX` (e.g., `DAT_0804d844`) -- rename based on usage
- **String pointers**: `PTR_s_string_XXXXXXXX` (e.g., `PTR_s_#none_0807199c`)
- **Parameters**: `param_1`, `param_2`, etc.
- **Local variables**: `local_XX` with hex stack offsets (e.g., `local_14c`)
- **Typed temporaries**: prefix indicates type -- `uVarN` (unsigned),
  `iVarN` (int), `pVarN` (pointer), `bVarN` (byte/bool), `cVarN` (char),
  `pcVarN` (char pointer), `puVarN` (unsigned pointer)
- **Stack arrays**: `auStack_X` (unsigned array), `acStack_X` (char array)
- **Goto labels**: `LAB_XXXXXXXX`
- **Switch labels**: `switchD_XXXXXXXX_caseD_XX`

### Ghidra Type Artifacts

Ghidra uses non-standard type names that must be replaced:

| Ghidra type | Replace with |
|-------------|-------------|
| `undefined1` | `uint8_t` or `char` |
| `undefined2` | `uint16_t` or `int16_t` |
| `undefined4` | `uint32_t`, `int32_t`, or pointer |
| `undefined` | Determine from context |
| `byte` | `uint8_t` |
| `word` | `uint16_t` |
| `dword` | `uint32_t` |
| `uint` | `unsigned int` |
| `ulong` | `unsigned long` or `size_t` |
| `longlong` | `int64_t` |
| `code *` | Proper function pointer type |

### Ghidra Control Flow Artifacts

- **Infinite loops**: `do { ... } while(true)` with `break` -- often a loop
  Ghidra couldn't fully recover. Determine the real loop condition.
- **Goto chains**: `LAB_XXXXXXXX` labels with gotos -- many can be refactored
  to structured if/else or switch, but some are legitimate state machines.
- **WARNING comments**: Ghidra inserts `// WARNING: Subroutine does not return`
  before `exit()` calls, and `// WARNING: Unknown calling convention` when it
  cannot determine parameter passing. These are helpful hints -- read them.

### Ghidra Special Constructs

- **CONCAT operations**: `CONCAT11(a, b)`, `CONCAT31(a, b)` -- combines
  smaller values into larger ones. Usually indicates bitfield packing or
  register pair operations. Replace with explicit shifts and ORs.
- **extraout variables**: `extraout_var`, `extraout_EAX` -- values left in
  registers after function calls that Ghidra couldn't map to a return value.
  Usually indicates misunderstood calling convention; verify against objdump.
- **Stack references**: `&stack0x0000000c` -- direct stack addressing for
  variadic function arguments (e.g., `vfprintf(stderr, fmt, &stack0x0c)`).
  Replace with proper `va_list` usage.

### Ghidra Misleading Patterns

**Manual strlen loops** -- Ghidra decompiles glibc's optimized `strlen` as:
```c
uVar2 = 0xffffffff;
pcVar4 = str;
do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
} while (cVar1 != '\0');
len = ~uVar2 - 1;
```
Replace with: `len = strlen(str);`

**False array indexing** -- pointer arithmetic that looks like arrays:
```c
(&DAT_0807f340)[param_1 * 2]  // Not really an array
```
Verify whether this is a real array or offset calculation.

**Alignment calculations** -- bitwise idioms for rounding:
```c
~uVar2 + 3 & 0xfffffffc  // Really: (n + 3) & ~3 (round up to 4)
```
Replace with a named macro: `ALIGN4(n)`.

**Duplicate global types** -- Ghidra sometimes declares the same address
with different types:
```c
uint *DAT_0807b298;       // One place
undefined4 DAT_0807b298;  // Another place, same address!
```
Determine the true type through usage analysis.

## Decompiler Artifact Cleanup

Common artifacts from both decompilers:

- Remove redundant casts: `(int32_t)(int32_t)x` -> `x`
- Simplify `result = x; return result;` -> `return x;`
- Replace `v1 = func(); if (v1 != 0)` with `if (func())`
- Decompiler-generated names like `g1`, `v2`, `a1` should all be renamed
- Watch for incorrect sign extension - verify against actual behavior

## Handling Decompiler Failures

Neither decompiler perfectly recovers all code. Know when to disable broken
code versus attempting to fix it.

### Placeholder Variables

The `placeholder_g279` pattern indicates RetDec couldn't decode stack
parameters. This is a RetDec-specific artifact; Ghidra does not produce
these. It appears 1300+ times in armlink's RetDec output:

```c
// RetDec output with placeholder:
int32_t result = func_804a234(a1, placeholder_g279, a3);

// This usually means the parameter was passed on the stack
// You may need to analyze the calling convention or look at
// the assembly to understand what's actually being passed
```

### Disabled/Broken Modules

Some decompiled code simply cannot work due to uninitialized pointer bases
or other fundamental issues. Mark and disable these:

```c
/* DISABLED: Demangler module (demangler_8051234 through demangler_8051890)
 * RetDec produced code with uninitialized pointer bases that crash on 64-bit.
 * Original armlink demangler functionality is not critical for basic linking.
 *
 * To re-enable: Would need to reverse-engineer the demangler from scratch
 * using the original binary's behavior as reference.
 */
#if 0  /* DEMANGLER_DISABLED */
static char *demangle_symbol_8051234(const char *mangled) {
    // Broken decompiled code here
}
#endif
```

### Compiler Pragmas for Known Issues

Use pragmas to suppress warnings for known decompiler artifacts that you
cannot immediately fix:

```c
// At the top of the file, suppress known harmless warnings:
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"

// For specific problematic sections:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"
// ... code with known false positive ...
#pragma GCC diagnostic pop
```

Use sparingly - pragmas should mark known issues, not hide real bugs.

## Documenting Uncertainty

- Mark uncertain interpretations with `/* UNCERTAIN: ... */`
- Use `/* TODO: ... */` for areas needing further analysis
- Keep a mapping table of original names to new names in comments at file top

Example header:
```c
/*
 * Function name mapping:
 *   function_0x1234 -> parse_chunk_header_0x1234
 *   function_0x5678 -> read_symbol_table_0x5678
 *
 * Global variable mapping:
 *   g1 -> chunk_count_g1
 *   g2 -> current_area_g2
 */
```

### Binary Compatibility Comments

Mark sections that are critical for binary compatibility with the original
tools. These must not be modified without careful testing:

```c
/* BINARY COMPAT: This version string must match original exactly.
 * Used in OBJ_IDFN chunk and affects binary comparison tests.
 * From: 3doasm/src/aof_write.c:34
 */
#define ASSEMBLER_VERSION "ARM AOF Macro Assembler vsn 2.50 (ARM Ltd SDT2.51)"

/* BINARY COMPAT: Area alignment padding must match armlink behavior.
 * Changing this breaks byte-for-byte output comparison.
 */
static void pad_to_alignment_804b456(uint32_t align) {
    // ...
}

/* BINARY COMPAT: Symbol ordering in output must follow original.
 * See test failures if changed.
 */
```

These comments alert future maintainers that changes require verification
against the original binaries.

## Verification Strategy

**The project requires byte-for-byte output matching with the original tools.**
This is the ultimate test of cleanup correctness.

### Byte-for-Byte Verification

After cleaning a function, verify behavior matches original by:
1. Comparing output against original binary for known inputs
2. Using test cases from the test suite
3. Stepping through with a debugger if unclear

Binary comparison for output files:
```bash
# Direct binary comparison (strictest test)
cmp original.aif reimplemented.aif

# Or with diff for readable output
diff <(xxd original.aif) <(xxd reimplemented.aif)
```

### Semantic Comparison

When byte-for-byte matching isn't possible (e.g., symbol ordering differs),
use semantic comparison via decaof:

```bash
# Compare via disassembly - content must match even if bytes differ
diff <(../bin/decaof -agst orig.o) <(./build/decaof -agst new.o)

# Compare linked output behavior
diff <(../bin/decaof -agst original.aif) <(../bin/decaof -agst reimplemented.aif)
```

### What Must Match Exactly

- Version strings (even whitespace matters)
- AOF chunk ordering and padding
- Symbol values and flags
- Relocation entries
- AIF header fields

### What May Differ

- Symbol ordering within tables (if content is equivalent)
- Internal temporary file handling
- Debug/diagnostic output formatting

### Build Testing

Each subproject has its own Makefile. Build frequently during cleanup to
catch issues early:

```bash
# Build the recompiled version
cd toolname/recompiled && make

# Run its tests
make test

# Quick syntax check during iterative cleanup
gcc -Wall -Wextra -c -fsyntax-only src/toolname.c
```

Use `-fsyntax-only` for quick syntax checking without full compilation.
Build after each major change to catch type errors, missing declarations,
and syntax issues.

## Commit Strategy

- Commit after each logical group of functions is cleaned
- Include before/after function name mapping in commit message
- **Only commit source code, test scripts, test fixtures, Makefiles, and
  documentation.** Never commit build artifacts (`.o` files, `.d` files,
  compiled executables in `build/`). The `build/` directory should be in
  `.gitignore` for every subproject. If a binary or object file shows up
  in `git status`, do not `git add` it.

## String Literals and Error Messages

Error messages and debug strings reveal function purpose:
- Search for string literals passed to printf/fprintf/error functions
- Error messages often name the operation: "failed to open file" -> file_open function
- Use strings to name functions when behavior is unclear
- Look for usage strings that describe command-line options

## Standard Library Patterns

Recognize common stdlib usage:
- malloc/free pairs - track allocation lifetimes
- fopen/fread/fwrite/fclose - file I/O sequences
- strcmp/strcpy/strlen - string handling
- memcpy/memset - bulk memory operations
- getopt/argc/argv - command-line parsing

## POSIX Types and Structures

Decompilers often generate custom struct definitions for standard POSIX types.
Check structs and POD types against POSIX standards and replace with proper
types from system headers:

### Common Replacements
- Custom file structs -> `FILE *` (from `<stdio.h>`)
- Custom stat structs -> `struct stat` (from `<sys/stat.h>`)
- Custom time structs -> `time_t`, `struct tm` (from `<time.h>`)
- Custom dir structs -> `DIR *`, `struct dirent` (from `<dirent.h>`)
- 32-bit integer types -> `int32_t`, `uint32_t` (from `<stdint.h>`)
- Size types -> `size_t`, `ssize_t` (from `<stddef.h>`, `<sys/types.h>`)
- Offset types -> `off_t` (from `<sys/types.h>`)

### Identification Hints
- Structs passed to fread/fwrite/fseek/ftell are likely `FILE *`
- Structs populated by stat()/fstat() are `struct stat`
- Return values from opendir() are `DIR *`
- Arguments to read()/write() use `size_t` and `ssize_t`

### Example
```c
// Before (decompiler output):
struct struct_12345 {
    int32_t field_0;
    int32_t field_4;
    // ... many fields
};
int32_t result = fread(buf, 1, size, (struct struct_12345 *)stream);

// After:
#include <stdio.h>
size_t result = fread(buf, 1, size, stream);  // stream is FILE *
```

### Standard Headers to Include
```c
#include <stdint.h>     /* int32_t, uint32_t, etc. */
#include <stddef.h>     /* size_t, NULL */
#include <stdio.h>      /* FILE, fopen, fread, etc. */
#include <stdlib.h>     /* malloc, free, exit */
#include <string.h>     /* memcpy, strcpy, strlen */
#include <sys/types.h>  /* off_t, ssize_t */
#include <sys/stat.h>   /* struct stat, stat() */
#include <fcntl.h>      /* open flags: O_RDONLY, etc. */
#include <unistd.h>     /* read, write, close */
#include <dirent.h>     /* DIR, opendir, readdir */
#include <errno.h>      /* errno, error codes */
```

### PLT Stub Wrappers for glibc Internals

RetDec sometimes generates calls to glibc internal functions (prefixed with
`__`) that aren't part of the public API. Create wrapper functions using
standard POSIX equivalents:

```c
/* Wrapper for glibc internal __xstat - use standard stat() */
static int __xstat_wrapper(int ver, const char *path, struct stat *buf) {
    (void)ver;  /* Version parameter not needed with standard stat */
    return stat(path, buf);
}

/* Wrapper for glibc internal __fxstat - use standard fstat() */
static int __fxstat_wrapper(int ver, int fd, struct stat *buf) {
    (void)ver;
    return fstat(fd, buf);
}

/* Wrapper for glibc internal __lxstat - use standard lstat() */
static int __lxstat_wrapper(int ver, const char *path, struct stat *buf) {
    (void)ver;
    return lstat(path, buf);
}
```

Then replace calls in the decompiled code:
```c
// Before (RetDec output):
__xstat(1, filename, &statbuf);

// After:
stat(filename, &statbuf);  // Or use wrapper if gradual cleanup
```

## Function Pointers and Dispatch Tables

Look for:
- Arrays of function pointers (operation dispatch tables)
- Callback patterns where function pointers are passed as arguments
- Switch statements that could be replaced with dispatch tables
- vtable-like structures for polymorphic behavior

## Printf Format String Type Inference

Use format specifiers to determine variable types:
- %d, %i -> int
- %u, %x, %X -> unsigned int
- %s -> char*
- %p -> void*
- %ld -> long
- %08x -> likely a 32-bit address or flags field

## Recompiled File Structure

Organize recompiled source files with this structure. Include status tracking
and remaining work to help coordinate efforts:

```c
/*
 * toolname/recompiled/src/toolname.c
 * Cleaned recompilation of toolname from Ghidra decompilation
 *
 * Source: toolname/toolname (ARM SDT 2.51, original binary)
 * Primary reference: toolname/toolname_decomp_ghidra.c
 * Secondary reference: toolname/toolname_decomp_retdec.c
 *
 * Status: ~40% complete
 * Last updated: 2024-01-15
 *
 * Remaining work:
 *   - 119 field_ references need struct recovery
 *   - Functions 0x8051000-0x8051FFF not yet analyzed
 *
 * Known issues:
 *   - DWARF functions stubbed out (not needed for basic operation)
 *   - Some gotos retained in state machine code (see TODO comments)
 *
 * Function name mapping:
 *   function_0x8041234 -> parse_chunk_header_8041234
 *   function_0x8045678 -> read_symbol_table_8045678
 *   ...
 *
 * Global variable mapping:
 *   g1 -> chunk_count_g1
 *   g2 -> current_area_g2
 *   ...
 */

/* Compiler pragmas for known decompiler artifacts */
#pragma GCC diagnostic ignored "-Wunused-variable"

/* Includes */
#include <stdint.h>
#include <stdio.h>
...

/* Constants and Macros */
#define CHUNK_MAGIC 0xC3CBC6C5
...

/* Type Definitions */
typedef struct { ... } chunk_header_t;
...

/* Global Variables */
static int32_t chunk_count_g1;
...

/* Forward Declarations */
static int parse_header_0x1234(void *data);
...

/* Function Implementations (leaf functions first) */
...
```

## Recreated File Structure

Organize recreated source files with clean, modern C structure:

```
toolname/recreated/
|-- Makefile
|-- src/
|   |-- main.c           # Entry point, argument parsing
|   |-- toolname.h       # Public API and shared types
|   |-- chunk_io.c       # Chunk file reading/writing
|   |-- aof.c            # AOF format handling
|   `-- ...
|-- tests/
|   |-- test_main.c      # Test runner
|   |-- test_chunk_io.c  # Unit tests for chunk I/O
|   `-- ...
`-- build/
```

The recreated version should:
- Use clear module boundaries with well-defined headers
- Not carry decompiler artifacts or address suffixes
- Be written as if from scratch, using modern C conventions
- Share no code with the recompiled version (independent implementation)

## Documentation

Additional information, particularly with regard to file formats used
by the apps, can be found in the docs/ directory. All documentation must
be written in Markdown using ASCII only -- no Unicode characters.


## Commit changes

Every change of note should be committed in git with a description of
the change. Commit messages must use ASCII only -- no Unicode characters.


## End State

A tool is complete when ALL of the following are met:

1. **Both implementations exist** -- recompiled and recreated versions are
   built and functional.
2. **Byte-for-byte identical output** -- both produce output identical to the
   original tool for all supported inputs. Any behavioral difference is a bug.
3. **100% test coverage** -- unit tests cover every function and code path;
   integration tests exercise every command-line option, flag combination,
   and error condition.
4. **3do-devkit integration** -- both can transparently replace the original
   in 3do-devkit to rebuild libraries, object files, assembly files, and
   executables.
5. **Comprehensive documentation** -- each tool has documentation within its
   directory covering functionality, supported options, file formats, internal
   architecture, and any limitations relative to the original.
6. **Build independence** -- both produce identical output regardless of
   optimization level or other compiler options.
7. **Build cleanly** -- There should be no undefined behavior / UB in
   these applications and no warnings or errors at build time
   regardless of settings. Build options should be strict.
8. Once functionally complete and identical the recompiled and
   recreated tools, if it exists as a single file, should be broken up
   by class of functions for human readability and maintainability.
