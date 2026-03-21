# Generic Step 1 - Reverse engineer and recompile

## Objective

This document centralizes shared step 1 guidance that applies to every tool. Per-tool `*_step1.md` files keep only tool-specific details (profile metadata, concrete paths, and tool-specific focus).

Use decompiled sources as reverse-engineering inputs to produce a compilable C89 implementation in `<tool>/recompiled/` that matches original behavior exactly for every input form, option path, output artifact, diagnostic, exit code, and edge case present in the original binary while reconstructing the likely original source structure. Remove decompiler artifacts and recover plausible original names, types, control flow, and data layout, but do not materially redesign algorithms, helper structure, or module boundaries unless strong evidence or a narrowly justified portability fix requires it. Start by copying `<tool>/<tool>_decomp_ghidra.c` into the recompiled source tree, commit that baseline, and then iterate until the result is compilable and fully functional.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: generic-step1
  step: 1
  applies_to: all tools
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - <tool>/<tool>
    - <tool>/<tool>_decomp_ghidra.c
    - <tool>/<tool>_decomp_retdec.c
    - <tool>/<tool>_objdump.txt
    - <tool>/<tool>_readelf.txt
    - <tool>/<tool>_usage.txt
  must_outputs:
    - <tool>/recompiled/Makefile
    - <tool>/recompiled/src/
    - <tool>/recompiled/tests/
    - <tool>/recompiled/build/<tool>
  status_values:
    - confirmed
    - open
    - blocked
  closeout_requirements:
    - no externally visible mismatch
    - tests pass with parity evidence
    - unresolved items remain only as blocked with closure experiments
```

## Workflow entrypoint

Start from [README.md](README.md) before reading this file.

- Use [workflow_manifest.json](workflow_manifest.json) to determine tool order, step readiness, and resume rules.
- This file is the canonical shared guidance for step 1 across all tools.
- Tool-specific `*_step1.md` files add concrete paths, profile metadata, and tool-specific focus.

## Exact-original parity rule

- Default requirement is exact parity with the original binary for all externally visible behavior.
- Treat original runtime behavior as ground truth when decompilers or docs disagree.
- Do not accept "close enough" behavior for outputs, diagnostics, exit semantics, option precedence, or edge handling.
- If parity cannot be proven for an original behavior, record it as `UNCERTAIN` with evidence and closure experiments; do not mark the step complete.

## Original-source reconstruction rule

- Treat step 1 as evidence-based reconstruction of likely original C89 source, not as general refactoring or modernization.
- Preserve likely original function boundaries, control-flow shape, state-machine structure, data layout, and helper granularity when evidence supports them.
- Do not split, merge, or invent helper functions, abstractions, or modules unless strong evidence suggests the original source likely had them or a narrowly scoped portability fix requires it.
- Use renames, recovered structs, constants, and similar edits only to remove decompiler artifacts and move the code toward plausible original C89 source form.

## Tool profile

- Directory: `<tool>/`
- Tool: <tool binary name and version>
- Description: <tool purpose summary>
- Original binary size: <size>
- Recompiled priority: <recompiled priority>

## Required references and inputs

- `<tool>/<tool>` (original binary, read-only oracle)
- `<tool>/<tool>_decomp_ghidra.c` (primary decompilation reference)
- `<tool>/<tool>_decomp_retdec.c` (secondary decompilation reference)
- `<tool>/<tool>_objdump.txt` (instruction-level disassembly)
- `<tool>/<tool>_readelf.txt` (ELF metadata and symbols)
- `<tool>/<tool>_usage.txt` (captured `-help` behavior)

## Tool directory reference roles

Use each artifact for its strongest signal:

- Original binary: final behavioral oracle for outputs, exit codes, and diagnostics.
- Ghidra decompilation: first-pass logic and control-flow recovery.
- RetDec decompilation: secondary cross-check, especially when globals or literals differ.
- Objdump: instruction-level tie-breaker when decompilers disagree.
- Readelf: symbol/section/import context and dynamic-link hints.
- Usage capture: authoritative CLI surface and option combinations.

## Required outputs

- `<tool>/recompiled/Makefile`
- `<tool>/recompiled/src/` reconstructed source that aims to preserve likely original C89 names, types, and structure
- `<tool>/recompiled/tests/` shared test suite for original and recompiled binaries
- `<tool>/recompiled/build/<tool>`

## Required bootstrap sequence

For a new or reset step 1 effort, preserve the raw Ghidra-derived starting point before reconstruction work begins:

1. Copy `<tool>/<tool>_decomp_ghidra.c` into `<tool>/recompiled/src/` as the initial implementation baseline.
2. Commit that copied baseline before structural recovery, type recovery, portability edits, compile fixes, or behavior repairs.
3. Then iterate on that checked-in file until the recompiled implementation builds, passes tests, and reaches exact-original parity.

The initial baseline commit is expected to contain rough decompiler output. Its purpose is traceability to the primary decompilation input, not step completion by itself.

## Agent execution protocol

### Preflight checklist

- Confirm required references exist and are readable.
- Confirm parity scope from original behavior and usage captures for this run (architectures, formats, endianness, and diagnostics).
- Capture baseline `-vsn` and `-help` behavior from the original binary before editing.
- Confirm test harness can execute original and recompiled binaries from one entry point.
- Identify any known unresolved modules/paths and ensure they are explicitly documented with closure experiments.

### Optional bootstrap commands (first five)

```bash
cd <tool>/recompiled
make clean
make
make test
../<tool> -vsn
```

### Required evidence artifacts per reconstruction batch

- Command transcript (or equivalent log) for build and tests.
- Fixture IDs used for behavior checks.
- Exit code plus stdout/stderr captures for compatibility-sensitive cases.
- Output parity evidence (`cmp` results for byte-for-byte checks, or approved semantic diff output).

### Hard-stop and escalation conditions

- Stop if original runtime behavior contradicts decompiler-derived assumptions.
- Stop if a change weakens tests that pass on the original binary.
- Stop if pointer typing remains ambiguous in compatibility-critical paths.
- Escalate with explicit `UNCERTAIN` notes and closure experiments when evidence is insufficient.

### Completion gate (objective)

Only close a reconstruction batch when all of the following are true:

1. Build and test commands complete successfully with recorded outputs.
2. Compatibility-sensitive behaviors under edit have new or refreshed parity evidence.
3. New uncertainty is explicitly tracked (`UNCERTAIN`/`TODO`) with next actions.
4. No hard-stop issue remains unresolved.

## Build system requirements

Each subproject Makefile must be simple and self-contained:

- No recursive make and no autotools.
- Object files and dependency files go in `build/`.
- Final executable goes in `build/`.
- `make` builds executable.
- `make test` runs full test suite.
- `make clean` removes build artifacts.
- `make help` lists available targets.

## Test requirements

- Tests live under `tests/` and run via `make test`.
- Include unit tests and integration tests against original behavior.
- Use a simple local test framework with no heavy external dependency.
- Cover normal paths, edge cases, malformed input, and error handling.
- Exercise every required option and flag combination, including repeated/conflicting forms and precedence-sensitive cases.
- Target exhaustive coverage of original behavior: every public function, meaningful branch, required option combination, and required error path.
- Do not leave failing tests unresolved; if original passes and recompiled fails, implementation is wrong.

### Test-first adversarial workflow

1. Write tests before implementation changes.
2. Confirm tests pass on original binary first.
3. Run against recompiled build and expect failures.
4. Implement until tests pass without weakening assertions.
5. Add additional adversarial tests after initial pass.

### Two-way testing (required)

Every test in step 1 should run against both versions:

1. Original: `<tool>/<tool>`
2. Recompiled: `<tool>/recompiled/build/<tool>`

Use one shared test harness for these two binaries in step 1. If a test passes on original but fails on recompiled, implementation is wrong.

```bash
TOOLS=(
  "../../<tool>"
  "../recompiled/build/<tool>"
)

for TOOL in "${TOOLS[@]}"; do
  run_tests "$TOOL"
done
```

### Two-way testing continuity

Project-level parity is three-way (original, recompiled, recreated). During step 1, tests run on original and recompiled because recreated may not exist yet, but keep one shared harness shape so `recreated/build/<tool>` can be added without rewriting tests.

## Analysis workflow and source priority

- Start by copying Ghidra output into the recompiled source tree and committing that baseline first.
- Cross-check with RetDec when unclear.
- Use objdump and readelf when decompilers disagree.
- Treat original runtime behavior as the final oracle.

## Critical context to lock first

### Version string extraction

Extract and record exact `-vsn` output from the original binary before reconstruction starts:

```bash
./<tool>/<tool> -vsn
```

This string is compatibility-critical: it must match exactly (including spacing and punctuation), can appear in identity metadata output paths, and is a reliable anchor for finding version-reporting code in decompiled sources.

### Scope boundaries

Required scope for this project:

- Full original behavior parity for all CLI and processing workflows present in the original binary.
- All AOF object handling, AIF executable handling, and ALF library handling present in the original tool.
- Endianness and metadata rules exactly as emitted/consumed by the original binary.
- Architecture- and directive-specific behavior observed in runtime evidence.

Coverage baseline for this project:

- Preserve full original behavior across all forms, options, targets, architecture modes, endianness modes, formats, diagnostics, and edge cases present in the original executable.
- Treat every original feature path as in scope for reverse engineering, specification, and recreation.
- Use runtime evidence to resolve ambiguities; do not scope original behavior out of implementation.

### Host versus target architecture

- Decompiled code reflects host x86-32 binaries.
- Data and formats being processed target ARM structures.
- Separate host execution details from target file-format semantics.

## 32-bit to 64-bit portability rules

### Pointer versus integer ambiguity

Decompiler output often uses `int32_t` where pointers should be used. Reclassify by usage:

- Pointer signs: dereference patterns, NULL checks, allocator and IO APIs, pointer arithmetic.
- Integer signs: counters, flags, sizes, encoded constants.

### Type corrections

- Replace ambiguous integer pointer carriers with proper pointer types.
- Use `size_t` for sizes/counts, `ptrdiff_t` for pointer differences, and `intptr_t` only as a temporary bridge.
- Avoid any cast chain that stores pointers through `int32_t`.
- Update function signatures when arguments or return values are pointer-like.

### Struct layout differences

Keep two categories clear:

1. On-disk format structs: fixed-width integer fields only.
2. Runtime structs: real pointer fields and natural host layout.

Rules:

- Use `sizeof()` for allocation, never hardcoded sizes.
- Once struct is defined, use field access instead of offset arithmetic.
- Offset comments should describe original 32-bit layout only.

### Safe conversion procedure (required)

When converting an inferred pointer field from `int32_t` to a real pointer type, follow the full sequence below. Skipping steps creates silent 64-bit defects.

1. Identify pointer-like fields from all use sites (dereference, NULL checks, allocator/IO calls, pointer arithmetic).
2. Update struct definitions first so field intent is explicit.
3. Fix all allocation sites to use `sizeof(struct_type)` and remove integer-casted pointer stores.
4. Replace offset-based loads/stores with typed field access (`->field`) consistently.
5. Remove truncating pointer casts (`(int32_t)ptr`, `(void *)int32_value`) from assignments and call paths.
6. Update function signatures and return types so pointer semantics are explicit end-to-end.
7. Convert list traversal and ownership paths to typed pointer flow.

```c
/* Before (decompiler style) */
int32_t sym = (int32_t)malloc(16);
*(int32_t *)(sym + 0x0C) = (int32_t)next_sym;
while (sym != 0) {
    sym = *(int32_t *)(sym + 0x0C);
}

/* After (64-bit safe, typed) */
symbol_t *sym = malloc(sizeof(symbol_t));
sym->next = next_sym;
for (; sym != NULL; sym = sym->next) {
    /* ... */
}
```

### Using intptr_t as an intermediate type

If full typing is not immediately possible, use `intptr_t` as a temporary safe bridge. Replace with explicit pointer types as understanding improves.

### Common pitfalls

- Pointer size is 8 bytes on 64-bit hosts.
- Casting pointers through `int32_t` truncates addresses.
- Function pointers are pointer-width, not 32-bit integers.
- Mixed raw-offset access and struct-field access for the same object causes subtle bugs.

### Optional 32-bit-first validation flow

If toolchain support exists, this can isolate logic bugs from type-width bugs:

1. Build a temporary 32-bit check (`-m32`) to validate behavior quickly.
2. Migrate recovered types for 64-bit safety.
3. Rebuild 64-bit and confirm outputs still match expectations.

Do not treat 32-bit mode as the final target; it is only a debugging aid.

### Comparing against original executable during reconstruction

Do not wait until the end to compare behavior:

- Check `-help`, `-vsn`, and common error paths early.
- Re-run comparisons after each major subsystem reconstruction batch.
- Validate output bytes when possible; otherwise compare stable semantic views.

## Source recovery and reconstruction rules

### Basic reconstruction rules

- Never modify original decompilation reference files.
- Keep reconstruction work in `recompiled/src/`.
- Restructure only to remove decompiler artifacts and recover likely original C89 source form.
- Preserve likely original function boundaries, control-flow shape, state-machine structure, data layout, and helper granularity when evidence supports them.
- Do not split, merge, or invent helper functions, abstractions, or modules unless strong evidence suggests the original source likely had them or a narrowly scoped portability fix requires it.
- Rename functions and globals only when evidence supports likely original intent; keep unique suffixes where certainty is incomplete.
- Add brief human-readable behavior comments before recovered function/global definitions when purpose is non-obvious.
- Add short behavior comments where intent is non-obvious, especially around renamed logic.
- Replace non-trivial literals with named constants and enums.
- Never leave new magic numbers unexplained.

### Processing order

1. Leaf helpers first.
2. Work upward through call graph.
3. Recover related modules together.
4. Entry-point orchestration last.

### Structure recovery

- Convert repeated offset access patterns into recovered structs when multiple call sites and data-flow evidence indicate the original source likely used C structs.
- Prefer partial structs with unknown placeholders over macro-based offset wrappers; do not invent higher-level wrappers that hide uncertain layout.

### Never use field-access macros for recovered structs

Do not hide pointer arithmetic in accessor macros. Macros mask type mistakes and 64-bit truncation bugs. Prefer real struct definitions (including partial structs with `unknown_XX` placeholders) and typed `->field` access.

### Linked list recognition

ARM SDT tools frequently encode core state as linked lists rather than arrays. When traversal evidence indicates the original source likely used linked lists, recover typed traversal without changing function boundaries or state-machine structure.

```c
/* Decompiled pattern */
v1 = head;
while (v1 != 0) {
    /* ... */
    v1 = *(int32_t *)(v1 + 12);  /* next pointer */
}

/* Recovered pattern */
for (symbol_t *sym = head; sym != NULL; sym = sym->next) {
    /* ... */
}
```

Use consistent recovered node layouts when evidence matches:

```c
typedef struct symbol {
    char *name;
    uint32_t value;
    uint32_t flags;
    struct symbol *next;
} symbol_t;

typedef struct area {
    char *name;
    uint32_t attributes;
    uint8_t *data;
    struct reloc *relocs;
    struct area *next;
} area_t;
```

### Array recognition

- Recognize array indexing (`base + index * size`) and convert to array notation where valid.
- Infer fixed-size arrays from loop bounds and element strides.

### Cross-tool type consistency

- Reuse proven struct patterns across tools (for example `chunk_file_t`, `area_t`, `symbol_t`, `reloc_t`) when evidence matches.
- Cross-check with known working definitions and format docs before introducing a divergent layout.

### Control flow simplification

- Refactor decompiler goto chains only when evidence suggests the original C source likely expressed the same logic more directly and behavior is clearly preserved.
- Keep state-machine and cleanup gotos when preserving likely original structure or behavior requires it.
- Distinguish normal flow from error/unwind flow explicitly.
- Remove dead code only after proving it is unreachable from all jump targets.

### State-machine gotos

Keep goto-heavy regions when they implement parser or linker state transitions or complex cleanup ladders. Add a targeted TODO explaining why the structure is retained and what evidence would permit limited restructuring later.

### Dead code removal

Decompiler output may include duplicated tails or unreachable blocks. Before deletion:

1. Verify no labels or indirect jumps target the block.
2. Confirm exact-original behavior on the full required fixture corpus, including adversarial edge cases for the edited path.
3. Leave a brief comment in commit or nearby notes describing what was removed.

### Constants, enums, and domain patterns

- Replace magic values with named constants.
- Recover bit flags and enums for clarity.
- Keep architecture-specific encoding and endianness semantics explicit.
- Name chunk/file-format constants (magic values, flags, relocation tags) from observed behavior.

### ARM and target-data patterns to preserve

These tools run on x86 hosts but process ARM-target data. Keep these semantics explicit:

- Architecture-specific instruction encodings and condition bits for all modes supported by the original binary.
- APCS-related metadata assumptions in emitted data.
- AOF/AIF/ALF structure fields, ordering, and padding rules.
- Big-endian byte ordering for output data.

### AOF and related quick-recognition patterns

When recovering parser and emitter logic, keep these recurrent constants/patterns explicit:

- Chunk magic values and chunk-walk loops (for example `0xC3CBC6C5` in known chunk files).
- Symbol/area/relocation flag handling tied to documented AOF semantics.
- Big-endian conversion idioms (shift/or byte-swap sequences) that should become named helpers once verified.

### DWARF and debug paths

DWARF and debug paths are part of original-feature parity when present in the original binary. Recover and preserve their externally visible behavior (outputs, diagnostics, exits, and edge handling) exactly.

Use evidence capture to lock exact-original DWARF/debug behavior across all original modes and inputs; do not replace original behavior with stubs at completion.

If analysis is still in progress, mark uncertainty explicitly and keep parity closure tasks attached to concrete experiments:

```c
/* DWARF: decode_location_804f234
 * Compatibility-critical: preserve original decode semantics, diagnostics, and text output.
 * TODO: close remaining edge-case parity gaps with fixture-backed tests.
 */
static const char *decode_location_804f234(const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
    return decode_location_with_original_parity(data, len);
}
```

### Ghidra and RetDec artifact handling

Address artifacts systematically rather than ad hoc.

#### Naming artifacts

Rename synthetic identifiers (`FUN_`, `DAT_`, `PTR_s_`, `param_`, `local_`, `LAB_`, `uVar`, `iVar`, `pVar`, `pcVar`, `puVar`, `auStack`, `acStack`, and switch labels) to behavior-based names while preserving traceability suffixes.

#### Type artifacts

Replace synthetic types with standard C/POSIX types inferred from usage:

| Synthetic form | Typical replacement |
| --- | --- |
| `undefined1` / `byte` | `uint8_t` or `char` |
| `undefined2` / `word` | `uint16_t` or `int16_t` |
| `undefined4` / `dword` | `uint32_t`, `int32_t`, or pointer |
| `undefined` | infer from usage and call signatures |
| `uint` | `unsigned int` (or narrower fixed-width type if proven) |
| `ulong` | `unsigned long` or `size_t` depending on semantics |
| `longlong` | `int64_t` |
| `code *` | explicit function-pointer typedef |

#### Control-flow and expression artifacts

- Convert `CONCATxx` patterns to explicit shifts/OR operations.
- Investigate `extraout_*` register artifacts against objdump before trusting inferred values.
- Replace stack-address vararg artifacts (for example `&stack0x...`) with proper `va_list` handling.
- Treat RetDec `placeholder_gNNN` parameters as unresolved stack/calling-convention decode failures (RetDec-specific; Ghidra does not emit this form).
- Expect this artifact at scale in large outputs (for example 1300+ occurrences in `armlink` RetDec output) and prioritize call-site plus objdump validation.
- Interpret Ghidra warning comments (`Subroutine does not return`, unknown calling convention) as analysis hints, not noise.

#### Misleading patterns to verify before restructuring

- Replace decompiler-expanded library patterns only after verification:

```c
/* Ghidra-expanded strlen-like loop */
uVar2 = 0xffffffff;
pcVar4 = str;
do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
} while (cVar1 != '\0');
len = ~uVar2 - 1;

/* Verified replacement */
len = strlen(str);
```

- Validate "array-looking" expressions like `(&DAT_x)[idx * k]` before assuming true array semantics.
- Replace alignment bit-hacks with named helpers once behavior is confirmed:

```c
/* Decompiled idiom */
aligned = ~uVar2 + 3 & 0xfffffffc;

/* Normalized */
aligned = ALIGN4(n);
```

- Resolve duplicate globals at the same address by usage-driven typing before reconstruction edits:

```c
uint *DAT_0807b298;       /* one site */
undefined4 DAT_0807b298;  /* another site, same address */
```

### Decompiler artifact recovery quick wins

Apply these mechanical recovery edits once behavior is confirmed and the change moves the code toward plausible original C89 source form:

- Remove redundant cast chains (for example `(int32_t)(int32_t)x` -> `x`).
- Collapse temporary-return patterns (`tmp = x; return tmp;` -> `return x;`).
- Prefer direct predicate calls (`if (func())`) when decompiler temporaries add no behavior.
- Recheck sign-extension-sensitive expressions against runtime or objdump before changing signedness.

### Handling decompiler failures

#### Placeholder variables

Treat `placeholder_gNNN` artifacts as unresolved calling-convention evidence, never as final typed parameters.

```c
/* RetDec artifact */
int32_t result = func_804a234(a1, placeholder_g279, a3);
```

Resolve by checking stack argument setup and callee behavior in objdump/runtime evidence.

#### Disabled or broken modules

For fundamentally broken and non-critical modules, disable narrowly and document re-enable criteria.

```c
/* DISABLED: demangler_8051234..demangler_8051890
 * Broken pointer-base recovery in decompiler output.
 * TODO: Re-enable after behavior-led rewrite against original runtime.
 */
#if 0  /* DEMANGLER_DISABLED */
static char *demangle_symbol_8051234(const char *mangled) { return NULL; }
#endif
```

#### Compiler pragmas for known artifacts

Use targeted suppression only around known artifacts; never silence entire files.

```c
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"
/* known decompiler artifact region */
#pragma GCC diagnostic pop
```

Keep pragma scope minimal and document the exact artifact being suppressed.

## Documentation discipline during reconstruction

- Mark uncertain logic with explicit `/* UNCERTAIN: ... */` comments.
- Keep `/* TODO: ... */` notes tied to specific unresolved behavior.
- Maintain function/global mapping tables for traceability back to decompiler names.
- Mark compatibility-critical paths with `/* BINARY COMPAT: ... */` comments.
- For every touched implementation `.c` file under `<tool>/recompiled/src/`, keep an ASCII `HISTORY:` block near the top of the file.
- Add one short step-by-step `HISTORY:` entry for each material reconstruction or behavior-recovery batch, recording what changed plus the current state or remaining note that the next agent needs.
- Keep notes concise and evidence-based (objdump, runtime comparison, format docs).

### `HISTORY:` block minimal format

Use this exact shape in touched implementation `.c` files:

```c
/*
HISTORY:
- YYYY-MM-DD: <material batch summary>; parity: <confirmed|open|blocked>; next: <single next action or none>.
*/
```

Rules:

1. Keep the block near the top of the file.
2. Append one entry per material batch (do not rewrite prior entries).
3. Keep entries ASCII-only and concise.
4. Keep `parity` aligned to `confirmed`, `open`, or `blocked`.

Example markers for compatibility-sensitive sections:

```c
/* BINARY COMPAT: Version text must match original exactly. */
#define TOOL_VERSION_TEXT "..."

/* BINARY COMPAT: Output padding/order is byte-identity critical. */
static void write_aligned_block(/* ... */);
```

## Reverse engineering heuristics that speed recovery

### String literals and diagnostics

Use user-facing strings (`usage`, error messages, warnings) to infer function purpose, option handling, and control-flow intent.

### Standard library and POSIX type recovery

Map decompiler-invented structs/signatures to real APIs (`FILE *`, `struct stat`, `DIR *`, `size_t`, `ssize_t`, `off_t`) based on call patterns. If RetDec emits glibc internals such as `__xstat`/`__fxstat`/`__lxstat`, wrap or replace them with standard `stat`/`fstat`/`lstat` usage.

Common standard-library signal patterns:

- `malloc`/`free` lifetimes indicate ownership boundaries.
- `fopen`/`fread`/`fwrite`/`fclose` sequences indicate stream lifecycle and error precedence.
- `strcmp`/`strcpy`/`strlen` usage reveals string field semantics.
- `memcpy`/`memset` usage reveals struct or buffer boundaries.
- `getopt`/`argc`/`argv` usage anchors CLI parsing behavior.

Common replacements to apply consistently:

- Custom file stream structs -> `FILE *`
- Custom stat-like structs -> `struct stat`
- Custom dir structs -> `DIR *`, `struct dirent`
- Raw size counters -> `size_t` / `ssize_t`
- File offsets -> `off_t`

Identification hints:

- Values passed as stream handles to `fread`/`fwrite`/`fseek` are typically `FILE *`.
- Buffers populated by `stat`-like calls should be typed as `struct stat`.
- Values returned by `opendir`-like flows should be typed as `DIR *`.
- Read/write size and return paths should use `size_t`/`ssize_t`.

Standard headers typically required during reconstruction:

- `<stdint.h>`, `<stddef.h>`
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`
- `<sys/types.h>`, `<sys/stat.h>`, `<fcntl.h>`, `<unistd.h>`, `<dirent.h>`, `<errno.h>`

### glibc internal wrapper normalization

When decompilation references glibc internals, normalize to public APIs:

- `__xstat` -> `stat`
- `__fxstat` -> `fstat`
- `__lxstat` -> `lstat`

If incremental migration is needed, temporary wrappers are acceptable but must preserve behavior and be retired once call sites are typed correctly.

### Function pointers and dispatch tables

Look for jump-table or callback patterns and recover explicit function-pointer typedefs and tables when they reflect real design.

### Printf format-string type inference

Use format specifiers to validate recovered types (`%s` string pointers, `%p` pointers, `%u`/`%x` unsigned fields, `%ld` long).


## Verification strategy

Compatibility target is exact-original external behavior for all original paths, with strict checks for outputs, diagnostics, option semantics, exit behavior, and edge cases.

### Byte-for-byte verification

For artifacts that must match byte-for-byte, compare the original and candidate outputs directly with `cmp` and record the comparison result:

```bash
cmp original_output.bin recompiled_output.bin
```

### Semantic verification

Use semantic comparison only when byte-for-byte identity is proven non-authoritative for that artifact. In that case, decoded semantic output must still match original behavior exactly, including compatibility-critical diagnostics and exit semantics.

```bash
diff <(path/to/decaof -agst original_output.bin) <(path/to/decaof -agst recompiled_output.bin)
```

### What must match exactly

- Version strings and identity metadata, including compatibility-sensitive whitespace and punctuation.
- Option parsing and precedence semantics, including repeated and conflicting flag behavior.
- Required chunk ordering, alignment, relocation, header fields, and formatting-sensitive text output.
- Exit codes, failure precedence, and diagnostics for the same inputs.
- Edge-case behavior for malformed inputs and boundary conditions in original behavior.

### Differences permitted only by explicit unresolved record

- No externally visible differences are allowed by default.
- Internal implementation strategy can vary only when externally visible behavior remains exactly identical and parity evidence is recorded.
- Any unresolved externally visible mismatch must be explicitly recorded as `UNCERTAIN` with evidence, impact, and closure experiments.

### Build testing loop

- Build frequently.
- Run full tests frequently.
- Use quick syntax-only checks during heavy edits.

```bash
cd <tool>/recompiled
make
make test
# Optional fast parse/type sanity check while iterating:
gcc -Wall -Wextra -fsyntax-only src/<file>.c
```

## Commit and artifact rules

- Commit in logical units.
- After each material reconstruction or behavior-recovery batch, make a git commit before starting the next material batch.
- For a new step 1 effort, make the first commit the copied Ghidra baseline before reconstruction or repair work.
- Include traceability notes in commit messages (renames, recovered structs, behavior evidence).
- Use an ASCII-only summary in the commit subject and any commit body text.
- Commit source, tests, docs, and Makefiles; never commit artifacts from `build/`.
- Keep `build/` ignored and clean in `git status`.
- Keep documentation and commit text ASCII-only.

## Recompiled source organization

Recommended shape:

```text
<tool>/recompiled/
  Makefile
  src/
    *.c, *.h
  tests/
    test_*.c
  build/
```

File-level header guidance:

- Source provenance references.
- ASCII `HISTORY:` block with one step-by-step entry per material reconstruction batch.
- Current reconstruction status.
- Remaining known work.
- Function and global mapping notes.
- Known compatibility-sensitive sections.
- Keep mapping and uncertainty notes close to affected code (`UNCERTAIN`, `TODO`, `BINARY COMPAT`) rather than in detached notes.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 1 completion criteria

Step 1 is complete for a tool when:

1. `make` and `make test` pass with command outputs recorded for the current revision.
2. Shared two-way tests pass against original and recompiled binaries, using one harness that can extend to three-way.
3. Required outputs, diagnostics, option semantics, exit behavior, and edge-case handling have recorded exact-parity evidence (fixture IDs plus recorded `cmp` results for original and recompiled outputs, or approved semantic evidence when byte-for-byte identity is non-authoritative).
4. Updated mappings, `UNCERTAIN` items, unresolved modules, and any unresolved mismatches are explicitly documented with evidence-backed closure actions.
5. No unresolved hard-stop item from the agent execution protocol remains.
