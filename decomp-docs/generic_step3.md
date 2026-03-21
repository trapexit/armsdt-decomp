# Generic Step 3 - Recreate from specification

## Objective

This document centralizes shared step 3 guidance that applies to every tool. Per-tool `*_step3.md` files keep only tool-specific details (inputs, original outputs, and tool-specific recreation focus).

Implement a clean-room C11 recreation in `<tool>/recreated/` using step 2 technical contracts and step 1 validation assets. This implementation must be independent in structure while matching original externally visible behavior exactly for every original path, feature, option interaction, and edge case.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: generic-step3
  step: 3
  applies_to: all tools
  objective: implement clean-room recreation with exact-original parity
  must_inputs:
    - <tool>/technical_specification.md
    - shared regression corpus and three-way test harness
    - original runtime behavior as oracle
  must_outputs:
    - <tool>/recreated/Makefile
    - <tool>/recreated/src/
    - <tool>/recreated/tests/
    - <tool>/recreated/build/<tool>
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
- This file is the canonical shared guidance for step 3 across all tools.
- Tool-specific `*_step3.md` files add concrete inputs, output paths, and tool-specific recreation focus.

## Exact-original parity rule

- Required end state is exact-original behavior for outputs, diagnostics, exit behavior, option semantics, and edge handling.
- Treat any externally visible mismatch as a defect.
- Do not accept partial parity for original workflows.
- If evidence is incomplete, mark the item `UNCERTAIN` and block closeout until closure experiments run.

## Inputs

- `<tool>/technical_specification.md` from step 2.
- Shared tests and regression corpus from step 1.
- Original binary behavior as oracle during validation.

## Agent execution protocol

### Preflight checklist

- Confirm step 1 outputs are present, `<tool>/technical_specification.md` is current, and references are current.
- Confirm shared three-way test harness paths for original, recompiled, and recreated binaries.
- Confirm must-match behavior list and any explicitly approved unresolved-difference records from step 2.
- Confirm replacement fixtures cover all original forms, paths, features, and edge cases.

### Optional bootstrap commands (first five)

```bash
cd <tool>/recreated
make clean
make
make test
../<tool> -vsn
```

### Required evidence artifacts per implementation increment

- Three-way test run output tied to changed requirements.
- Parity artifacts (`cmp` results for byte-for-byte checks, or approved semantic diffs) for compatibility-sensitive outputs.
- Diagnostic parity captures for precedence-sensitive error cases.
- Replacement workflow results for every original workflow class and touched edge-case class.

### Hard-stop and escalation conditions

- Stop if recreated behavior differs from original on a must-match requirement.
- Stop if tests are weakened to hide parity failures.
- Stop if a claimed unresolved difference is missing explicit step 2 record and evidence.
- Escalate unresolved mismatches with `UNCERTAIN` notes and closure experiments.

### Completion gate (objective)

Only close an implementation pass when all of the following are true:

1. Relevant three-way tests pass and are recorded.
2. Compatibility-sensitive outputs changed in the pass have fresh parity evidence.
3. No externally visible mismatch remains.
4. No unresolved hard-stop issue remains.

## Start gate and authority order

- Do not begin step 3 coding until step 1 outputs are present, `<tool>/technical_specification.md` is current, and `recompiled/` is functional on shared tests.
- Resolve behavior using this authority order: original binary runtime behavior, step 2 documented contracts, step 1 reverse engineering evidence.
- If sources conflict, treat original binary output as ground truth and update tests plus step 2 notes before finalizing implementation.

## Clean-room implementation rules

- Do not copy implementation code from `recompiled/src/`.
- Share no source files between `recompiled/` and `recreated/`.
- Use step 2 behavior contracts as the primary design authority.
- Treat step 1 and recompiled artifacts as behavioral evidence, not as a code template.
- Keep architecture modular and maintainable, without decompiler naming artifacts or address-suffixed identifiers.
- Preserve exact-original externally visible behavior and deterministic outputs for all original paths.

## Required outputs

- `<tool>/recreated/Makefile`
- `<tool>/recreated/src/` modular C11 implementation
- `<tool>/recreated/tests/` shared tests that also run against original and recompiled binaries
- `<tool>/recreated/build/<tool>`

## Recommended recreated project structure

```text
<tool>/recreated/
  Makefile
  src/
    main.c
    <tool>.h
    module_*.c
  tests/
    test_*.c
  build/
```

## Module boundary requirements

- Keep `main.c` thin: argument parsing, top-level orchestration, and exit code mapping.
- Separate CLI parsing, domain model, file-format IO, transformation passes, diagnostics, and emitters into distinct modules.
- Define stable interfaces in headers; avoid hidden cross-module coupling and implicit global state.
- Align tests with module boundaries so subsystems can be validated in isolation and in integration.

## Build system requirements

- Simple, self-contained Makefile with no recursive make or external generators.
- Build artifacts in `build/` only, including `.o` and `.d` files plus final executable.
- `make`, `make test`, `make clean`, and `make help` implemented.
- Default build should be warning-clean under strict project flags.

## Testing requirements

- Reuse one shared suite across original, recompiled, recreated binaries.
- Do not maintain separate behavior suites for recompiled and recreated; one suite drives all three.
- Keep test-first and adversarial testing strategy.
- Expand tests whenever parity appears complete to uncover edge drift.
- Coverage target is full original behavior surface: every public module, every required CLI option and meaningful flag combination, every required error path, and required edge-case handling.

### Test-first adversarial workflow

1. Write or extend tests against original binary behavior first.
2. Run the same tests against recreated binary and treat failures as implementation backlog.
3. Implement only until tests pass, then add adversarial cases for boundaries, malformed input, and precedence conflicts.
4. Never weaken a test that passes on the original binary; fix implementation instead.

### Three-way parity requirement

All critical tests must pass against:

1. `<tool>/<tool>`
2. `<tool>/recompiled/build/<tool>`
3. `<tool>/recreated/build/<tool>`

### Three-way harness protocol

Keep one shared harness target that runs the same scenario set against all three binaries and stores artifacts with stable scenario IDs:

```bash
TOOLS=(
  "../../<tool>"
  "../recompiled/build/<tool>"
  "../recreated/build/<tool>"
)

for TOOL in "${TOOLS[@]}"; do
  run_tests "$TOOL"
done
```

Required per-scenario records:

1. Scenario ID and fixture ID(s).
2. Command and option set.
3. Exit code plus stdout/stderr capture path for each binary.
4. Parity mode (`cmp` or documented semantic fallback) and outcome.


## Original feature coverage gate

Import the step 2 feature inventory into step 3 execution.

- Every `confirmed` item must remain `confirmed` after recreation changes.
- Every `open` item must be resolved to `confirmed` before closeout.
- `blocked` items require documented blocker ownership and closure experiments.

## Implementation order guidance

1. Implement CLI and option parsing contract first.
2. Build core data model and IO boundary modules.
3. Implement processing pipeline stages incrementally.
4. Add diagnostics and error precedence behavior.
5. Lock deterministic output and compatibility fields.
6. Expand edge-case behavior based on adversarial corpus.

## Domain and portability constraints

- Keep original behavior aligned to every architecture, format, and workflow path present in the original binary, including all AOF, AIF, and ALF behavior it implements.
- Respect endianness behavior exactly as required by original format semantics.
- Keep host portability and type safety explicit (`size_t`, pointer-width correctness).
- Use fixed-width type aliases (`u8`, `s8`, `u16`, `s16`, `u32`, `s32`, `u64`, `s64`) consistently when width is known from evidence. Define them in a shared header as shown in generic_step1.md.
- Avoid undefined behavior and keep strict warning cleanliness.

## Verification strategy

### Byte-level checks

For artifacts that must match byte-for-byte, compare the original and recreated outputs directly with `cmp` and record the result:

```bash
cmp original_output.bin recreated_output.bin
# If cmp reports a mismatch, use hex diffs only to localize it.
diff <(xxd original_output.bin) <(xxd recreated_output.bin)
```

### Semantic checks

Use semantic comparison only when step 2 proves byte-for-byte identity is non-authoritative for the artifact; decoded semantic output must still match original behavior exactly.

```bash
diff <(path/to/decaof -agst original_output.bin) <(path/to/decaof -agst recreated_output.bin)
```

### Must-match behavior categories

- Option handling semantics and precedence.
- Version strings and identity metadata, including whitespace where compatibility-sensitive.
- Compatibility-sensitive headers, chunk ordering, padding, alignment, and relocation content.
- Required symbol values, flags, and table semantics for supported formats.
- Error text, exit codes, and failure precedence where step 2 marks them compatibility-critical.

### Unresolved differences (must be resolved before closeout)

- No unresolved externally visible difference is accepted by default.
- Any unresolved difference must have evidence, parity impact, and closure plan while work is in progress; unresolved differences are not allowed at closeout.
- Internal implementation details may vary only when all required external behavior remains exactly identical.

## Integration and replacement expectations

Target end-state expectations:

1. Recreated tool can replace original across all original forms, paths, features, and edge cases.
2. Shared test suite demonstrates parity across all three binaries.
3. Byte-level or approved semantic checks pass for every original output class.
4. Tool-local documentation records original behavior and evidence-backed parity results for all original feature paths.
5. Output behavior remains stable under required optimization levels and strict build settings.

## Commit and artifact rules

- Commit logical implementation increments with clear scope.
- After each material recreation or parity-fix batch, make a git commit before starting the next material batch.
- Use an ASCII-only summary in the commit subject and any commit body text.
- Update the touched implementation `.c` file `HISTORY:` block in the same batch so git history and file-local history stay aligned.
- Do not commit `build/` artifacts.
- Keep documentation and commit messages ASCII-only.


## Recreated source file tracking

- For every touched implementation `.c` file under `<tool>/recreated/src/`, keep an ASCII `HISTORY:` block near the top of the file.
- Add one short step-by-step `HISTORY:` entry for each material recreation or parity-fix batch, recording what changed plus the current parity state or remaining note that the next agent needs.
- Keep file-wide progress notes in that header block and keep `UNCERTAIN`, `TODO`, and `BINARY COMPAT` comments close to affected code.

### `HISTORY:` block minimal format

Use this exact shape in touched implementation `.c` files:

```c
/*
HISTORY:
- GEN-001: <material batch summary>; parity: <confirmed|open|blocked>; next: <single next action or none>.
*/
```

Rules:

1. Keep the block near the top of the file.
2. Append one entry per material batch (do not rewrite prior entries).
3. Prefix each entry with a monotonically increasing generation tag in `GEN-XXX` form (for example `GEN-001`).
4. Keep entries ASCII-only and concise.
5. Keep `parity` aligned to `confirmed`, `open`, or `blocked`.

## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 3 completion criteria

Step 3 is complete for a tool when:

1. Recreated build is functional and warning-clean under strict settings (`make`, `make test`) with outputs recorded.
2. Shared three-way tests pass for full original behavior surface with explicit references to test paths and scenarios.
3. Coverage includes full original CLI surface, core modules, and documented error paths, with evidence linked to requirement IDs.
4. Byte-for-byte `cmp` or approved semantic parity checks pass for compatibility-sensitive outputs, with fixture IDs and recorded comparison/diff artifacts.
5. Replacement workflow validation succeeds for all original scenario classes and is documented.
6. No remaining externally visible mismatch exists.
7. If implementation started as a monolith, it has been split into maintainable modules before closeout.
