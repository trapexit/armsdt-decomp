# Generic Step 2 - Create the technical behavior specification

## Objective

This document centralizes shared step 2 guidance that applies to every tool. Per-tool `*_step2.md` files keep only tool-specific details (inputs, deliverable location, requirement ID prefix, and tool-specific emphasis).

Produce an evidence-backed technical specification that states exact-original `<tool>` behavior for every original path, feature, option interaction, and edge case.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: generic-step2
  step: 2
  applies_to: all tools
  objective: write implementation-ready exact-original behavior specification
  must_inputs:
    - step 1 artifacts and parity evidence
    - <tool>/<tool> original runtime behavior
    - <tool> decompilation/disassembly/readelf artifacts
    - <tool> usage capture and format docs
  must_outputs:
    - <tool>/technical_specification.md
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

## Workflow entrypoint

Start from [README.md](README.md) before reading this file.

- Use [workflow_manifest.json](workflow_manifest.json) to determine tool order, step readiness, and resume rules.
- This file is the canonical shared guidance for step 2 across all tools.
- Tool-specific `*_step2.md` files add concrete inputs, the step 2 spec output path, requirement ID prefix, and tool-specific emphasis.

## Exact-original parity rule

- Treat exact-original behavior as the default contract for all required functionality.
- Define outputs, diagnostics, exit behavior, option semantics, and edge handling as must-match for every behavior present in the original binary.
- Do not document approximate behavior as acceptable for original workflows.
- If exact behavior is unresolved, mark it `UNCERTAIN` with evidence, parity impact, and closure plan.

## Inputs

- Step 1 artifacts from `<tool>/recompiled/` (code, tests, findings, and parity notes).
- Original binary behavior from `<tool>/<tool>`.
- `<tool>_decomp_ghidra.c`, `<tool>_decomp_retdec.c`, `<tool>_objdump.txt`, and `<tool>_readelf.txt`.
- Usage and options from `<tool>_usage.txt`.
- Relevant format documentation in `docs/`.

## Deliverable

Create or update `<tool>/technical_specification.md`, the canonical step 2 technical specification for `<tool>`, so it captures behavior, constraints, edge cases, compatibility requirements, and explicit evidence.

## Specification path

- `<tool>/technical_specification.md`

## Required scaffold

Start from [templates/step2_specification_scaffold.md](templates/step2_specification_scaffold.md), then adapt for tool-specific requirements in `*_step2.md`.

## Agent execution protocol

### Preflight checklist

- Confirm step 1 artifacts are present and runnable for the tool.
- Confirm requirement ID prefix and target spec output path.
- Confirm fixture corpus identifiers used in evidence capture.
- Confirm baseline authority order for conflicts (runtime > objdump/readelf > decompiler > prose).

### Optional bootstrap commands (first five)

```bash
cd <tool>/recompiled
make
make test
../<tool> -help
../<tool> -vsn
```

### Required evidence artifacts per documented claim

- Runtime capture: command line, fixture ID, stdout/stderr, exit code.
- Output identity: file path plus the recorded `cmp` comparison result when byte-for-byte parity is required.
- Static reference: source path plus line range and short rationale.
- Conflict note when sources disagree, including selected resolution reason.

### Hard-stop and escalation conditions

- Stop if a compatibility-critical claim lacks direct evidence.
- Stop if runtime observations conflict with documented contract and no resolution note is present.
- Stop if a must-match rule is listed without test linkage.
- Escalate unresolved claims as `UNCERTAIN` with closure experiments.

### Completion gate (objective)

Only close a spec pass when all of the following are true:

1. Every major behavior claim maps to a requirement row and evidence IDs.
2. Must-match requirements are explicit and complete for all original behavior, and any unresolved mismatch is explicitly marked with evidence, impact, and closure plan.
3. High-risk requirements link to validation tests and current outcomes.
4. No unresolved hard-stop issue remains.

## Required documentation scope

### CLI contract

- Document all supported options, aliases, defaults, and precedence.
- Document illegal combinations and exact diagnostics where compatibility-sensitive.
- Document repeated-option behavior (for example, last-wins versus accumulate).
- Document exit-code behavior, including failure precedence when multiple faults occur.

### Input and output model

- Define accepted input artifact types and invalid-input rejection rules.
- Define output artifact structure, ordering, alignment, and compatibility-sensitive fields.
- Document deterministic behavior requirements (ordering, formatting, padding, metadata).
- Capture exact version-string behavior and where identity strings are emitted.

### Processing pipeline behavior

- Describe major stages and transition rules.
- Describe data model transitions across stages and subsystem boundaries.
- Capture critical invariants and ordering guarantees.
- Identify externally visible side effects (file writes, temp outputs, diagnostics).

### Error and diagnostic behavior

- Classify error families (CLI parse, IO, format, semantic, internal).
- Define trigger conditions and first-failure precedence.
- Document recoverable versus fatal behavior per class.
- Capture exact stderr text and spacing when required for compatibility.

### Compatibility-critical behavior

- Mark behavior that must match byte-for-byte with the original, meaning the original and candidate outputs are compared directly with `cmp`.
- Include chunk, header, relocation, ordering, and padding semantics where relevant.
- Include output-text compatibility rules (including whitespace-sensitive cases).
- Include any behavior that will break parity validation if changed.

### Scope coverage

- Required baseline is full original behavior across all forms, options, targets, architecture modes, endianness modes, formats, diagnostics, and edge handling present in the original binary.
- Do not classify any original behavior as outside parity coverage.
- Record unresolved understanding as `UNCERTAIN` with evidence, parity impact, and closure plan until resolved.

### Host and target architecture distinctions

- Distinguish host execution behavior from ARM target data semantics.
- Document where host portability decisions (32-bit to 64-bit typing) are implementation details versus externally visible behavior.
- Call out assumptions that must remain stable across host environments.

## Evidence collection protocol

For each significant claim, attach reproducible evidence. Prefer both runtime and static evidence for high-risk claims.

### Runtime evidence (required for externally visible behavior)

Record at least:

- Exact command line used.
- Input fixture identity (file names and, when helpful, hashes).
- Captured stdout, stderr, and exit code.
- Output artifact identity (path plus recorded `cmp` comparison result for original and candidate outputs, or documented semantic fallback when byte-for-byte comparison is non-authoritative).

### Static evidence (required for non-obvious logic)

Record at least:

- Source path and line range in decompilation, disassembly, or readelf output.
- Brief rationale explaining why the source supports the claim.
- Cross-reference when Ghidra and RetDec disagree.

### Conflict resolution

When sources conflict, resolve using this precedence unless contradicted by direct runtime proof:

1. Original runtime observation.
2. Objdump/readelf level evidence.
3. Ghidra decompilation.
4. RetDec decompilation.
5. Existing prose documentation.

Document every conflict and why the selected interpretation was chosen.

## Behavior capture workflow

1. Enumerate CLI and feature surface from usage text and step 1 findings.
2. Build a required fixture corpus that covers all original forms, paths, and features, then add adversarial edge cases.
3. Run original and step 1 binaries to gather behavior evidence.
4. Diff outputs and classify each rule as must-match or unresolved mismatch requiring closure.
5. Add traceable requirements tied to evidence and tests.
6. Re-run critical checks after doc updates to ensure reproducibility.


## Original feature inventory protocol

Maintain a complete inventory of original feature families and track each row with `confirmed`, `open`, or `blocked`.

Minimum inventory columns:

- `feature_id`
- `family` (CLI, input, output, diagnostics, pipeline, edge-case)
- `behavior`
- `evidence_ids`
- `status` (`confirmed`/`open`/`blocked`)
- `tests`

Step 2 cannot close until all original feature rows are `confirmed` or `blocked` with explicit closure experiments.

## Traceability requirements

Include a traceability matrix (or equivalent structured section) with these fields:

- Requirement ID (stable and tool-scoped, for example `<tool>-REQ-###`).
- Behavior statement.
- Category (CLI, format, pipeline, diagnostics, compatibility, scope).
- Evidence reference IDs.
- Confidence level (high, medium, low).
- Validation reference (test case name/path and three-way status).
- Resolution status (confirmed, open, blocked).
- Follow-up action for non-confirmed entries.

Every major behavior claim must appear in this matrix.

## Uncertainty handling

- Mark uncertainty explicitly using labels such as `UNCERTAIN`, `HYPOTHESIS`, and `ASSUMPTION`.
- Never present inferred behavior as confirmed without evidence.
- For each unresolved item, define a closure experiment with expected observations.
- Record confidence changes when new evidence resolves uncertainty.

## Verification and parity documentation

### Verification levels

- Byte-for-byte comparison is the default acceptance check for compatibility-sensitive outputs: compare the original and candidate outputs directly with `cmp` and record the result.
- Semantic comparison is fallback-only, requires documented proof that byte-for-byte identity is non-authoritative, and must preserve exact external behavior.

### Must-match list

Maintain an explicit list of behavior that must match exactly (for example option semantics, version strings, chunk ordering, alignment, relocation content, diagnostics, exit semantics, and required edge cases).

### Unresolved-difference register (exception path)

If any externally visible behavior cannot yet match exactly, list it explicitly as unresolved with evidence, rationale, parity impact, and closure plan. No implicit differences are acceptable.

### Three-way test traceability

For each high-risk requirement, link validation to tests that compare original and recompiled behavior.

## Documentation standards

- All documentation must be Markdown with ASCII-only text.
- Keep heading hierarchy consistent and stable.
- Keep links relative and valid within this repository.
- Avoid unverifiable claims; each technical claim must map to evidence.
- Keep `HOW_TO_PROCESS_DECOMP_C.md` as repository overview only.
- Keep `README.md` as the canonical human-readable agent entrypoint.
- Keep `workflow_manifest.json` as the canonical machine-readable routing and resume file.
- Place detailed shared guidance in generic step docs and tool-specific guidance in per-tool docs.

## Recommended specification structure

1. Overview and responsibilities.
2. CLI contract and option precedence.
3. Input and output model.
4. Processing pipeline and invariants.
5. Error model and diagnostics.
6. Compatibility-critical rules and parity constraints.
7. Scope coverage across full original behavior.
8. Evidence log and conflict resolution notes.
9. Traceability matrix.
10. Open questions, uncertainty register, and closure experiments.
11. Validation summary with three-way test references.

This structure is provided as a ready-to-fill scaffold in `templates/step2_specification_scaffold.md`.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 2 completion criteria

Step 2 is complete for a tool when:

1. Documentation is implementation-ready and states exact-original behavior for each original path/feature/edge case with requirement/evidence linkage.
2. Compatibility-critical behavior is explicit, marked must-match, and linked to validation tests with status for outputs, diagnostics, exit behavior, option semantics, and edge cases.
3. Runtime and static evidence references are present for all high-risk claims, including fixture IDs and command captures.
4. Uncertainty is explicit, bounded, and paired with closure experiments.
5. ASCII, heading structure, and link sanity checks pass with no broken internal references.
