# decaof Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `decaof/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


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

## Step 1 completion criteria

Step 1 for `decaof` is complete when:

1. Recompiled `decaof` builds repeatably and decodes all original inputs.
2. Shared tests match original behavior for chunk traversal and core render behavior.
3. Parity checks cover compatibility-sensitive text formatting and decoded output structure.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original debug/disassembly behavior is excluded.
