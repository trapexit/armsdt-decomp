# armcc Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `armcc/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


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

## Step 1 completion criteria

Step 1 for `armcc` is complete when:

1. Recompiled `armcc` builds repeatably and compiles all original inputs end-to-end.
2. Shared tests match original behavior for driver option handling and stage transitions.
3. Parity checks cover emitted objects plus compatibility-sensitive version and diagnostic text.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original compiler features are excluded.
