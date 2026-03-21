# armlink Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `armlink/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


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

## Step 1 completion criteria

Step 1 for `armlink` is complete when:

1. Recompiled `armlink` builds repeatably and links all required input classes.
2. Shared tests match original behavior for symbol resolution, relocation application, and layout.
3. Parity checks cover output headers, section ordering, and padding-sensitive bytes.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
