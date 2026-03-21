# armasm Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `armasm/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


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

## Step 1 completion criteria

Step 1 for `armasm` is complete when:

1. Recompiled `armasm` builds repeatably and assembles representative all architecture modes supported by the original binary fixtures end-to-end.
2. Shared tests match original behavior for macro expansion, label resolution, and directive handling.
3. Compatibility-sensitive object output (encoding bytes, relocation records, and section ordering) is parity-checked.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
