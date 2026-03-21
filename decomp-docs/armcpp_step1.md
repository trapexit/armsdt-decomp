# armcpp Step 1 - Reverse engineer and recompile

## Objective

Create a faithful, compilable C89 reconstruction in `armcpp/recompiled/` using decompiled sources as reverse-engineering inputs, with the goal of preserving likely original function boundaries and structure. This step defines reverse-engineering and recompilation work only.


## Agent contract (machine-readable)

```yaml
agent_contract:
  doc_id: armcpp-step1
  step: 1
  applies_to: armcpp
  objective: reverse-engineer and recompile with exact-original parity
  must_inputs:
    - armcpp/armcpp
    - armcpp/armcpp_decomp_ghidra.c
    - armcpp/armcpp_decomp_retdec.c
    - armcpp/armcpp_objdump.txt
    - armcpp/armcpp_readelf.txt
    - armcpp/armcpp_usage.txt
  must_outputs:
    - armcpp/recompiled/Makefile
    - armcpp/recompiled/src/
    - armcpp/recompiled/tests/
    - armcpp/recompiled/build/armcpp
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

- Directory: `armcpp/`
- Tool: ARM C++ Compiler
- Description: Compiles C++ source into AOF objects.
- Original binary size: 902 KB
- Recompiled priority: 6

## Shared step 1 guidance

Use [generic_step1.md](generic_step1.md) for shared step 1 requirements:
- Required references and inputs
- Required outputs
- Bootstrap-from-Ghidra baseline and initial commit order
- Build and test workflow, including two-way testing
- Analysis workflow, portability rules, source recovery rules, and verification strategy
- Commit and artifact rules

## armcpp-specific focus

Prioritize driver compatibility and shared backend interactions first; recover C++ semantic behavior carefully for name resolution, overload behavior, and diagnostics; preserve compatibility-critical output and error behavior for supported workflows.

## Tool-specific constraints and priorities

- Prioritize driver compatibility and backend coupling before advanced C++ edge features.
- Recover C++ semantic behavior with emphasis on name resolution and overload handling.
- Treat diagnostics and deterministic output text as compatibility-critical.

## Tool-specific examples

- Overload-resolution cases with ambiguous-call diagnostics.
- Language-mode switches that alter parsing or code generation.
- Class and namespace semantics exercised by the required corpus.


## Tracking status vocabulary

Use one status vocabulary across all tables/checklists: `confirmed`, `open`, `blocked`.

- `confirmed`: verified with runtime/static evidence and linked tests.
- `open`: still under investigation; closure experiments defined.
- `blocked`: cannot proceed now; blocker and next action documented.

## Step 1 completion criteria

Step 1 for `armcpp` is complete when:

1. Recompiled `armcpp` builds repeatably and processes all original C++ inputs.
2. Shared tests match original behavior for language-mode handling, name lookup, and diagnostics.
3. Parity checks cover emitted objects and compatibility-sensitive text output.
4. Any remaining uncertainty is explicitly tracked with closure actions, and no original features are excluded.
