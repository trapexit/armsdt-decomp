# Workflow glossary

## Core terms

- **Exact-original parity**: No externally visible mismatch versus original behavior for outputs, diagnostics, exit behavior, option semantics, and edge handling.
- **Closeout criteria**: Required conditions that must be satisfied before a step can be marked complete.
- **Compatibility-sensitive output**: Output class where byte identity or strictly defined semantic identity is required for acceptance.
- **Three-way parity**: Comparison across original, recompiled, and recreated binaries.
- **Material batch**: A logical implementation or parity-fix increment that should be committed before starting the next increment.
- **Near-complete**: Candidate step with all required outputs present and only narrow closeout work remaining.

## Evidence terms

- **Runtime evidence**: Command, fixture identity, stdout/stderr, exit code, and output comparison result.
- **Static evidence**: Source reference with path and line range plus rationale.
- **Stale evidence**: Evidence invalidated by later material changes to covered code/tests/requirements/outputs.
- **Closure experiment**: Reproducible next action designed to resolve an `open` or `blocked` item.

## Status vocabulary

- **`confirmed`**: Claim verified with current evidence and linked tests.
- **`open`**: Investigation active; closure experiment defined.
- **`blocked`**: Cannot proceed; blocker and next closure experiment documented.
