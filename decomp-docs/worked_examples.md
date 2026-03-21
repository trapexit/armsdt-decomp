# Worked examples for step artifacts

This file provides compact examples of closeout-ready artifact updates.

## Example 1: Step 2 requirement with evidence linkage

```text
Requirement ID: armlib-REQ-014
Behavior: Duplicate member replacement keeps deterministic archive order.
Evidence IDs: EVT-011, EST-004
Validation reference: tests/test_replace_duplicate.c::test_order_stability
Status: confirmed
```

Minimal runtime evidence row:

```text
EVT-011 | ../armlib r lib.alf a.o a.o | FX-ARL-03 | logs/evt-011.stderr | 0 | cmp | confirmed
```

## Example 2: Blocked item with closure experiment

```text
Item ID: O-007
Reference: armlink-REQ-032
Reason: Relocation-order mismatch on mixed input class.
Status: blocked
Closure experiment: Run mixed-reloc fixture set with deterministic input ordering and compare emitted relocation blocks with cmp/hex diff.
Expected observation: Mismatch localizes to relocation-write pass ordering.
```

## Example 3: Step 3 three-way summary row

```text
Scenario ID: S-012
Original: pass
Recompiled: pass
Recreated: pass
Parity check: cmp
Status: confirmed
```

Use these examples as shape references only; keep real artifacts in tool-local step outputs.
