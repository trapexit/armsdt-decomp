# Workflow state and routing diagram

Use this file for a compact visual of step routing and start-gate transitions.

## Step state machine (per tool)

```text
               +------------------------------------------+
               | Step 1: <tool>/recompiled/               |
               | required: Makefile, src/, tests/, build/ |
               +-------------------+----------------------+
                                   |
                                   | step-1 outputs present
                                   v
               +------------------------------------------+
               | Step 2: <tool>/technical_specification.md|
               | required: traceability + inventory +     |
               | evidence-backed exact-original contract  |
               +-------------------+----------------------+
                                   |
                                   | step-2 spec current
                                   v
               +------------------------------------------+
               | Step 3: <tool>/recreated/                |
               | required: Makefile, src/, tests/, build/ |
               +------------------------------------------+
```

## Readiness and loopback rules

```text
Missing outputs OR incomplete closeout evidence => stay in current step
Blocked item with closure experiment              => stay in current step
Externally visible mismatch found                 => return to active step work
Stale evidence after material change              => refresh evidence before closeout
```

## Candidate selection flow

```text
1) Recompute readiness from repository state
2) Check near-complete criteria
   - outputs exist
   - remaining work is narrowly scoped
   - no unresolved hard-stop
   - fits one material batch
   - start gates preserved
3) If a candidate passes all checks, finish it first
4) Otherwise select first ready tool by priority:
   armlib -> decaof -> armlink -> armasm -> armcc -> armcpp
```

## Status vocabulary

Use only:

- `confirmed`
- `open`
- `blocked`
