# Workflow status matrix

This file is the concise repository-visible snapshot of tool and step readiness.

Status vocabulary: `confirmed`, `open`, `blocked`.

## Baseline snapshot

| Tool | Step 1 core outputs (`Makefile`, `src/`, `tests/`) | Step 1 build (`recompiled/build/<tool>`) | Step 2 spec (`technical_specification.md`) | Step 3 core outputs (`Makefile`, `src/`, `tests/`) | Step 3 build (`recreated/build/<tool>`) | Primary blocker/notes |
| --- | --- | --- | --- | --- | --- | --- |
| `armlib` | confirmed | blocked | open | open | open | Step 1 compile-triage remains blocked at runtime parity. This batch converted `__libc_start_main` from an infinite-loop stub to a minimal dispatcher and added lightweight startup breadcrumbs in `recompiled/src/armlib.c`. Evidence now advances from timeout to crash: candidate `./build/armlib`, `./build/armlib -help`, and `./build/armlib -vsn` each exit 139 (segfault), while original exits remain `1`/`0`/`1`; `make test` now fails with no-args exit mismatch (`orig=1`, `cand=139`). Breadcrumbs show execution reaches `FUN_0804a988` and passes `FUN_0804b7f0` (`DBG:4a988:enter`, `DBG:4a988:post_b7f0`) before crashing. Next closure experiment: instrument immediately after each reset/allocation step in `FUN_0804a988` and triage the first crashing helper/global write on that path (pointer-width/global typing likely), then rerun no-args/help/vsn parity probes. |
| `decaof` | open | open | open | open | open | Step outputs not started |
| `armlink` | open | open | open | open | open | Step outputs not started |
| `armasm` | open | open | open | open | open | Step outputs not started |
| `armcc` | open | open | open | open | open | Step outputs not started |
| `armcpp` | open | open | open | open | open | Step outputs not started |

## Current readiness highlights

1. Highest-priority actionable item remains step 1 completion for `armlib`.
2. `armlib` step 1 core outputs remain present (`recompiled/Makefile`, `recompiled/src/`, `recompiled/tests/`), and compile triage is active with startup-dispatch recovery applied; runtime has progressed from timeout to an early segfault and still blocks two-way CLI parity.
3. Step 1 remains the active phase across all tools; step 2 and step 3 are not ready for any tool.

## Update rules

1. Update this file whenever a tool-step readiness state changes.
2. Use only `confirmed`, `open`, and `blocked`.
3. Keep blockers concrete and include the next closure experiment in touched step artifacts.
