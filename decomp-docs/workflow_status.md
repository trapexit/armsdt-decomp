# Workflow status matrix

This file is the concise repository-visible snapshot of tool and step readiness.

Status vocabulary: `confirmed`, `open`, `blocked`.

## Baseline snapshot

| Tool | Step 1 core outputs (`Makefile`, `src/`, `tests/`) | Step 1 build (`recompiled/build/<tool>`) | Step 2 spec (`technical_specification.md`) | Step 3 core outputs (`Makefile`, `src/`, `tests/`) | Step 3 build (`recreated/build/<tool>`) | Primary blocker/notes |
| --- | --- | --- | --- | --- | --- | --- |
| `armlib` | confirmed | blocked | open | open | open | Step 1 compile-triage remains blocked at runtime parity. This batch continued startup-unblock work in `recompiled/src/armlib.c` by replacing local `strncpy`/`strcpy` infinite-loop stubs with concrete libc-equivalent loops used by `FUN_0804b7f0` program-name normalization. Build still succeeds (`rtk make` emits `recompiled/build/armlib`), but behavior is unchanged: candidate timeouts persist for `timeout 3s ./build/armlib`/`-help`/`-vsn` (exit 124) while original exits are `1`/`0`/`1`; `timeout 5s rtk make test` still exits 124 at the no-args case. Next closure experiment: add lightweight startup checkpoints (`write`-based breadcrumbs) across `_DT_INIT` -> `FUN_08048a60` -> `FUN_0804bb30` -> `FUN_0804a988` to pinpoint first reached hang site, then replace exactly that remaining import stub loop (likely in `strcmp`/`fopen`/`opendir` family). |
| `decaof` | open | open | open | open | open | Step outputs not started |
| `armlink` | open | open | open | open | open | Step outputs not started |
| `armasm` | open | open | open | open | open | Step outputs not started |
| `armcc` | open | open | open | open | open | Step outputs not started |
| `armcpp` | open | open | open | open | open | Step outputs not started |

## Current readiness highlights

1. Highest-priority actionable item remains step 1 completion for `armlib`.
2. `armlib` step 1 core outputs remain present (`recompiled/Makefile`, `recompiled/src/`, `recompiled/tests/`), and compile triage is active with incremental startup-stub recovery applied, but runtime still blocks before two-way CLI parity can pass.
3. Step 1 remains the active phase across all tools; step 2 and step 3 are not ready for any tool.

## Update rules

1. Update this file whenever a tool-step readiness state changes.
2. Use only `confirmed`, `open`, and `blocked`.
3. Keep blockers concrete and include the next closure experiment in touched step artifacts.
