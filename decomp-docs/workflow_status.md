# Workflow status matrix

This file is the concise repository-visible snapshot of tool and step readiness.

Status vocabulary: `confirmed`, `open`, `blocked`.

## Baseline snapshot

| Tool | Step 1 core outputs (`Makefile`, `src/`, `tests/`) | Step 1 build (`recompiled/build/<tool>`) | Step 2 spec (`technical_specification.md`) | Step 3 core outputs (`Makefile`, `src/`, `tests/`) | Step 3 build (`recreated/build/<tool>`) | Primary blocker/notes |
| --- | --- | --- | --- | --- | --- | --- |
| `armlib` | confirmed | blocked | open | open | open | Step 1 compile-triage remains blocked at runtime parity. This batch applied startup-unblock repairs in `recompiled/src/armlib.c`: local `printf`/`exit` now forward via `vsnprintf`+`write` and `_Exit`, frame-registration stubs (`__register_frame_info`/`__deregister_frame_info`) were converted from infinite loops to no-ops, and the unresolved `FUN_0804bb30` constructor walk was disabled to avoid pre-main loop traps. `rtk make` still emits `recompiled/build/armlib`, but startup still hangs: `timeout 3s ./build/armlib` and `timeout 3s ./build/armlib -help` both exit 124 while original exits are 1 and 0 respectively; `make test` continues to terminate at the no-args case. Next closure experiment: instrument `FUN_0804a988` early-path checkpoints and replace the first remaining infinite-loop import stub reached on startup (for example `strcpy`/`strcmp`/`fopen` family) with a behavior-preserving implementation to recover first post-startup parity signal. |
| `decaof` | open | open | open | open | open | Step outputs not started |
| `armlink` | open | open | open | open | open | Step outputs not started |
| `armasm` | open | open | open | open | open | Step outputs not started |
| `armcc` | open | open | open | open | open | Step outputs not started |
| `armcpp` | open | open | open | open | open | Step outputs not started |

## Current readiness highlights

1. Highest-priority actionable item remains step 1 completion for `armlib`.
2. `armlib` step 1 core outputs remain present (`recompiled/Makefile`, `recompiled/src/`, `recompiled/tests/`), and compile triage is active with link-stage startup, argv-width entry, and additional startup-stub recovery applied, but runtime still blocks before two-way CLI parity can pass.
3. Step 1 remains the active phase across all tools; step 2 and step 3 are not ready for any tool.

## Update rules

1. Update this file whenever a tool-step readiness state changes.
2. Use only `confirmed`, `open`, and `blocked`.
3. Keep blockers concrete and include the next closure experiment in touched step artifacts.
