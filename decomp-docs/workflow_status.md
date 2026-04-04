# Workflow status matrix

This file is the concise repository-visible snapshot of tool and step readiness.

Status vocabulary: `confirmed`, `open`, `blocked`.

## Baseline snapshot

| Tool | Step 1 core outputs (`Makefile`, `src/`, `tests/`) | Step 1 build (`recompiled/build/<tool>`) | Step 2 spec (`technical_specification.md`) | Step 3 core outputs (`Makefile`, `src/`, `tests/`) | Step 3 build (`recreated/build/<tool>`) | Primary blocker/notes |
| --- | --- | --- | --- | --- | --- | --- |
| `armlib` | confirmed | blocked | open | open | open | Step 1 compile-triage remains blocked at runtime parity. This batch replaced local `strcmp`/`strncmp` infinite-loop stubs with concrete lexicographic implementations and refreshed startup probes. Candidate `./build/armlib`, `./build/armlib -help`, and `./build/armlib -vsn` still time out (exit 124 under `timeout 5`) while original exits remain `1`/`0`/`1`; `-help`/`-vsn` still stop at reset breadcrumbs (`DBG:4a988:enter`, `DBG:4a988:post_b7f0`, `DBG:4a988:pre_reset`, `DBG:4a988:post_workspace_zero`, `DBG:4a988:post_globals_reset`), but no-args now progresses deeper through help text and reaches new `FUN_0804a378` probes up to `DBG:4a378:post_wc` before hanging (no `post_opt1`). This localizes the no-args stall to later banner formatting/output work, while help/vsn still block before option-branch breadcrumbs. Next closure experiment: replace local `fprintf` infinite-loop stub with a forwarding implementation (matching `printf`/`vfprintf` semantics enough for diagnostics) and rerun no-args/help/vsn parity probes to determine whether help/vsn advance into `FUN_0804a458` branch markers and whether no-args passes `post_opt1`/`post_opt2`. |
| `decaof` | open | open | open | open | open | Step outputs not started |
| `armlink` | open | open | open | open | open | Step outputs not started |
| `armasm` | open | open | open | open | open | Step outputs not started |
| `armcc` | open | open | open | open | open | Step outputs not started |
| `armcpp` | open | open | open | open | open | Step outputs not started |

## Current readiness highlights

1. Highest-priority actionable item remains step 1 completion for `armlib`.
2. `armlib` step 1 core outputs remain present (`recompiled/Makefile`, `recompiled/src/`, `recompiled/tests/`), and compile triage is active with startup/reset recovery applied; runtime has progressed from early segfault to later hangs after global reset and still blocks two-way CLI parity.
3. Step 1 remains the active phase across all tools; step 2 and step 3 are not ready for any tool.

## Update rules

1. Update this file whenever a tool-step readiness state changes.
2. Use only `confirmed`, `open`, and `blocked`.
3. Keep blockers concrete and include the next closure experiment in touched step artifacts.
