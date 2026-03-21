# Agent operations overview

This directory provides reusable operations guidance for generic coding agents.

It is orchestration-only guidance. Canonical workflow authority remains:

1. `decomp-docs/README.md`
2. `decomp-docs/workflow_manifest.json`
3. `decomp-docs/generic_step1.md`, `decomp-docs/generic_step2.md`, `decomp-docs/generic_step3.md`
4. Per-tool `decomp-docs/*_step*.md`

## Layout

- `runbooks/`: repeatable procedures for session setup, task selection, execution handling, and migration.

Use this folder to standardize execution style without duplicating or replacing step authority.
