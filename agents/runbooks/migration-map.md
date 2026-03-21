# Runbook: migration map (prompt and setup routing)

## Goal

Map legacy ad-hoc startup guidance to the new agent operations layout without breaking existing workflow authority.

## Current mapping

1. `prompt.txt` startup instructions remain valid and continue to point to canonical workflow docs.
2. `AGENTS.md` is the new cross-agent entrypoint for structured startup.
3. `agents/runbooks/session-setup.md` defines generic coding-agent setup.
4. Reusable startup/handoff/blocker prompt patterns now live in:
   - `prompts/templates/resume-work.prompt.md`
   - `prompts/templates/step-handoff.prompt.md`
   - `prompts/templates/blocker-triage.prompt.md`

## Migration policy

- Phase 1 is additive and non-breaking: no required moves of existing canonical docs.
- Legacy references can continue to use `prompt.txt` while new sessions can standardize on `AGENTS.md` and runbooks.
- Layout and naming are kept simple for OpenCode and other coding agents: one generic setup runbook and no vendor-specific profile files.
- Any future relocation of prompt content must preserve references to:
  - `decomp-docs/README.md`
  - `decomp-docs/workflow_manifest.json`
  - `HOW_TO_PROCESS_DECOMP_C.md` as overview only
