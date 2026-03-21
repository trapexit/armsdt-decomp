#!/usr/bin/env python3
from __future__ import annotations

import json
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / 'decomp-docs'
README = DOCS_DIR / 'README.md'
MANIFEST = DOCS_DIR / 'workflow_manifest.json'
EXECUTION_INDEX = DOCS_DIR / 'execution_index.md'
WORKFLOW_STATUS = DOCS_DIR / 'workflow_status.md'
TEMPLATES_DIR = DOCS_DIR / 'templates'
SCOPE_POLICY_FILE = DOCS_DIR / 'scope_policy.json'
HOW = ROOT / 'HOW_TO_PROCESS_DECOMP_C.md'
AGENTS = ROOT / 'AGENTS.md'
AGENTS_DIR = ROOT / 'agents'
SKILLS_DIR = ROOT / 'skills'
PROMPTS_DIR = ROOT / 'prompts'
LINK_RE = re.compile(r'\[[^\]]+\]\(([^)]+)\)')
EXPECTED_TOOLS = ['armlib', 'decaof', 'armlink', 'armasm', 'armcc', 'armcpp']
REQUIRED_AGENT_FILES = [
    'AGENTS.md',
    'agents/README.md',
    'agents/runbooks/session-setup.md',
    'agents/runbooks/select-next-step.md',
    'agents/runbooks/blocker-handling.md',
    'agents/runbooks/migration-map.md',
    'skills/README.md',
    'skills/select-next-ready-step/SKILL.md',
    'skills/step1-recompiled/SKILL.md',
    'skills/step2-specification/SKILL.md',
    'skills/step3-recreated/SKILL.md',
    'skills/parity-evidence-and-status/SKILL.md',
    'prompts/README.md',
    'prompts/templates/resume-work.prompt.md',
    'prompts/templates/step-handoff.prompt.md',
    'prompts/templates/blocker-triage.prompt.md',
]
REQUIRED_DECOMP_FILES = [
    'decomp-docs/execution_index.md',
    'decomp-docs/workflow_status.md',
    'decomp-docs/workflow_diagram.md',
    'decomp-docs/state_recovery.md',
    'decomp-docs/glossary.md',
    'decomp-docs/worked_examples.md',
    'decomp-docs/scope_policy.json',
    'decomp-docs/templates/README.md',
    'decomp-docs/templates/step1_evidence_log.md',
    'decomp-docs/templates/step2_traceability_matrix.md',
    'decomp-docs/templates/step2_specification_scaffold.md',
    'decomp-docs/templates/step3_parity_summary.md',
    'decomp-docs/templates/blocker_closure_record.md',
]
SCOPE_POLICY_PATTERNS: list[tuple[str, re.Pattern[str]]] = []

errors: list[str] = []


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def read_text(path: Path) -> str:
    if not path.exists():
        errors.append(f'Missing required file: {rel(path)}')
        return ''
    return path.read_text(encoding='utf-8')


def require_contains(path: Path, needle: str) -> None:
    text = read_text(path)
    check(needle in text, f'{rel(path)} missing required text: {needle}')


def validate_links(path: Path) -> None:
    text = read_text(path)
    for target in LINK_RE.findall(text):
        if target.startswith(('http://', 'https://', 'mailto:')):
            continue
        relative_target = target.split('#', 1)[0]
        if not relative_target:
            continue
        resolved = (path.parent / relative_target).resolve()
        if not resolved.exists():
            errors.append(f'Broken link in {rel(path)} -> {target}')


def validate_scope_policy(path: Path) -> None:
    text = read_text(path)
    for label, pattern in SCOPE_POLICY_PATTERNS:
        if pattern.search(text):
            errors.append(f'{rel(path)} contains banned scope text: {label}')


def load_scope_policy_patterns() -> None:
    global SCOPE_POLICY_PATTERNS
    try:
        raw = json.loads(SCOPE_POLICY_FILE.read_text(encoding='utf-8'))
    except FileNotFoundError:
        errors.append(f'Missing required file: {rel(SCOPE_POLICY_FILE)}')
        SCOPE_POLICY_PATTERNS = []
        return
    except json.JSONDecodeError as exc:
        errors.append(f'{rel(SCOPE_POLICY_FILE)} is not valid JSON: {exc}')
        SCOPE_POLICY_PATTERNS = []
        return

    rules = raw.get('rules')
    if not isinstance(rules, list):
        errors.append(f'{rel(SCOPE_POLICY_FILE)} missing required list: rules')
        SCOPE_POLICY_PATTERNS = []
        return

    loaded: list[tuple[str, re.Pattern[str]]] = []
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f'{rel(SCOPE_POLICY_FILE)} rules[{idx}] must be an object')
            continue
        label = rule.get('label')
        pattern = rule.get('pattern')
        if not isinstance(label, str) or not label:
            errors.append(f'{rel(SCOPE_POLICY_FILE)} rules[{idx}] missing string label')
            continue
        if not isinstance(pattern, str) or not pattern:
            errors.append(f'{rel(SCOPE_POLICY_FILE)} rules[{idx}] missing string pattern')
            continue
        try:
            loaded.append((label, re.compile(re.escape(pattern))))
        except re.error as exc:
            errors.append(f'{rel(SCOPE_POLICY_FILE)} rules[{idx}] invalid pattern: {exc}')
    SCOPE_POLICY_PATTERNS = loaded


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Validate decomp-docs workflow contracts')
    parser.add_argument('--json', action='store_true', dest='json_output', help='Emit machine-readable JSON result')
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    for path in (README, MANIFEST, EXECUTION_INDEX, WORKFLOW_STATUS, HOW, AGENTS):
        check(path.exists(), f'Missing required file: {rel(path)}')

    for relative in REQUIRED_AGENT_FILES:
        check((ROOT / relative).exists(), f'Missing required file: {relative}')
    for relative in REQUIRED_DECOMP_FILES:
        check((ROOT / relative).exists(), f'Missing required file: {relative}')

    check(SCOPE_POLICY_FILE.exists(), f'Missing required file: {rel(SCOPE_POLICY_FILE)}')
    load_scope_policy_patterns()

    manifest = {}
    if MANIFEST.exists():
        try:
            manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            errors.append(f'{rel(MANIFEST)} is not valid JSON: {exc}')

    check(manifest.get('canonical_human_entrypoint') == 'decomp-docs/README.md', 'workflow_manifest.json canonical_human_entrypoint mismatch')
    check(manifest.get('repository_overview') == 'HOW_TO_PROCESS_DECOMP_C.md', 'workflow_manifest.json repository_overview mismatch')
    check(manifest.get('machine_validation') == 'decomp-docs/validate_docs.py', 'workflow_manifest.json machine_validation mismatch')
    check(manifest.get('status_values') == ['confirmed', 'open', 'blocked'], 'workflow_manifest.json status_values mismatch')

    require_contains(README, '## Canonical authority order')
    require_contains(README, '## How to choose the next tool and step')
    require_contains(README, '## Resume protocol')
    require_contains(README, 'execution_index.md')
    require_contains(README, 'workflow_status.md')
    require_contains(README, 'workflow_diagram.md')
    require_contains(README, 'state_recovery.md')
    require_contains(README, 'templates/README.md')
    require_contains(README, 'worked_examples.md')
    require_contains(README, 'glossary.md')
    require_contains(README, 'technical_specification.md')
    require_contains(README, 'ASCII `HISTORY:` block')
    require_contains(README, 'likely original function boundaries and structure')
    require_contains(README, 'Near-complete decision checklist')
    require_contains(README, 'step2_specification_scaffold.md')
    require_contains(EXECUTION_INDEX, '## Canonical authority and routing')
    require_contains(EXECUTION_INDEX, 'workflow_status.md')
    require_contains(EXECUTION_INDEX, 'templates/README.md')
    require_contains(EXECUTION_INDEX, 'state_recovery.md')
    require_contains(EXECUTION_INDEX, 'workflow_diagram.md')
    require_contains(EXECUTION_INDEX, 'step2_specification_scaffold.md')
    require_contains(WORKFLOW_STATUS, 'Status vocabulary: `confirmed`, `open`, `blocked`')
    require_contains(WORKFLOW_STATUS, '## Baseline snapshot')
    require_contains(WORKFLOW_STATUS, '`armcpp`')
    require_contains(WORKFLOW_STATUS, '| `armcpp` | open | open | open | open | open | Step outputs not started |')
    require_contains(TEMPLATES_DIR / 'README.md', 'step1_evidence_log.md')
    require_contains(TEMPLATES_DIR / 'README.md', 'step2_traceability_matrix.md')
    require_contains(TEMPLATES_DIR / 'README.md', 'step2_specification_scaffold.md')
    require_contains(TEMPLATES_DIR / 'README.md', 'step3_parity_summary.md')
    require_contains(TEMPLATES_DIR / 'README.md', 'blocker_closure_record.md')
    require_contains(TEMPLATES_DIR / 'step1_evidence_log.md', '## Runtime evidence')
    require_contains(TEMPLATES_DIR / 'step2_traceability_matrix.md', 'Requirement ID')
    require_contains(TEMPLATES_DIR / 'step2_specification_scaffold.md', '<tool>/technical_specification.md')
    require_contains(TEMPLATES_DIR / 'step2_specification_scaffold.md', 'Requirement ID')
    require_contains(TEMPLATES_DIR / 'step3_parity_summary.md', '## Three-way execution summary')
    require_contains(TEMPLATES_DIR / 'blocker_closure_record.md', '## Closure experiment')
    require_contains(HOW, '[decomp-docs/README.md](decomp-docs/README.md)')
    require_contains(HOW, '[decomp-docs/workflow_manifest.json](decomp-docs/workflow_manifest.json)')
    require_contains(HOW, '[decomp-docs/execution_index.md](decomp-docs/execution_index.md)')
    require_contains(HOW, '[decomp-docs/workflow_status.md](decomp-docs/workflow_status.md)')
    require_contains(HOW, 'decomp-docs/generic_step1.md')
    require_contains(HOW, 'decomp-docs/generic_step2.md')
    require_contains(HOW, 'decomp-docs/generic_step3.md')
    require_contains(HOW, 'decomp-docs/templates/README.md')
    require_contains(HOW, 'After each material implementation change')
    require_contains(HOW, 'ASCII `HISTORY:` block')
    require_contains(HOW, 'preserve likely original C89 source structure')
    require_contains(AGENTS, 'decomp-docs/README.md')
    require_contains(AGENTS, 'decomp-docs/workflow_manifest.json')
    require_contains(AGENTS, '`confirmed`, `open`, `blocked`')

    require_contains(ROOT / 'agents/README.md', 'orchestration-only guidance')
    require_contains(ROOT / 'agents/runbooks/session-setup.md', 'skills/README.md')
    require_contains(ROOT / 'agents/runbooks/session-setup.md', 'decomp-docs/execution_index.md')
    require_contains(ROOT / 'agents/runbooks/session-setup.md', 'decomp-docs/workflow_status.md')
    require_contains(ROOT / 'agents/runbooks/migration-map.md', 'prompt.txt')
    require_contains(ROOT / 'agents/runbooks/migration-map.md', 'prompts/templates/resume-work.prompt.md')

    markdown_files = (
        sorted(DOCS_DIR.glob('*.md'))
        + sorted(TEMPLATES_DIR.glob('*.md'))
        + [HOW, AGENTS]
        + sorted(AGENTS_DIR.glob('**/*.md'))
        + sorted(SKILLS_DIR.glob('**/*.md'))
        + sorted(PROMPTS_DIR.glob('**/*.md'))
    )
    for path in markdown_files:
        validate_links(path)
        validate_scope_policy(path)

    validate_scope_policy(MANIFEST)

    for doc_name in ('generic_step1.md', 'generic_step2.md', 'generic_step3.md'):
        path = DOCS_DIR / doc_name
        require_contains(path, '## Workflow entrypoint')
        require_contains(path, '## Agent contract (machine-readable)')

    require_contains(DOCS_DIR / 'generic_step1.md', '## Original-source reconstruction rule')
    require_contains(DOCS_DIR / 'generic_step1.md', 'Do not split, merge, or invent helper functions')
    require_contains(DOCS_DIR / 'generic_step1.md', 'material reconstruction or behavior-recovery batch')
    require_contains(DOCS_DIR / 'generic_step1.md', 'ASCII `HISTORY:` block')
    require_contains(DOCS_DIR / 'generic_step1.md', 'cmp original_output.bin recompiled_output.bin')
    require_contains(DOCS_DIR / 'generic_step2.md', '<tool>/technical_specification.md')
    require_contains(DOCS_DIR / 'generic_step2.md', 'templates/step2_specification_scaffold.md')
    require_contains(DOCS_DIR / 'generic_step2.md', 'compared directly with `cmp`')
    require_contains(DOCS_DIR / 'generic_step3.md', 'material recreation or parity-fix batch')
    require_contains(DOCS_DIR / 'generic_step3.md', 'ASCII `HISTORY:` block')
    require_contains(DOCS_DIR / 'generic_step3.md', 'Three-way harness protocol')
    require_contains(DOCS_DIR / 'generic_step3.md', 'cmp original_output.bin recreated_output.bin')
    require_contains(DOCS_DIR / 'generic_step3.md', '<tool>/technical_specification.md')
    require_contains(SCOPE_POLICY_FILE, '"rules"')

    tools = manifest.get('tools')
    check(isinstance(tools, list), 'workflow_manifest.json tools must be a list')
    if isinstance(tools, list):
        check([tool.get('name') for tool in tools] == EXPECTED_TOOLS, 'workflow_manifest.json tool order mismatch')
        check([tool.get('recompiled_priority') for tool in tools] == [1, 2, 3, 4, 5, 6], 'workflow_manifest.json recompiled priorities mismatch')
        check([tool.get('recreated_priority') for tool in tools] == [7, 8, 9, 10, 11, 12], 'workflow_manifest.json recreated priorities mismatch')
        for tool in tools:
            name = tool.get('name')
            if not isinstance(name, str):
                errors.append('workflow_manifest.json contains a tool without a string name')
                continue
            spec_path = f'{name}/technical_specification.md'
            check(tool.get('spec_path') == spec_path, f'workflow_manifest.json spec path mismatch for {name}')
            step_docs = tool.get('step_docs', {})
            for step in ('1', '2', '3'):
                expected_doc = f'decomp-docs/{name}_step{step}.md'
                check(step_docs.get(step) == expected_doc, f'workflow_manifest.json step doc mismatch for {name} step {step}')
                path = ROOT / expected_doc
                require_contains(path, '## Agent contract (machine-readable)')
            require_contains(ROOT / f'decomp-docs/{name}_step2.md', spec_path)
            require_contains(ROOT / f'decomp-docs/{name}_step3.md', spec_path)

    if errors:
        if args.json_output:
            print(json.dumps({
                'ok': False,
                'errors': errors,
                'checked_markdown_files': len(markdown_files),
            }, indent=2))
        else:
            for error in errors:
                print(f'ERROR: {error}')
        return 1

    if args.json_output:
        print(json.dumps({
            'ok': True,
            'errors': [],
            'checked_markdown_files': len(markdown_files),
            'checked': [
                'workflow_manifest.json',
                'per-tool step contracts',
                'scope_policy.json',
            ],
        }, indent=2))
    else:
        print('decomp-docs validation passed')
        print(f'Checked {len(markdown_files)} Markdown files, workflow_manifest.json, and per-tool step contracts.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
