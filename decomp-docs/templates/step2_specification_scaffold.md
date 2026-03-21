# Step 2 technical specification scaffold

Copy this scaffold into `<tool>/technical_specification.md` and fill it with tool-specific evidence.

## 1. Overview and responsibilities

- Tool:
- Binary version string evidence:
- Scope summary:

## 2. CLI contract and precedence

| Requirement ID | Behavior | Evidence IDs | Status (`confirmed`/`open`/`blocked`) |
| --- | --- | --- | --- |
| `<tool>-REQ-001` |  |  |  |

Include:

- options, aliases, defaults
- repeated-option behavior
- invalid-combination diagnostics
- exit behavior precedence

## 3. Input and output model

Document accepted inputs, rejected forms, output structure/order/alignment, and compatibility-sensitive fields.

## 4. Processing pipeline and invariants

Describe stages, transitions, ordering guarantees, and externally visible side effects.

## 5. Error model and diagnostics

| Requirement ID | Trigger | Expected stderr/exit behavior | Evidence IDs | Status |
| --- | --- | --- | --- | --- |
| `<tool>-REQ-050` |  |  |  |  |

## 6. Compatibility-critical rules (must-match)

Explicitly list behavior that must match exactly, including any byte-for-byte output classes validated with `cmp`.

## 7. Feature inventory rollup

| Feature ID | Family | Behavior summary | Evidence IDs | Tests | Status (`confirmed`/`open`/`blocked`) |
| --- | --- | --- | --- | --- | --- |
| `FEAT-001` |  |  |  |  |  |

## 8. Evidence log and conflicts

### Runtime evidence

| Evidence ID | Command | Fixture ID(s) | Capture path | Exit code | Parity mode | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `EVT-001` |  |  |  |  |  |  |

### Static evidence

| Evidence ID | Source artifact | Path and line range | Rationale | Status |
| --- | --- | --- | --- | --- |
| `EST-001` |  |  |  |  |

### Conflict notes

| Conflict ID | Sources in conflict | Chosen interpretation | Authority rationale | Follow-up |
| --- | --- | --- | --- | --- |
| `C-001` |  |  |  |  |

## 9. Traceability matrix

| Requirement ID | Behavior statement | Category | Evidence IDs | Confidence | Validation reference | Status (`confirmed`/`open`/`blocked`) | Follow-up action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `<tool>-REQ-100` |  |  |  |  |  |  |  |

## 10. Uncertainty and closure experiments

| Item ID | Requirement/Feature reference | Uncertainty note | Parity impact | Closure experiment | Expected observation | Status (`open`/`blocked`) |
| --- | --- | --- | --- | --- | --- | --- |
| `O-001` |  |  |  |  |  |  |

## 11. Validation summary

- Shared-test coverage references:
- Three-way parity summary reference:
- Remaining blockers:
