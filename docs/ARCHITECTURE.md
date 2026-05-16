# Architecture — TrinityGuard-SARC Safety Bridge

## Overview

The TrinityGuard-SARC Safety Bridge is a **novel governance+safety integration** that combines:

1. **TrinityGuard's** OWASP-aligned risk taxonomy (20 risk types, 3 levels) with pre-deployment testing
2. **SARC's** governance-by-architecture (4 enforcement sites, hard/soft constraints, trace trees)

The result is a system where safety knowledge *compiles into* structural enforcement.

## Design Principles

### 1. Risk-to-Constraint Compilation

The core innovation: TrinityGuard's risk definitions aren't just labels — they **compile** into SARC constraint specifications. Each risk has:

- **Constraint Class** (hard/soft) — determines enforcement strictness
- **Verification Point** (PRE_ACTION/ACTION_TIME/POST_ACTION/PERIODIC) — determines *where* in the agent loop the check happens
- **Response Protocol** (BLOCK/THROTTLE/ESCALATE/LOG_AND_CONTINUE) — determines *what happens* on violation

This compilation is automated: `TrinityGuardRiskRegistry.to_sarc_constraints()` produces ready-to-use SARC `ConstraintSpec` objects.

### 2. Pre-Deployment + Runtime Continuity

| Phase | TrinityGuard | SARC | Bridge |
|---|---|---|---|
| **Pre-Deployment** | 20 risk type test cases | N/A | `PreDeploymentTester` runs TG-style tests, validates constraint coverage |
| **Runtime** | LLM judge monitors | 4 enforcement sites | `SafetyBridgeLoop` enforces compiled constraints at structural sites |
| **Reporting** | Test results | Audit trails | `UnifiedSafetyReport` merges both into compliance report |

Failed pre-deployment tests can add new runtime constraints. Runtime violations feed back into test improvement.

### 3. Enforcement Site Mapping

SARC's 4 enforcement sites map naturally to TrinityGuard's risk levels:

```
┌─────────────────────┐
│   PRE_ACTION_GATE   │  ← L1 risks (jailbreak, injection, PII, agency)
│   (Before execute)  │     Hard constraints → BLOCK
├─────────────────────┤
│ ACTION_TIME_MONITOR │  ← L2 risks (tampering, propagation, drift)
│  (During execute)   │     Real-time monitoring → ESCALATE
├─────────────────────┤
│ POST_ACTION_AUDITOR │  ← L2/L3 soft risks (hallucination, group errors)
│  (After execute)    │     Soft constraints → LOG_AND_CONTINUE
├─────────────────────┤
│ ESCALATION_ROUTER   │  ← L3 critical risks (cascading, emergence, rogue)
│  (On violation)     │     Hard constraints → ESCALATE to human
├─────────────────────┤
│ PERIODIC_CHECK      │  ← L3 monitoring (insufficient monitoring)
│  (Background)       │     Soft constraint → ESCALATE if gaps detected
└─────────────────────┘
```

### 4. OWASP Alignment

Every constraint carries OWASP ASI references in its `tags`. The `OWASPMap` class provides:

- Full coverage matrix (10 OWASP risks → 20 TG risks)
- Reverse lookup (TG risk → covering OWASP IDs)
- Coverage statistics for compliance reporting

## Module Architecture

### `risk_registry.py` — Risk Taxonomy

The `RiskDefinition` dataclass is the bridge artifact. It encodes:
- TrinityGuard's safety knowledge (risk ID, name, description, level, OWASP refs)
- SARC enforcement mapping (constraint class, verification point, response protocol)
- Runtime hook configuration (keywords, severity)

`TrinityGuardRiskRegistry` provides lookup, filtering, and compilation methods.

### `bridge.py` — SafetyBridgeLoop

The main integration point. Wraps any agent executor with:
1. **Pre-Action Gate** — runs hard PRE_ACTION constraints
2. **Safety Hooks** — keyword/pattern detection (TG-inspired lightweight monitors)
3. **Action Execution** — calls the wrapped executor (only if allowed)
4. **Post-Action Auditor** — runs POST_ACTION constraints on execution results
5. **Escalation Router** — handles ESCALATE decisions

The loop maintains:
- Full audit trail (`_audit_log`)
- Safety alerts list (`safety_alerts`)
- Runtime statistics

### `safety_hooks.py` — Runtime Monitors

Lightweight, deterministic monitors inspired by TrinityGuard's LLM-based judge agents:

- **Keyword matching** — detect known jailbreak/injection patterns
- **Regex patterns** — detect PII, code injection, XSS
- **Severity mapping** — HIGH/CRITICAL → BLOCK, MEDIUM → THROTTLE, LOW → ALLOW

These are first-pass filters. For production, TrinityGuard's full LLM monitors handle nuanced detection.

### `pre_deployment.py` — Test Suite

20 built-in test cases (one per risk type) validate:
- Agent resistance to jailbreaks, injection, PII disclosure
- Constraint coverage completeness
- OWASP alignment

Results feed into the unified report and can generate additional runtime constraints.

### `report.py` — Unified Safety Report

Merges pre-deployment + runtime data into:
- Executive summary (actions, blocks, escalations)
- OWASP coverage matrix (10/10 ASI risks)
- Risk coverage summary (all 20 risks with enforcement status)
- Pre-deployment test results
- Runtime safety alerts
- Audit trail

Exportable as JSON (machine-readable) or text (human-readable).

### `owasp_map.py` — OWASP Reference

Static mapping of OWASP Top 10 Agentic AI Security Risks to TrinityGuard coverage. Used for compliance reporting and constraint tagging.

## Integration Patterns

### Pattern 1: Direct Integration (Recommended)

```python
registry = TrinityGuardRiskRegistry()
constraints = registry.to_sarc_constraints()
loop = SafetyBridgeLoop(constraints=constraints, agent_id="my_agent")
result = loop.step(AgentAction(action="...", params={...}))
```

### Pattern 2: Framework Wrapping

```python
# Wrap CrewAI, LangGraph, AutoGen, etc.
loop = SafetyBridgeLoop(
    constraints=constraints,
    executor=lambda action: crew_agent.execute(action.action, action.params),
)
```

### Pattern 3: Pre-Deployment First

```python
# 1. Test before deploy
tester = PreDeploymentTester(constraints)
results = tester.run_all()
# 2. Deploy only if passing
if all(r.outcome == "passed" for r in results):
    loop = SafetyBridgeLoop(constraints=constraints, ...)
```

## Novel Contributions

1. **Automated risk-to-constraint compilation** — TrinityGuard's 20 risks automatically map to SARC enforcement specs with correct site/class/protocol
2. **Pre-deployment ↔ Runtime continuity** — Failed tests generate runtime constraints; runtime violations improve tests
3. **Full OWASP Top 10 Agentic AI coverage** — Every constraint tagged with ASI references; compliance matrix generated automatically
4. **Dual monitoring** — Lightweight deterministic hooks (fast) complement TrinityGuard's LLM judges (thorough)
5. **Unified audit trail** — Single report combining safety testing results with governance enforcement records
