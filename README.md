# TrinityGuard-SARC Safety Bridge

> **OWASP × SARC: Pre-deployment safety testing meets runtime governance.**

Bridges [TrinityGuard](https://github.com/AI45Lab/TrinityGuard) (20 risk types, 3 levels, OWASP-aligned) with [SARC](https://arxiv.org/abs/2605.07728) (governance-by-architecture, 4 enforcement sites) to create a unified safety governance layer for agentic AI systems.

## The Gap This Bridge Fills

| Framework | What It Provides | What It Lacks |
|---|---|---|
| **TrinityGuard** | Pre-deployment safety testing (20 risk types), runtime monitoring via LLM judges, OWASP Top 10 Agentic AI mapping | Structural enforcement sites — monitors detect but don't block/throttle/rollback at runtime |
| **SARC** | 4 enforcement sites (PAG/ATM/PAA/ER), hard/soft constraint classes, attribution-preserving trace trees, audit-by-construction | Concrete safety test cases and risk taxonomy — knows *where* to enforce but not *what* to check for |

**The bridge**: TrinityGuard's risk taxonomy and test suite *compile into* SARC constraint specifications. TrinityGuard's monitors become *sources* for SARC's enforcement sites. SARC's architecture *enforces* what TrinityGuard detects.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    TrinityGuard-SARC Bridge                      │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │   TrinityGuard        │    │   SARC                       │  │
│  │                       │    │                              │  │
│  │  20 Risk Types        │    │  4 Enforcement Sites         │  │
│  │  ┌─── L1: 8 risks ──┐│    │  ┌─ Pre-Action Gate ──────┐ │  │
│  │  │ Jailbreak          ││    │  │                        │ │  │
│  │  │ Prompt Injection   ││───▶│  │  Hard → BLOCK          │ │  │
│  │  │ PII Disclosure     ││    │  │  Soft → THROTTLE        │ │  │
│  │  │ Excessive Agency   ││    │  └────────────────────────┘ │  │
│  │  │ Code Execution     ││    │  ┌─ Action-Time Monitor ──┐ │  │
│  │  │ Hallucination      ││    │  │                        │ │  │
│  │  │ Memory Poisoning   ││    │  │  Cumulative tracking   │ │  │
│  │  │ Tool Misuse        ││    │  │  Rate limit enforcement │ │  │
│  │  └────────────────────┘│    │  └────────────────────────┘ │  │
│  │  ┌─── L2: 6 risks ──┐│    │  ┌─ Post-Action Auditor ──┐ │  │
│  │  │ Msg Tampering      ││    │  │                        │ │  │
│  │  │ Malicious Prop.    ││───▶│  │  Side-effect detection  │ │  │
│  │  │ Misinfo Amplify    ││    │  │  Rollback capability   │ │  │
│  │  │ Insecure Output    ││    │  └────────────────────────┘ │  │
│  │  │ Goal Drift         ││    │  ┌─ Escalation Router ────┐ │  │
│  │  │ Identity Spoof     ││    │  │                        │ │  │
│  │  └────────────────────┘│    │  │  Human-in-the-loop     │ │  │
│  │  ┌─── L3: 6 risks ──┐│    │  │  Auto-resolution rules  │ │  │
│  │  │ Cascading Failures ││    │  └────────────────────────┘ │  │
│  │  │ Sandbox Escape     ││    │                              │  │
│  │  │ Insufficient Mon.  ││    │  Trace Tree:                 │  │
│  │  │ Group Halluc.      ││    │  Full attribution chain      │  │
│  │  │ Malicious Emerg.   ││    │  Blame assignment            │  │
│  │  │ Rogue Agent        ││    │  Audit replay                │  │
│  │  └────────────────────┘│    │                              │  │
│  └──────────────────────┘    └──────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Bridge Layer                                              │  │
│  │  • risk_to_constraint()  — Risk taxonomy → SARC specs     │  │
│  │  • SafetyBridgeloop      — Governed loop with TG monitors  │  │
│  │  • UnifiedSafetyReport   — Combined test + audit report    │  │
│  │  • OWASP Mapping         — ASI-01..10 ↔ SARC sources      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Risk-to-Constraint Mapping

Each of TrinityGuard's 20 risk types maps to a SARC `ConstraintSpec`:

### L1 — Single-Agent Risks (8)

| Risk | OWASP Ref | SARC Class | Verification Point | Response |
|---|---|---|---|---|
| Jailbreak | ASI-01, ASI-04 | HARD | PRE_ACTION | BLOCK |
| Prompt Injection | ASI-01 | HARD | PRE_ACTION | BLOCK |
| Sensitive Data Disclosure | ASI-03 | HARD | PRE_ACTION | BLOCK |
| Excessive Agency | ASI-07 | HARD | PRE_ACTION | BLOCK |
| Code Execution | ASI-05 | HARD | PRE_ACTION | ESCALATE |
| Hallucination | ASI-09 | SOFT | POST_ACTION | LOG_AND_CONTINUE |
| Memory Poisoning | ASI-02 | HARD | PRE_ACTION | BLOCK |
| Tool Misuse | ASI-06 | HARD | PRE_ACTION | BLOCK |

### L2 — Inter-Agent Communication Risks (6)

| Risk | OWASP Ref | SARC Class | Verification Point | Response |
|---|---|---|---|---|
| Message Tampering | ASI-02 | HARD | ACTION_TIME | BLOCK |
| Malicious Propagation | ASI-02 | HARD | ACTION_TIME | ESCALATE |
| Misinformation Amplification | ASI-09 | SOFT | POST_ACTION | THROTTLE |
| Insecure Output | ASI-03 | SOFT | POST_ACTION | LOG_AND_CONTINUE |
| Goal Drift | ASI-07 | SOFT | ACTION_TIME | ESCALATE |
| Identity Spoofing | ASI-02 | HARD | PRE_ACTION | BLOCK |

### L3 — System-Level Risks (6)

| Risk | OWASP Ref | SARC Class | Verification Point | Response |
|---|---|---|---|---|
| Cascading Failures | ASI-10 | HARD | ACTION_TIME | ESCALATE |
| Sandbox Escape | ASI-05 | HARD | PRE_ACTION | BLOCK |
| Insufficient Monitoring | ASI-10 | SOFT | PERIODIC | ESCALATE |
| Group Hallucination | ASI-09 | SOFT | POST_ACTION | LOG_AND_CONTINUE |
| Malicious Emergence | ASI-07 | HARD | POST_ACTION | ESCALATE |
| Rogue Agent | ASI-07 | HARD | ACTION_TIME | ESCALATE |

## Quick Start

```bash
pip install -e .
```

### Option 1: Use the Risk Registry (TrinityGuard taxonomy → SARC constraints)

```python
from trinityguard_sarc_bridge import (
    SafetyBridgeLoop,
    TrinityGuardRiskRegistry,
    RiskLevel,
)

# Create constraints from TrinityGuard's full risk taxonomy
risk_registry = TrinityGuardRiskRegistry()
sarc_constraints = risk_registry.to_sarc_constraints(
    levels=[RiskLevel.L1, RiskLevel.L2, RiskLevel.L3],
    # Customize: make hallucination a hard constraint instead of soft
    overrides={
        "hallucination": {"constraint_class": "hard"},
    },
)

# Create a governed loop with TrinityGuard safety constraints
loop = SafetyBridgeLoop(
    constraints=sarc_constraints,
    agent_id="my_agent",
)

# Every action now passes through OWASP-aligned safety gates
result = loop.step(AgentAction(action="send_email", params={
    "recipient": "user@example.com",
    "body": "This is a test email",
}))
print(f"Decision: {result.gated.decision}")  # ALLOW, BLOCK, THROTTLE, or ESCALATE
print(f"Safety alerts: {len(loop.safety_alerts)}")
```

### Option 2: Use with Pre-Deployment Testing

```python
from trinityguard_sarc_bridge import (
    SafetyBridgeLoop,
    TrinityGuardRiskRegistry,
    PreDeploymentTester,
    UnifiedSafetyReport,
)

# 1. Define which risks to test for
risk_registry = TrinityGuardRiskRegistry()
constraints = risk_registry.to_sarc_constraints(levels=[RiskLevel.L1, RiskLevel.L2])

# 2. Run pre-deployment tests (simulated TrinityGuard test suite)
tester = PreDeploymentTester(constraints)
test_results = tester.run_all(risk_levels=[RiskLevel.L1, RiskLevel.L2])
print(tester.get_report())

# 3. Deploy with only passing constraints, or all constraints in monitoring mode
loop = SafetyBridgeLoop(
    constraints=constraints,
    agent_id="production_agent",
    enable_safety_hooks=True,  # Enable TrinityGuard-style safety checks
)

# 4. After execution, generate unified report
report = UnifiedSafetyReport.from_loop(loop)
report.export_json("safety_report.json")
```

### Option 3: Framework-Agnostic Integration

```python
from trinityguard_sarc_bridge import SafetyBridgeLoop

# Wrap any agent framework
def my_agent_executor(action: str, params: dict) -> dict:
    """Execute action using your preferred agent framework."""
    # CrewAI, LangGraph, AutoGen, custom...
    return your_framework.execute(action, params)

loop = SafetyBridgeLoop(
    constraints=constraints,
    executor=my_agent_executor,
    agent_id="wrapped_agent",
)
```

## Key Features

### 1. Automated Risk-to-Constraint Compilation
TrinityGuard's 20 risk types automatically compile into SARC constraint specifications with correct class, verification point, and response protocol.

### 2. Pre-Deployment Safety Testing
Run TrinityGuard-style test cases before deployment. Failed tests generate additional runtime constraints.

### 3. OWASP Top 10 Agentic AI Mapping
Every constraint carries OWASP ASI references. Use `constraint.tags` or `constraint.source` for compliance reporting.

### 4. Runtime Safety Hooks
Optional runtime safety hooks perform lightweight checks inspired by TrinityGuard's monitor agents — catching jailbreaks, prompt injection, excessive agency, etc. at the structural enforcement sites.

### 5. Unified Safety Report
Combines pre-deployment test results with runtime audit trails into a single compliance report with OWASP coverage matrix.

### 6. Multi-Agent Safety
Constraint propagation through SARC's trace trees ensures that safety constraints follow delegation chains — a manager's constraints bind its workers.

## Project Structure

```
trinityguard-sarc-bridge/
├── README.md                          # This file
├── pyproject.toml                     # Package config
├── trinityguard_sarc_bridge/
│   ├── __init__.py                    # Public API
│   ├── risk_registry.py               # TrinityGuard risk taxonomy → SARC constraints
│   ├── bridge.py                      # SafetyBridgeLoop (main integration)
│   ├── safety_hooks.py                # Runtime safety checks (TG-inspired monitors)
│   ├── pre_deployment.py              # Pre-deployment testing framework
│   ├── report.py                      # Unified safety report generator
│   └── owasp_map.py                   # OWASP ASI-01..10 ↔ risk mapping
├── tests/
│   ├── test_risk_registry.py          # Risk-to-constraint compilation tests
│   ├── test_bridge.py                 # Bridge integration tests
│   ├── test_safety_hooks.py           # Runtime safety hook tests
│   └── test_unified_report.py         # Report generation tests
├── examples/
│   ├── basic_usage.py                 # Quick-start example
│   ├── pre_deployment_demo.py         # Pre-deployment testing demo
│   └── multi_agent_safety.py          # Multi-agent safety propagation
└── docs/
    └── ARCHITECTURE.md                # Detailed architecture document
```

## Compliance Coverage

The bridge provides structural coverage of **all 10 OWASP Top 10 Agentic AI Security Risks**:

| OWASP Risk | Coverage | How |
|---|---|---|
| ASI-01: Indirect Prompt Injection | ✅ | Prompt Injection + Jailbreak constraints at PAG |
| ASI-02: Training Data Poisoning | ✅ | Memory Poisoning + Identity Spoofing constraints |
| ASI-03: Supply Chain Vulnerabilities | ✅ | Sensitive Data Disclosure + Insecure Output |
| ASI-04: Data Processing Errors | ✅ | Hallucination + Group Hallucination soft constraints |
| ASI-05: System Prompt Leakage | ✅ | Sandbox Escape + Code Execution at PAG |
| ASI-06: Improper Output Handling | ✅ | Tool Misuse + Excessive Agency at PAG |
| ASI-07: Excessive Agency | ✅ | Goal Drift + Malicious Emergence + Rogue Agent |
| ASI-08: Insufficient Isolation | ✅ | Sandbox Escape + Cascading Failures |
| ASI-09: Excessive Authorisation | ✅ | Excessive Agency + Hallucination soft monitoring |
| ASI-10: Insufficient Logging & Monitoring | ✅ | Insufficient Monitoring periodic constraint |

## License

MIT — inherits from both TrinityGuard (MIT) and SARC prototype (MIT).
