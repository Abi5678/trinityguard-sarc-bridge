"""
TrinityGuard-SARC Safety Bridge.

OWASP × SARC: Integrates TrinityGuard pre-deployment safety testing
(20 risk types, 3 levels) into SARC runtime governance
(4 enforcement sites, hard/soft constraints, trace trees).

The bridge compiles TrinityGuard's OWASP-aligned risk taxonomy into
SARC ConstraintSpec objects, enabling structural enforcement of
safety properties at the right points in the agent loop.

Usage:
    from trinityguard_sarc_bridge import SafetyBridgeLoop, TrinityGuardRiskRegistry, RiskLevel

    risk_registry = TrinityGuardRiskRegistry()
    constraints = risk_registry.to_sarc_constraints(levels=[RiskLevel.L1, RiskLevel.L2, RiskLevel.L3])

    loop = SafetyBridgeLoop(constraints=constraints, agent_id="my_agent")
    result = loop.step(AgentAction(action="send_email", params={...}))
"""

__version__ = "0.1.0"

from .risk_registry import (
    OWASPReference,
    RiskDefinition,
    RiskLevel,
    TrinityGuardRiskRegistry,
)
from .bridge import SafetyBridgeLoop, SafetyAlert
from .safety_hooks import RuntimeSafetyHook, SafetyHookRegistry
from .pre_deployment import PreDeploymentTester, TestResult
from .report import UnifiedSafetyReport
from .owasp_map import OWASPMap, owasp_map
from .os_security import (
    OSSecurityGate,
    IsolationDomainManager,
    CapabilityManager,
    IPCMediator,
    ActionChainAnalyzer,
    DomainType,
    DomainPolicy,
    IPCPolicy,
    MessageDirection,
)

__all__ = [
    # Version
    "__version__",
    # Risk Registry
    "OWASPReference",
    "RiskDefinition",
    "RiskLevel",
    "TrinityGuardRiskRegistry",
    # Bridge
    "SafetyBridgeLoop",
    "SafetyAlert",
    # Safety Hooks
    "RuntimeSafetyHook",
    "SafetyHookRegistry",
    # Pre-Deployment
    "PreDeploymentTester",
    "TestResult",
    # Reports
    "UnifiedSafetyReport",
    # OWASP
    "OWASPMap",
    "owasp_map",
    # OS Security Layer
    "OSSecurityGate",
    "IsolationDomainManager",
    "CapabilityManager",
    "IPCMediator",
    "ActionChainAnalyzer",
    "DomainType",
    "DomainPolicy",
    "IPCPolicy",
    "MessageDirection",
]
