"""
TrinityGuard Risk Registry — Risk Taxonomy → SARC Constraint Compilation.

Defines TrinityGuard's 20 risk types across 3 levels (L1/L2/L3) and
provides compilation into SARC ConstraintSpec objects. Each risk carries
OWASP references, severity, and the full SARC constraint specification
(class, verification point, response protocol).

This is the core of the bridge: TrinityGuard's risk knowledge compiled
into SARC's enforcement architecture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .owasp_map import owasp_map


# ---------------------------------------------------------------------------
# Enums & Types
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """TrinityGuard risk taxonomy levels."""
    L1 = "L1"  # Single-Agent Risks
    L2 = "L2"  # Inter-Agent Communication Risks
    L3 = "L3"  # System-Level Risks


@dataclass(frozen=True)
class OWASPReference:
    """Reference to OWASP Top 10 Agentic AI Security risk."""
    id: str          # e.g., "ASI-01"
    name: str        # e.g., "Indirect Prompt Injection"
    relevance: str   # How the TG risk relates to this OWASP risk


# ---------------------------------------------------------------------------
# Risk Definition — TrinityGuard risk with SARC mapping
# ---------------------------------------------------------------------------

@dataclass
class RiskDefinition:
    """A TrinityGuard risk type with its SARC constraint mapping.

    This is the bridge artifact: it encodes both TrinityGuard's safety
    knowledge and how that knowledge maps to SARC enforcement.
    """
    # TrinityGuard identification
    risk_id: str              # e.g., "jailbreak"
    name: str                 # e.g., "Jailbreak"
    level: RiskLevel          # L1, L2, or L3
    description: str          # What this risk is
    owasp_refs: list[OWASPReference]  # OWASP ASI references

    # SARC constraint mapping
    constraint_class: str     # "hard" or "soft"
    verification_point: str   # "pre_action", "action_time", "post_action", "periodic"
    response_protocol: str    # "block", "throttle", "escalate", "log_and_continue", "rollback"
    severity: str = "high"    # high, medium, low

    # Safety hook configuration (for runtime safety checks)
    enable_safety_hook: bool = True
    hook_keywords: list[str] = field(default_factory=list)  # Trigger words for lightweight checks

    def to_sarc_constraint_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs for creating a SARC ConstraintSpec.

        The caller must provide `predicate`, `name`, and `description`.
        This provides the governance metadata.
        """
        tags = [
            f"trinityguard:{self.risk_id}",
        ] + [
            f"owasp:{ref.id}" for ref in self.owasp_refs
        ] + [
            f"level:{self.level.value}",
            f"severity:{self.severity}",
        ]
        return {
            "constraint_class": self.constraint_class,
            "verification_point": self.verification_point,
            "response_protocol": self.response_protocol,
            "tags": tags,
        }


# ---------------------------------------------------------------------------
# Built-in Risk Definitions — All 20 TrinityGuard Risks
# ---------------------------------------------------------------------------

def _l1_risks() -> list[RiskDefinition]:
    """L1: Single-Agent Risks (8 types)."""
    return [
        RiskDefinition(
            risk_id="jailbreak",
            name="Jailbreak",
            level=RiskLevel.L1,
            description="Bypass safety guidelines through crafted prompts",
            owasp_refs=[
                OWASPReference("ASI-01", "Indirect Prompt Injection", "Direct coverage"),
                OWASPReference("ASI-04", "Data Processing Errors", "Jailbreak exploits data processing"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["ignore previous instructions", "you are now", "bypass", "override safety"],
        ),
        RiskDefinition(
            risk_id="prompt_injection",
            name="Prompt Injection",
            level=RiskLevel.L1,
            description="Inject malicious instructions into agent prompts",
            owasp_refs=[
                OWASPReference("ASI-01", "Indirect Prompt Injection", "Primary coverage"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["<system>", "</system>", "new instruction:", "ignore above", "role: admin"],
        ),
        RiskDefinition(
            risk_id="sensitive_disclosure",
            name="Sensitive Data Disclosure",
            level=RiskLevel.L1,
            description="Leak sensitive information through agent outputs",
            owasp_refs=[
                OWASPReference("ASI-03", "Supply Chain Vulnerabilities", "Data exfiltration vector"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["ssn", "social security", "credit card", "password", "api_key", "secret_key"],
        ),
        RiskDefinition(
            risk_id="excessive_agency",
            name="Excessive Agency",
            level=RiskLevel.L1,
            description="Agent takes unauthorized actions beyond its scope",
            owasp_refs=[
                OWASPReference("ASI-07", "Excessive Agency", "Direct coverage"),
                OWASPReference("ASI-09", "Excessive Authorisation", "Related coverage"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["delete all", "drop database", "rm -rf", "shutdown", "reboot"],
        ),
        RiskDefinition(
            risk_id="code_execution",
            name="Code Execution",
            level=RiskLevel.L1,
            description="Execute dangerous or unauthorized code",
            owasp_refs=[
                OWASPReference("ASI-05", "System Prompt Leakage", "Code execution can leak internals"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["exec(", "eval(", "os.system", "subprocess", "__import__", "compile("],
        ),
        RiskDefinition(
            risk_id="hallucination",
            name="Hallucination",
            level=RiskLevel.L1,
            description="Generate false or misleading information",
            owasp_refs=[
                OWASPReference("ASI-04", "Data Processing Errors", "Hallucination is a data processing failure"),
            ],
            constraint_class="soft",
            verification_point="post_action",
            response_protocol="log_and_continue",
            severity="medium",
            enable_safety_hook=True,
            hook_keywords=["i'm confident that", "according to", "as of", "it is well known"],
        ),
        RiskDefinition(
            risk_id="memory_poisoning",
            name="Memory Poisoning",
            level=RiskLevel.L1,
            description="Corrupt agent memory with malicious content",
            owasp_refs=[
                OWASPReference("ASI-02", "Training Data Poisoning", "Runtime analogue of training poisoning"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=False,  # Requires agent-specific memory access
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="tool_misuse",
            name="Tool Misuse",
            level=RiskLevel.L1,
            description="Misuse available tools for unintended purposes",
            owasp_refs=[
                OWASPReference("ASI-06", "Improper Output Handling", "Tool misuse via output exploitation"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["unauthorized", "bypass security", "escalate privileges", "access restricted"],
        ),
    ]


def _l2_risks() -> list[RiskDefinition]:
    """L2: Inter-Agent Communication Risks (6 types)."""
    return [
        RiskDefinition(
            risk_id="message_tampering",
            name="Message Tampering",
            level=RiskLevel.L2,
            description="Modify messages in transit between agents",
            owasp_refs=[
                OWASPReference("ASI-02", "Training Data Poisoning", "Inter-agent data integrity"),
            ],
            constraint_class="hard",
            verification_point="action_time",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="malicious_propagation",
            name="Malicious Propagation",
            level=RiskLevel.L2,
            description="Spread harmful content across agent network",
            owasp_refs=[
                OWASPReference("ASI-02", "Training Data Poisoning", "Content propagation vector"),
            ],
            constraint_class="hard",
            verification_point="action_time",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="misinformation_amplification",
            name="Misinformation Amplification",
            level=RiskLevel.L2,
            description="Amplify false information through agent interactions",
            owasp_refs=[
                OWASPReference("ASI-04", "Data Processing Errors", "Amplified processing errors"),
            ],
            constraint_class="soft",
            verification_point="post_action",
            response_protocol="throttle",
            severity="medium",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="insecure_output",
            name="Insecure Output",
            level=RiskLevel.L2,
            description="Produce unsafe output that could harm downstream systems",
            owasp_refs=[
                OWASPReference("ASI-03", "Supply Chain Vulnerabilities", "Output as attack vector"),
            ],
            constraint_class="soft",
            verification_point="post_action",
            response_protocol="log_and_continue",
            severity="medium",
            enable_safety_hook=True,
            hook_keywords=["<script", "javascript:", "data:", "vbscript"],
        ),
        RiskDefinition(
            risk_id="goal_drift",
            name="Goal Drift",
            level=RiskLevel.L2,
            description="Deviate from original goals during multi-step execution",
            owasp_refs=[
                OWASPReference("ASI-07", "Excessive Agency", "Goal drift enables excessive agency"),
            ],
            constraint_class="soft",
            verification_point="action_time",
            response_protocol="escalate",
            severity="medium",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="identity_spoofing",
            name="Identity Spoofing",
            level=RiskLevel.L2,
            description="Impersonate other agents in multi-agent system",
            owasp_refs=[
                OWASPReference("ASI-02", "Training Data Poisoning", "Identity as trust vector"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
    ]


def _os_risks() -> list[RiskDefinition]:
    """OS-Level Structural Risks (4 types).

    Based on arXiv:2605.14932 "Toward Securing AI Agents Like
    Operating Systems" — these risks address structural vulnerabilities
    that the behavioral 20 risk types cannot fully cover.
    """
    return [
        RiskDefinition(
            risk_id="privilege_escalation",
            name="Privilege Escalation Chain",
            level=RiskLevel.L3,
            description=(
                "Multi-step privilege escalation through tool composition. "
                "Individually safe tool calls combined to escalate access "
                "(e.g., file_read → extract secrets → exec with credentials)."
            ),
            owasp_refs=[
                OWASPReference("ASI-07", "Excessive Agency", "Chain enables excessive agency"),
                OWASPReference("ASI-09", "Excessive Authorisation", "Escalation exceeds granted auth"),
            ],
            constraint_class="hard",
            verification_point="action_time",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=False,  # Requires chain analysis, not pattern matching
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="covert_exfiltration",
            name="Covert Data Exfiltration",
            level=RiskLevel.L3,
            description=(
                "Data exfiltration through indirect channels: encoding data "
                "in file names, error messages, rapid small messages, or "
                "timing patterns. Not detectable by simple content filters."
            ),
            owasp_refs=[
                OWASPReference("ASI-08", "Insufficient Isolation", "Lack of traffic analysis"),
                OWASPReference("ASI-10", "Insufficient Logging & Monitoring", "Covert channels evade logging"),
            ],
            constraint_class="soft",
            verification_point="action_time",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=False,  # Requires behavioral analysis, not pattern matching
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="isolation_breach",
            name="Isolation Boundary Breach",
            level=RiskLevel.L3,
            description=(
                "Violation of process isolation domain boundaries. Agent in "
                "one isolation domain accesses resources or communicates with "
                "agents in another domain without authorization."
            ),
            owasp_refs=[
                OWASPReference("ASI-08", "Insufficient Isolation", "Direct coverage"),
                OWASPReference("ASI-07", "Excessive Agency", "Cross-domain access is excessive agency"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=False,  # Requires domain tracking
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="capability_abuse",
            name="Capability Token Abuse",
            level=RiskLevel.L2,
            description=(
                "Exceeding or circumventing granted capability tokens for tool "
                "access. Includes using tokens for unintended purposes, "
                "exhausting tokens for denial-of-service, or forging tokens."
            ),
            owasp_refs=[
                OWASPReference("ASI-09", "Excessive Authorisation", "Exceeding granted authorisation"),
                OWASPReference("ASI-07", "Excessive Agency", "Capability abuse enables agency"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=False,  # Requires capability token tracking
            hook_keywords=[],
        ),
    ]


def _l3_risks() -> list[RiskDefinition]:
    """L3: System-Level Risks (6 types)."""
    return [
        RiskDefinition(
            risk_id="cascading_failures",
            name="Cascading Failures",
            level=RiskLevel.L3,
            description="Failure propagation across the multi-agent system",
            owasp_refs=[
                OWASPReference("ASI-10", "Insufficient Logging & Monitoring", "Failure detection"),
                OWASPReference("ASI-08", "Insufficient Isolation", "Isolation prevents cascading"),
            ],
            constraint_class="hard",
            verification_point="action_time",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=False,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="sandbox_escape",
            name="Sandbox Escape",
            level=RiskLevel.L3,
            description="Break isolation boundaries of the execution environment",
            owasp_refs=[
                OWASPReference("ASI-05", "System Prompt Leakage", "Escape enables info leakage"),
                OWASPReference("ASI-08", "Insufficient Isolation", "Direct coverage"),
            ],
            constraint_class="hard",
            verification_point="pre_action",
            response_protocol="block",
            severity="high",
            enable_safety_hook=True,
            hook_keywords=["/proc/", "/etc/passwd", "__pycache__", ".env", "chmod", "chown"],
        ),
        RiskDefinition(
            risk_id="insufficient_monitoring",
            name="Insufficient Monitoring",
            level=RiskLevel.L3,
            description="Inadequate oversight of agent system behavior",
            owasp_refs=[
                OWASPReference("ASI-10", "Insufficient Logging & Monitoring", "Direct coverage"),
            ],
            constraint_class="soft",
            verification_point="periodic",
            response_protocol="escalate",
            severity="medium",
            enable_safety_hook=False,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="group_hallucination",
            name="Group Hallucination",
            level=RiskLevel.L3,
            description="Collective false beliefs reinforced across agent interactions",
            owasp_refs=[
                OWASPReference("ASI-04", "Data Processing Errors", "Systematic data processing failure"),
            ],
            constraint_class="soft",
            verification_point="post_action",
            response_protocol="log_and_continue",
            severity="medium",
            enable_safety_hook=True,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="malicious_emergence",
            name="Malicious Emergence",
            level=RiskLevel.L3,
            description="Harmful emergent behavior from agent interactions",
            owasp_refs=[
                OWASPReference("ASI-07", "Excessive Agency", "Emergence enables novel agency"),
            ],
            constraint_class="hard",
            verification_point="post_action",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=False,
            hook_keywords=[],
        ),
        RiskDefinition(
            risk_id="rogue_agent",
            name="Rogue Agent",
            level=RiskLevel.L3,
            description="Uncontrolled agent behavior outside intended parameters",
            owasp_refs=[
                OWASPReference("ASI-07", "Excessive Agency", "Extreme excessive agency"),
            ],
            constraint_class="hard",
            verification_point="action_time",
            response_protocol="escalate",
            severity="high",
            enable_safety_hook=False,
            hook_keywords=[],
        ),
    ]


# ---------------------------------------------------------------------------
# Risk Registry
# ---------------------------------------------------------------------------

class TrinityGuardRiskRegistry:
    """Central registry for TrinityGuard's 20 risk types.

    Provides:
      - Lookup by risk ID, level, severity
      - Compilation to SARC ConstraintSpec objects
      - OWASP coverage analysis
      - Customization via overrides

    Usage:
        registry = TrinityGuardRiskRegistry()
        constraints = registry.to_sarc_constraints(
            levels=[RiskLevel.L1, RiskLevel.L2],
            predicate_factory=my_predicate_factory,
        )
    """

    def __init__(self) -> None:
        self._risks: dict[str, RiskDefinition] = {}
        for risk in _l1_risks() + _l2_risks() + _l3_risks() + _os_risks():
            self._risks[risk.risk_id] = risk

    def get(self, risk_id: str) -> RiskDefinition | None:
        """Look up a risk by ID."""
        return self._risks.get(risk_id)

    def all_risks(self) -> list[RiskDefinition]:
        """Return all 20 risk definitions."""
        return list(self._risks.values())

    def by_level(self, level: RiskLevel) -> list[RiskDefinition]:
        """Filter risks by level (L1, L2, L3)."""
        return [r for r in self._risks.values() if r.level == level]

    def by_severity(self, severity: str) -> list[RiskDefinition]:
        """Filter risks by severity (high, medium, low)."""
        return [r for r in self._risks.values() if r.severity == severity]

    def by_class(self, constraint_class: str) -> list[RiskDefinition]:
        """Filter risks by SARC constraint class (hard, soft)."""
        return [r for r in self._risks.values() if r.constraint_class == constraint_class]

    def risks_with_hooks(self) -> list[RiskDefinition]:
        """Return risks that have runtime safety hooks enabled."""
        return [r for r in self._risks.values() if r.enable_safety_hook]

    def count_by_level(self) -> dict[str, int]:
        """Count risks per level."""
        counts: dict[str, int] = {}
        for r in self._risks.values():
            counts[r.level.value] = counts.get(r.level.value, 0) + 1
        return counts

    def count_by_class(self) -> dict[str, int]:
        """Count risks by constraint class."""
        counts: dict[str, int] = {}
        for r in self._risks.values():
            counts[r.constraint_class] = counts.get(r.constraint_class, 0) + 1
        return counts

    def owasp_coverage(self) -> dict[str, list[str]]:
        """Map OWASP risk IDs to covering TrinityGuard risks."""
        coverage: dict[str, list[str]] = {}
        for risk in self._risks.values():
            for ref in risk.owasp_refs:
                coverage.setdefault(ref.id, []).append(risk.risk_id)
        return coverage

    def to_sarc_constraints(
        self,
        levels: list[RiskLevel] | None = None,
        predicate_factory: Any = None,
        overrides: dict[str, dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Compile risk definitions into SARC ConstraintSpec constructor kwargs.

        Returns a list of dicts, each suitable for unpacking into
        `ConstraintSpec(name=..., description=..., ...)`.

        Args:
            levels: Filter by risk levels (default: all levels).
            predicate_factory: Optional callable(risk_def) -> predicate_fn.
                If not provided, returns placeholder predicates that always pass.
            overrides: Optional dict mapping risk_id to override kwargs
                (e.g., {"hallucination": {"constraint_class": "hard"}}).

        Returns:
            List of ConstraintSpec constructor kwargs dicts.
        """
        overrides = overrides or {}
        risks = self.all_risks()

        if levels:
            levels_set = set(levels)
            risks = [r for r in risks if r.level in levels_set]

        results = []
        for risk in risks:
            kwargs = risk.to_sarc_constraint_kwargs()

            # Apply overrides
            if risk.risk_id in overrides:
                kwargs.update(overrides[risk.risk_id])

            # Name and description
            kwargs["name"] = f"tg_{risk.risk_id}"
            kwargs["description"] = risk.description

            # Source: OWASP-mapped risks are REGULATORY by default
            kwargs["source"] = "regulatory" if risk.owasp_refs else "organizational"

            # Predicate
            if predicate_factory:
                kwargs["predicate"] = predicate_factory(risk)
            else:
                # Default: always-pass predicate (caller should replace with real checks)
                kwargs["predicate"] = lambda ctx, _rid=risk.risk_id: (
                    True, {"risk_id": _rid, "check": "placeholder"}
                )

            # Constraint class enum
            from sarc import ConstraintClass, ResponseProtocol, VerificationPoint

            class_map = {"hard": ConstraintClass.HARD, "soft": ConstraintClass.SOFT}
            vp_map = {
                "pre_action": VerificationPoint.PRE_ACTION,
                "action_time": VerificationPoint.ACTION_TIME,
                "post_action": VerificationPoint.POST_ACTION,
                "periodic": VerificationPoint.PERIODIC,
            }
            rp_map = {
                "block": ResponseProtocol.BLOCK,
                "throttle": ResponseProtocol.THROTTLE,
                "escalate": ResponseProtocol.ESCALATE,
                "log_and_continue": ResponseProtocol.LOG_AND_CONTINUE,
                "rollback": ResponseProtocol.ROLLBACK,
            }

            kwargs["constraint_class"] = class_map[kwargs["constraint_class"]]
            kwargs["verification_point"] = vp_map[kwargs["verification_point"]]
            kwargs["response_protocol"] = rp_map[kwargs["response_protocol"]]

            # Tags (already set by to_sarc_constraint_kwargs, just ensure list)
            kwargs["tags"] = kwargs.get("tags", [])

            # Soft constraints need OperatingPoint
            if kwargs["constraint_class"] == ConstraintClass.SOFT:
                from sarc import OperatingPoint
                kwargs["operating_point"] = OperatingPoint(
                    tolerance_pct=10.0,
                    window_seconds=60.0,
                )

            results.append(kwargs)

        return results
