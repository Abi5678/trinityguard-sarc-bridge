"""
OWASP Top 10 Agentic AI Security Risks ↔ TrinityGuard Risk Mapping.

Maps each of the 10 OWASP ASI risks to the TrinityGuard risk types
that provide coverage, along with SARC enforcement guidance.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OWASPRisk:
    """A single OWASP ASI risk with coverage information."""
    id: str                          # e.g., "ASI-01"
    name: str                        # e.g., "Indirect Prompt Injection"
    description: str
    trinityguard_coverage: list[str]  # TrinityGuard risk IDs providing coverage
    sarc_enforcement_guidance: str    # How SARC enforces this risk
    severity: str = "high"           # high, medium, low


class OWASPMap:
    """OWASP Top 10 Agentic AI Security Risks mapping to TrinityGuard + SARC.

    Provides:
      - Lookup by OWASP ID (asi_01, asi_02, ...)
      - Full coverage matrix
      - Risk-to-constraint guidance
    """

    def __init__(self) -> None:
        self._risks: dict[str, OWASPRisk] = {
            "ASI-01": OWASPRisk(
                id="ASI-01",
                name="Indirect Prompt Injection",
                description=(
                    "LLM processing untrusted data can manipulate the system's behavior, "
                    "leading to unintended actions."
                ),
                trinityguard_coverage=["jailbreak", "prompt_injection"],
                sarc_enforcement_guidance=(
                    "Enforced at PRE_ACTION via hard constraints on agent inputs. "
                    "TrinityGuard monitors detect injection patterns in prompts; "
                    "SARC's Pre-Action Gate blocks the action before execution."
                ),
            ),
            "ASI-02": OWASPRisk(
                id="ASI-02",
                name="Training Data Poisoning",
                description=(
                    "Manipulation of training data or public knowledge bases to embed "
                    "vulnerabilities or biases."
                ),
                trinityguard_coverage=["memory_poisoning", "identity_spoofing", "message_tampering", "malicious_propagation"],
                sarc_enforcement_guidance=(
                    "Memory poisoning blocked at PRE_ACTION. Inter-agent tampering "
                    "detected at ACTION_TIME via SARC's monitor. Rogue memory writes "
                    "escalated through ER."
                ),
            ),
            "ASI-03": OWASPRisk(
                id="ASI-03",
                name="Supply Chain Vulnerabilities",
                description=(
                    "Vulnerable components or models from third-party sources can "
                    "compromise the overall system."
                ),
                trinityguard_coverage=["sensitive_disclosure", "insecure_output"],
                sarc_enforcement_guidance=(
                    "Data disclosure blocked at PRE_ACTION. Insecure outputs "
                    "monitored at POST_ACTION with soft constraints. Audit trail "
                    "captured for supply chain compliance."
                ),
            ),
            "ASI-04": OWASPRisk(
                id="ASI-04",
                name="Data Processing Errors",
                description=(
                    "Incorrect handling of structured data or instructions may lead to "
                    "unintended behavior, silent failures, or data corruption."
                ),
                trinityguard_coverage=["hallucination", "group_hallucination"],
                sarc_enforcement_guidance=(
                    "Hallucination treated as soft constraint at POST_ACTION — "
                    "logged, monitored for patterns. Group hallucination detected "
                    "across multi-agent traces via SARC's TraceTree analysis."
                ),
            ),
            "ASI-05": OWASPRisk(
                id="ASI-05",
                name="System Prompt Leakage",
                description=(
                    "System prompts or model internals may be exposed to end users "
                    "through carefully crafted queries."
                ),
                trinityguard_coverage=["sandbox_escape", "code_execution"],
                sarc_enforcement_guidance=(
                    "Sandbox escape blocked at PRE_ACTION (hard). Code execution "
                    "escalated at PRE_ACTION to human review. SARC's trace tree "
                    "captures all prompt-like content for audit."
                ),
            ),
            "ASI-06": OWASPRisk(
                id="ASI-06",
                name="Improper Output Handling",
                description=(
                    "LLM outputs consumed by downstream components without proper "
                    "validation may lead to vulnerabilities."
                ),
                trinityguard_coverage=["tool_misuse", "excessive_agency"],
                sarc_enforcement_guidance=(
                    "Tool misuse and excessive agency blocked at PRE_ACTION. "
                    "SARC enforces parameter validation and tool scope constraints "
                    "as hard constraints before dispatch."
                ),
            ),
            "ASI-07": OWASPRisk(
                id="ASI-07",
                name="Excessive Agency",
                description=(
                    "LLM-based systems granted excessive autonomy, permissions, or "
                    "functionality beyond what is needed."
                ),
                trinityguard_coverage=["excessive_agency", "goal_drift", "malicious_emergence", "rogue_agent"],
                sarc_enforcement_guidance=(
                    "Excessive agency blocked at PRE_ACTION. Goal drift monitored "
                    "at ACTION_TIME (soft → escalation). Malicious emergence and "
                    "rogue agent detected at ACTION_TIME/POST_ACTION with hard "
                    "escalation."
                ),
            ),
            "ASI-08": OWASPRisk(
                id="ASI-08",
                name="Insufficient Isolation",
                description=(
                    "Improper separation between tenants, users, or sessions may "
                    "allow unintended data access or privilege escalation."
                ),
                trinityguard_coverage=["sandbox_escape", "cascading_failures"],
                sarc_enforcement_guidance=(
                    "Sandbox escape blocked at PRE_ACTION (hard). Cascading failures "
                    "escalated at ACTION_TIME. SARC's trace tree provides attribution-"
                    "preserving isolation boundaries."
                ),
            ),
            "ASI-09": OWASPRisk(
                id="ASI-09",
                name="Excessive Authorisation",
                description=(
                    "LLM-based systems may access resources or perform actions beyond "
                    "what the user or system intends."
                ),
                trinityguard_coverage=["excessive_agency", "hallucination"],
                sarc_enforcement_guidance=(
                    "Excessive agency blocked at PRE_ACTION with scope-limited "
                    "constraints. Hallucination-driven unauthorized actions caught "
                    "by soft POST_ACTION monitoring."
                ),
            ),
            "ASI-10": OWASPRisk(
                id="ASI-10",
                name="Insufficient Logging & Monitoring",
                description=(
                    "Lack of comprehensive logging and monitoring for LLM system "
                    "inputs, outputs, and actions."
                ),
                trinityguard_coverage=["insufficient_monitoring", "cascading_failures"],
                sarc_enforcement_guidance=(
                    "Insufficient monitoring enforced as PERIODIC soft constraint "
                    "with ESCALATE response. SARC's trace tree provides structural "
                    "audit-by-construction. Cascading failures detected through "
                    "cross-agent trace analysis."
                ),
            ),
        }

    def get(self, owasp_id: str) -> OWASPRisk | None:
        """Look up an OWASP risk by ID (case-insensitive)."""
        return self._risks.get(owasp_id.upper())

    def all_risks(self) -> list[OWASPRisk]:
        """Return all 10 OWASP risks."""
        return list(self._risks.values())

    def coverage_matrix(self) -> dict[str, dict[str, Any]]:
        """Generate an OWASP coverage matrix showing which TrinityGuard risks cover each ASI item."""
        matrix = {}
        for risk_id, risk in self._risks.items():
            matrix[risk_id] = {
                "name": risk.name,
                "severity": risk.severity,
                "trinityguard_coverage": risk.trinityguard_coverage,
                "coverage_count": len(risk.trinityguard_coverage),
                "sarc_enforcement": risk.sarc_enforcement_guidance,
            }
        return matrix

    def risks_covering(self, tg_risk_id: str) -> list[str]:
        """Find which OWASP risks are covered by a given TrinityGuard risk ID."""
        return [
            risk_id for risk_id, risk in self._risks.items()
            if tg_risk_id in risk.trinityguard_coverage
        ]

    def total_coverage(self) -> dict[str, int]:
        """Count total coverage across all OWASP risks."""
        return {
            "total_owasp_risks": len(self._risks),
            "fully_covered": sum(1 for r in self._risks.values() if r.trinityguard_coverage),
            "coverage_entries": sum(len(r.trinityguard_coverage) for r in self._risks.values()),
        }


# Singleton instance
owasp_map = OWASPMap()
