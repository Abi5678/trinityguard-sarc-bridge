"""
Unified Safety Report — Combined Pre-Deployment + Runtime Report.

Generates a comprehensive safety report combining:
  - Pre-deployment test results (TrinityGuard-style test suite)
  - Runtime audit trail (SARC enforcement decisions)
  - OWASP coverage matrix
  - Risk coverage summary
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from .bridge import SafetyBridgeLoop, SafetyAlert
from .pre_deployment import PreDeploymentTester, TestResult
from .risk_registry import TrinityGuardRiskRegistry, RiskLevel


@dataclass
class ReportSection:
    """A section of the unified safety report."""
    title: str
    content: str
    data: dict[str, Any] = field(default_factory=dict)


class UnifiedSafetyReport:
    """Unified safety report combining pre-deployment and runtime data.

    Usage:
        report = UnifiedSafetyReport.from_loop(loop)
        print(report.to_text())
        report.export_json("safety_report.json")
    """

    def __init__(self) -> None:
        self._sections: list[ReportSection] = []
        self._generated_at: float = time.time()
        self._metadata: dict[str, Any] = {}

    def add_section(self, section: ReportSection) -> None:
        self._sections.append(section)

    @classmethod
    def from_loop(
        cls,
        loop: SafetyBridgeLoop,
        test_results: list[TestResult] | None = None,
        agent_id: str = "",
        report_metadata: dict[str, Any] | None = None,
    ) -> UnifiedSafetyReport:
        """Generate a report from a SafetyBridgeLoop instance.

        Args:
            loop: The bridge loop with runtime data.
            test_results: Optional pre-deployment test results.
            agent_id: Agent identifier for the report.
            report_metadata: Additional metadata (version, env, etc.).
        """
        report = cls()
        report._metadata = {
            "agent_id": agent_id,
            "report_version": "0.1.0",
            **(report_metadata or {}),
        }

        # Section 1: Summary
        stats = loop.get_stats()
        report.add_section(ReportSection(
            title="Executive Summary",
            content=(
                f"Agent: {agent_id or 'N/A'}\n"
                f"Actions processed: {stats['actions_processed']}\n"
                f"Actions blocked: {stats['actions_blocked']}\n"
                f"Escalations: {stats['escalations']}\n"
                f"Total alerts: {stats['total_alerts']}\n"
                f"Constraints loaded: {stats['constraints_loaded']}\n"
                f"Safety hooks active: {stats['hooks_active']}"
            ),
            data=stats,
        ))

        # Section 2: OWASP Coverage Matrix
        from .owasp_map import owasp_map
        coverage = owasp_map.coverage_matrix()
        owasp_section_data = {
            "coverage": coverage,
            "total_coverage": owasp_map.total_coverage(),
        }
        owasp_lines = ["OWASP Top 10 Agentic AI Coverage:"]
        for risk_id, info in coverage.items():
            count = info["coverage_count"]
            owasp_lines.append(f"  {risk_id}: {info['name']} → {count} TrinityGuard risk(s)")
        owasp_lines.append(f"\nTotal: {owasp_map.total_coverage()['fully_covered']}/10 OWASP risks covered")

        report.add_section(ReportSection(
            title="OWASP Coverage Matrix",
            content="\n".join(owasp_lines),
            data=owasp_section_data,
        ))

        # Section 3: Risk Coverage
        registry = TrinityGuardRiskRegistry()
        risk_section_lines = ["TrinityGuard Risk Coverage:"]
        for level in RiskLevel:
            risks = registry.by_level(level)
            risk_section_lines.append(f"\n  {level.value} — {level.value == 'L1' and 'Single-Agent' or level.value == 'L2' and 'Inter-Agent' or 'System-Level'} Risks:")
            for risk in risks:
                status = "✅ Active" if any(f"trinityguard:{risk.risk_id}" in c.get("tags", []) for c in loop._constraints) else "⚠️  Not mapped"
                risk_section_lines.append(f"    {risk.risk_id:30s} {risk.constraint_class:5s} {risk.verification_point:15s} {risk.response_protocol:18s} {status}")

        report.add_section(ReportSection(
            title="Risk Coverage Summary",
            content="\n".join(risk_section_lines),
            data={
                "l1_count": len(registry.by_level(RiskLevel.L1)),
                "l2_count": len(registry.by_level(RiskLevel.L2)),
                "l3_count": len(registry.by_level(RiskLevel.L3)),
                "hard_count": len(registry.by_class("hard")),
                "soft_count": len(registry.by_class("soft")),
            },
        ))

        # Section 4: Pre-Deployment Test Results
        if test_results:
            test_lines = ["Pre-Deployment Test Results:"]
            passed = sum(1 for r in test_results if r.outcome.value == "passed")
            total = len(test_results)
            test_lines.append(f"  Pass rate: {passed}/{total} ({passed/total*100:.1f}%)")
            for result in test_results:
                icon = "✅" if result.outcome.value == "passed" else "❌"
                test_lines.append(f"  {icon} [{result.severity.value:8s}] {result.risk_id:30s} {result.test_name}")

            report.add_section(ReportSection(
                title="Pre-Deployment Test Results",
                content="\n".join(test_lines),
                data={"passed": passed, "total": total, "results": [r.to_dict() for r in test_results]},
            ))

        # Section 5: Runtime Alerts
        if loop.safety_alerts:
            alert_lines = [f"Runtime Safety Alerts ({len(loop.safety_alerts)}):"]
            for alert in loop.safety_alerts:
                alert_lines.append(
                    f"  ⚠️  [{alert.severity.upper():6s}] {alert.risk_id:30s} "
                    f"→ {alert.decision.value:8s} on '{alert.action}' "
                    f"[{alert.constraint_name}]"
                )
                if alert.hook_result and alert.hook_result.matched_keywords:
                    alert_lines.append(f"       Keywords: {', '.join(alert.hook_result.matched_keywords)}")

            report.add_section(ReportSection(
                title="Runtime Safety Alerts",
                content="\n".join(alert_lines),
                data={"alerts": [a.to_dict() for a in loop.safety_alerts]},
            ))

        # Section 6: Audit Trail (last 20 entries)
        audit = loop.get_audit_trail()
        if audit:
            audit_lines = [f"Audit Trail (last {min(20, len(audit))} entries):"]
            for entry in audit[-20:]:
                audit_lines.append(
                    f"  [{entry['decision']:8s}] action='{entry['action']}' "
                    f"alerts={len(entry.get('alerts', []))} "
                    f"duration={entry.get('duration_ms', 0):.1f}ms"
                )
            report.add_section(ReportSection(
                title="Audit Trail",
                content="\n".join(audit_lines),
                data={"total_entries": len(audit), "recent_entries": audit[-20:]},
            ))

        return report

    def to_text(self) -> str:
        """Generate human-readable text report."""
        lines = [
            "=" * 70,
            "UNIFIED SAFETY REPORT",
            "TrinityGuard-SARC Bridge",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._generated_at))}",
            "=" * 70,
            "",
        ]

        # Metadata
        if self._metadata:
            for key, value in self._metadata.items():
                lines.append(f"{key}: {value}")
            lines.append("")

        # Sections
        for section in self._sections:
            lines.extend([
                "-" * 70,
                f"## {section.title}",
                "-" * 70,
                section.content,
                "",
            ])

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Generate machine-readable dict report."""
        return {
            "generated_at": self._generated_at,
            "metadata": self._metadata,
            "sections": [
                {"title": s.title, "content": s.content, "data": s.data}
                for s in self._sections
            ],
        }

    def export_json(self, filepath: str) -> None:
        """Export report as JSON."""
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def export_text(self, filepath: str) -> None:
        """Export report as text."""
        with open(filepath, "w") as f:
            f.write(self.to_text())
