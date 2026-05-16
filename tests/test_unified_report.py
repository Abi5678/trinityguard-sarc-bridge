"""Tests for the Unified Safety Report."""

import json
import pytest

from trinityguard_sarc_bridge.bridge import SafetyBridgeLoop, AgentAction
from trinityguard_sarc_bridge.report import UnifiedSafetyReport
from trinityguard_sarc_bridge.risk_registry import TrinityGuardRiskRegistry, RiskLevel
from trinityguard_sarc_bridge.pre_deployment import PreDeploymentTester, PreTestOutcome


class TestUnifiedSafetyReport:
    """Tests for the unified safety report generator."""

    def test_report_from_loop(self):
        """Should generate report from a bridge loop."""
        registry = TrinityGuardRiskRegistry()
        constraints = registry.to_sarc_constraints(levels=[RiskLevel.L1])

        loop = SafetyBridgeLoop(
            constraints=constraints,
            agent_id="test_agent",
            enable_safety_hooks=False,
        )
        loop.step(AgentAction(action="test_action"))

        report = UnifiedSafetyReport.from_loop(loop, agent_id="test_agent")
        text = report.to_text()
        assert "test_agent" in text
        assert "OWASP" in text
        assert "Risk Coverage" in text

    def test_report_with_test_results(self):
        """Report should include pre-deployment test results."""
        registry = TrinityGuardRiskRegistry()
        constraints = registry.to_sarc_constraints(levels=[RiskLevel.L1])

        loop = SafetyBridgeLoop(
            constraints=constraints,
            agent_id="test",
            enable_safety_hooks=False,
        )

        tester = PreDeploymentTester(constraints)
        test_results = tester.run_all(risk_levels=[RiskLevel.L1])

        report = UnifiedSafetyReport.from_loop(
            loop, test_results=test_results, agent_id="test"
        )
        text = report.to_text()
        assert "Pre-Deployment" in text

    def test_report_dict_format(self):
        """Report should be serializable to dict."""
        loop = SafetyBridgeLoop(
            constraints=TrinityGuardRiskRegistry().to_sarc_constraints(levels=[RiskLevel.L1]),
            agent_id="test",
            enable_safety_hooks=False,
        )
        loop.step(AgentAction(action="test"))

        report = UnifiedSafetyReport.from_loop(loop)
        d = report.to_dict()
        assert "generated_at" in d
        assert "sections" in d
        assert len(d["sections"]) > 0

    def test_report_json_export(self, tmp_path):
        """Report should export to JSON."""
        loop = SafetyBridgeLoop(
            constraints=TrinityGuardRiskRegistry().to_sarc_constraints(levels=[RiskLevel.L1]),
            agent_id="test",
            enable_safety_hooks=False,
        )
        loop.step(AgentAction(action="test"))

        report = UnifiedSafetyReport.from_loop(loop)
        filepath = str(tmp_path / "report.json")
        report.export_json(filepath)

        with open(filepath) as f:
            data = json.load(f)
        assert "sections" in data

    def test_report_text_export(self, tmp_path):
        """Report should export to text file."""
        loop = SafetyBridgeLoop(
            constraints=TrinityGuardRiskRegistry().to_sarc_constraints(levels=[RiskLevel.L1]),
            agent_id="test",
            enable_safety_hooks=False,
        )
        loop.step(AgentAction(action="test"))

        report = UnifiedSafetyReport.from_loop(loop)
        filepath = str(tmp_path / "report.txt")
        report.export_text(filepath)

        with open(filepath) as f:
            content = f.read()
        assert "UNIFIED SAFETY REPORT" in content

    def test_report_with_alerts(self):
        """Report should include safety alerts."""
        from trinityguard_sarc_bridge.safety_hooks import (
            SafetyHookRegistry, RuntimeSafetyHook, HookSeverity,
        )

        hook_registry = SafetyHookRegistry()
        hook_registry.register(RuntimeSafetyHook(
            risk_id="dangerous",
            name="dangerous_hook",
            keywords=["delete all"],
            severity=HookSeverity.HIGH,
        ))

        loop = SafetyBridgeLoop(
            constraints=[],
            agent_id="test",
            enable_safety_hooks=True,
            hook_registry=hook_registry,
        )
        loop.step(AgentAction(action="delete all data"))

        report = UnifiedSafetyReport.from_loop(loop)
        text = report.to_text()
        assert "Runtime Safety Alerts" in text

    def test_report_with_audit_trail(self):
        """Report should include audit trail."""
        loop = SafetyBridgeLoop(
            constraints=TrinityGuardRiskRegistry().to_sarc_constraints(levels=[RiskLevel.L1]),
            agent_id="test",
            enable_safety_hooks=False,
        )
        for i in range(5):
            loop.step(AgentAction(action=f"action_{i}"))

        report = UnifiedSafetyReport.from_loop(loop)
        text = report.to_text()
        assert "Audit Trail" in text

    def test_report_metadata(self):
        """Report should carry custom metadata."""
        loop = SafetyBridgeLoop(
            constraints=TrinityGuardRiskRegistry().to_sarc_constraints(levels=[RiskLevel.L1]),
            agent_id="test",
            enable_safety_hooks=False,
        )

        report = UnifiedSafetyReport.from_loop(
            loop,
            report_metadata={"version": "1.0", "environment": "staging"},
        )
        text = report.to_text()
        assert "version: 1.0" in text
        assert "environment: staging" in text


class TestPreDeploymentTester:
    """Tests for pre-deployment tester (report integration)."""

    def test_full_suite(self):
        tester = PreDeploymentTester()
        results = tester.run_all()
        assert len(results) == 20

    def test_report_format(self):
        tester = PreDeploymentTester()
        tester.run_all()
        report = tester.get_report()
        assert "PRE-DEPLOYMENT SAFETY TEST REPORT" in report

    def test_stats(self):
        tester = PreDeploymentTester()
        tester.run_all()
        stats = tester.get_stats()
        assert stats["total"] == 20
        assert "pass_rate" in stats

    def test_filtered_by_level(self):
        tester = PreDeploymentTester()
        l1_results = tester.run_all(risk_levels=["L1"])
        assert len(l1_results) == 8

    def test_filtered_by_risk_id(self):
        tester = PreDeploymentTester()
        results = tester.run_all(risk_ids=["jailbreak", "prompt_injection"])
        assert len(results) == 2
