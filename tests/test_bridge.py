"""Tests for the Safety Bridge Loop."""

import pytest

from trinityguard_sarc_bridge.bridge import (
    AgentAction,
    Decision,
    GatedResult,
    SafetyBridgeLoop,
    SafetyAlert,
)
from trinityguard_sarc_bridge.risk_registry import TrinityGuardRiskRegistry, RiskLevel
from trinityguard_sarc_bridge.safety_hooks import SafetyHookRegistry, RuntimeSafetyHook


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _always_pass_predicate(ctx, _rid="test"):
    return (True, {"reason": "pass"})


def _always_fail_predicate(ctx, _rid="test"):
    return (False, {"reason": "fail"})


def _make_constraints(count=5, predicate_fn=None):
    """Create mock constraints for testing."""
    from trinityguard_sarc_bridge.risk_registry import TrinityGuardRiskRegistry
    registry = TrinityGuardRiskRegistry()
    constraints = registry.to_sarc_constraints(
        levels=[RiskLevel.L1],
        predicate_factory=predicate_fn,
    )
    return constraints[:count]


def _make_loop(constraints=None, executor=None, enable_hooks=False):
    return SafetyBridgeLoop(
        constraints=constraints or _make_constraints(),
        agent_id="test_agent",
        executor=executor,
        enable_safety_hooks=enable_hooks,
    )


# ---------------------------------------------------------------------------
# Bridge Loop Tests
# ---------------------------------------------------------------------------

class TestSafetyBridgeLoop:
    """Tests for the main SafetyBridgeLoop."""

    def test_basic_step_allows(self):
        """Default predicates (always pass) should result in ALLOW."""
        loop = _make_loop()
        result = loop.step(AgentAction(action="say_hello"))
        assert result.allowed is True
        assert result.decision == Decision.ALLOW

    def test_step_increments_action_count(self):
        """Each step should increment the action counter."""
        loop = _make_loop()
        loop.step(AgentAction(action="test"))
        loop.step(AgentAction(action="test"))
        stats = loop.get_stats()
        assert stats["actions_processed"] == 2

    def test_agent_id_propagated(self):
        """Agent ID should be set on the action."""
        loop = _make_loop()
        result = loop.step(AgentAction(action="test"))
        assert result.action.agent_id == "test_agent"

    def test_executor_called(self):
        """Custom executor should be called with the action."""
        calls = []

        def my_executor(action: AgentAction):
            calls.append(action)
            return {"called": True}

        loop = _make_loop(executor=my_executor)
        result = loop.step(AgentAction(action="custom_action"))
        assert len(calls) == 1
        assert calls[0].action == "custom_action"
        assert result.execution_result == {"called": True}

    def test_hard_block_prevents_execution(self):
        """A hard constraint that fails at PRE_ACTION should block execution."""
        from trinityguard_sarc_bridge.risk_registry import TrinityGuardRiskRegistry

        registry = TrinityGuardRiskRegistry()
        constraints = registry.to_sarc_constraints(
            levels=[RiskLevel.L1],
            predicate_factory=lambda risk: _always_fail_predicate,
        )
        # Only keep PRE_ACTION hard constraints
        from sarc import VerificationPoint, ConstraintClass
        hard_pre = [
            c for c in constraints
            if c["verification_point"] == VerificationPoint.PRE_ACTION
        ]

        executed = []

        def executor(action):
            executed.append(action)
            return {"executed": True}

        loop = SafetyBridgeLoop(
            constraints=hard_pre[:1],  # Just one blocking constraint
            executor=executor,
            agent_id="test",
            enable_safety_hooks=False,
        )
        result = loop.step(AgentAction(action="dangerous_action"))
        assert result.was_blocked
        assert len(executed) == 0

    def test_enforcement_results_populated(self):
        """Enforcement results should be populated for each matching constraint."""
        loop = _make_loop()
        result = loop.step(AgentAction(action="test"))
        assert len(result.enforcement_results) > 0

    def test_audit_trail_grows(self):
        """Each step should add an audit entry."""
        loop = _make_loop()
        loop.step(AgentAction(action="test1"))
        loop.step(AgentAction(action="test2"))
        audit = loop.get_audit_trail()
        assert len(audit) == 2

    def test_stats_after_operations(self):
        """Stats should reflect operations."""
        loop = _make_loop()
        loop.step(AgentAction(action="test"))
        stats = loop.get_stats()
        assert stats["agent_id"] == "test_agent"
        assert stats["actions_processed"] == 1
        assert stats["constraints_loaded"] > 0

    def test_reset_stats(self):
        """Reset should clear all counters."""
        loop = _make_loop()
        loop.step(AgentAction(action="test"))
        loop.reset_stats()
        stats = loop.get_stats()
        assert stats["actions_processed"] == 0
        assert len(loop.safety_alerts) == 0

    def test_execution_error_handled(self):
        """Executor errors should be caught and returned as result."""
        def failing_executor(action):
            raise RuntimeError("execution failed")

        loop = _make_loop(executor=failing_executor)
        result = loop.step(AgentAction(action="fail"))
        # Action should still complete (error caught)
        assert "error" in result.execution_result


class TestSafetyBridgeWithHooks:
    """Tests for safety hooks integration."""

    def test_hook_blocks_dangerous_action(self):
        """Safety hook detecting keywords should block action."""
        hook_registry = SafetyHookRegistry()
        hook_registry.register(RuntimeSafetyHook(
            risk_id="test_dangerous",
            name="dangerous_hook",
            keywords=["delete all", "rm -rf"],
            severity="high",
        ))

        loop = SafetyBridgeLoop(
            constraints=[],
            agent_id="test",
            enable_safety_hooks=True,
            hook_registry=hook_registry,
        )
        result = loop.step(AgentAction(action="DELETE ALL records"))
        assert result.was_blocked

    def test_hook_passes_safe_action(self):
        """Safe actions should pass hook checks."""
        hook_registry = SafetyHookRegistry()
        hook_registry.register(RuntimeSafetyHook(
            risk_id="test_dangerous",
            name="dangerous_hook",
            keywords=["delete all"],
        ))

        loop = SafetyBridgeLoop(
            constraints=[],
            agent_id="test",
            enable_safety_hooks=True,
            hook_registry=hook_registry,
        )
        result = loop.step(AgentAction(action="read_records"))
        assert result.allowed

    def test_hook_alert_generated(self):
        """Triggered hook should generate a safety alert."""
        hook_registry = SafetyHookRegistry()
        hook_registry.register(RuntimeSafetyHook(
            risk_id="test_risk",
            name="test_hook",
            keywords=["banned_word"],
            severity="high",
        ))

        loop = SafetyBridgeLoop(
            constraints=[],
            agent_id="test",
            enable_safety_hooks=True,
            hook_registry=hook_registry,
        )
        loop.step(AgentAction(action="say banned_word"))
        assert len(loop.safety_alerts) == 1
        alert = loop.safety_alerts[0]
        assert alert.risk_id == "test_risk"
        assert "banned_word" in alert.details.get("matched_keywords", [])


class TestAgentAction:
    """Tests for AgentAction dataclass."""

    def test_basic_action(self):
        action = AgentAction(action="send_email", params={"to": "user@example.com"})
        assert action.action == "send_email"
        assert action.params["to"] == "user@example.com"

    def test_inter_agent_action(self):
        action = AgentAction(
            action="delegate",
            params={"task": "analyze"},
            agent_id="manager",
            source_agent_id="supervisor",
        )
        assert action.source_agent_id == "supervisor"
