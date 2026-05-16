"""Tests for Runtime Safety Hooks."""

import pytest

from trinityguard_sarc_bridge.safety_hooks import (
    HookSeverity,
    RuntimeSafetyHook,
    SafetyHookRegistry,
    SafetyHookResult,
)
from trinityguard_sarc_bridge.risk_registry import TrinityGuardRiskRegistry


class TestRuntimeSafetyHook:
    """Tests for individual safety hooks."""

    def test_keyword_match(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["delete all", "rm -rf"],
        )
        result = hook.check({"action": "DELETE ALL records"})
        assert result.triggered
        assert "delete all" in result.matched_keywords

    def test_keyword_no_match(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["delete all"],
        )
        result = hook.check({"action": "read records"})
        assert not result.triggered

    def test_pattern_match(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            patterns=[r"\d{3}-\d{2}-\d{4}"],  # SSN pattern
            target_fields=["action", "params"],
        )
        result = hook.check({"action": "query", "params": {"query": "123-45-6789"}})
        assert result.triggered
        assert len(result.matched_patterns) == 1

    def test_case_insensitive_keywords(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["jailbreak"],
        )
        result = hook.check({"action": "JAILBREAK attempt"})
        assert result.triggered

    def test_multiple_keywords(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["dangerous", "unsafe", "harmful"],
        )
        result = hook.check({"action": "dangerous and unsafe action"})
        assert result.triggered
        assert len(result.matched_keywords) == 2

    def test_custom_check_fn(self):
        def checker(ctx):
            return SafetyHookResult(
                hook_name="custom",
                risk_id="test",
                triggered=True,
                severity=HookSeverity.CRITICAL,
                details={"reason": "custom check"},
            )

        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            check_fn=checker,
        )
        result = hook.check({})
        assert result.triggered
        assert result.details["reason"] == "custom check"

    def test_trigger_count(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["bad"],
        )
        hook.check({"action": "bad"})
        hook.check({"action": "bad"})
        hook.check({"action": "good"})
        assert hook.trigger_count == 2

    def test_reset(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["bad"],
        )
        hook.check({"action": "bad"})
        hook.reset()
        assert hook.trigger_count == 0

    def test_target_fields(self):
        """Hook should check only specified target fields."""
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["dangerous"],
            target_fields=["safe_field"],
        )
        result = hook.check({"safe_field": "safe", "action": "dangerous"})
        assert not result.triggered

    def test_to_dict(self):
        hook = RuntimeSafetyHook(
            risk_id="test",
            name="test_hook",
            keywords=["bad"],
        )
        result = hook.check({"action": "bad"})
        d = result.to_dict()
        assert d["triggered"] is True
        assert d["risk_id"] == "test"
        assert "timestamp" in d


class TestSafetyHookRegistry:
    """Tests for the hook registry."""

    def test_register_and_get(self):
        registry = SafetyHookRegistry()
        hook = RuntimeSafetyHook(risk_id="test", name="test", keywords=["bad"])
        registry.register(hook)
        assert registry.get("test") is hook

    def test_unregister(self):
        registry = SafetyHookRegistry()
        hook = RuntimeSafetyHook(risk_id="test", name="test", keywords=["bad"])
        registry.register(hook)
        registry.unregister("test")
        assert registry.get("test") is None

    def test_check_all(self):
        registry = SafetyHookRegistry()
        registry.register(RuntimeSafetyHook(risk_id="a", name="a", keywords=["alpha"]))
        registry.register(RuntimeSafetyHook(risk_id="b", name="b", keywords=["beta"]))

        results = registry.check_all({"action": "alpha and beta"})
        assert len(results) == 2

    def test_check_triggered_only(self):
        registry = SafetyHookRegistry()
        registry.register(RuntimeSafetyHook(risk_id="a", name="a", keywords=["alpha"]))
        registry.register(RuntimeSafetyHook(risk_id="b", name="b", keywords=["beta"]))

        results = registry.check_triggered({"action": "alpha only"})
        assert len(results) == 1
        assert results[0].risk_id == "a"

    def test_from_risk_definitions(self):
        """Should create hooks for risks with enabled hooks and keywords."""
        registry = TrinityGuardRiskRegistry()
        hook_registry = SafetyHookRegistry.from_risk_definitions(
            registry.risks_with_hooks()
        )
        assert len(hook_registry.all_hooks()) > 0

        # Jailbreak should have a hook
        jailbreak_hook = hook_registry.get("jailbreak")
        assert jailbreak_hook is not None
        assert len(jailbreak_hook.keywords) > 0

    def test_summary(self):
        registry = SafetyHookRegistry()
        registry.register(RuntimeSafetyHook(risk_id="a", name="a", keywords=["x"]))
        registry.register(RuntimeSafetyHook(risk_id="b", name="b", keywords=["y", "z"]))

        summary = registry.summary()
        assert summary["total_hooks"] == 2
        assert summary["hooks"]["a"]["keywords_count"] == 1
        assert summary["hooks"]["b"]["keywords_count"] == 2
