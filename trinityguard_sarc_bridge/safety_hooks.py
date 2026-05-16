"""
Runtime Safety Hooks — TrinityGuard-Inspired Lightweight Monitors.

These are SARC-integrated safety checks inspired by TrinityGuard's
monitor agents. They perform lightweight keyword/pattern detection
at SARC's enforcement sites, providing an immediate safety signal
without requiring LLM-based judges.

For production use, these hooks complement (not replace) TrinityGuard's
full LLM-powered monitoring. They provide fast, deterministic first-pass
filtering; TrinityGuard's monitors handle nuanced detection.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class HookSeverity(str, Enum):
    """Severity of a safety hook match."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SafetyHookResult:
    """Result from a single safety hook check."""
    hook_name: str
    risk_id: str
    triggered: bool
    severity: HookSeverity = HookSeverity.LOW
    matched_keywords: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hook_name": self.hook_name,
            "risk_id": self.risk_id,
            "triggered": self.triggered,
            "severity": self.severity.value if hasattr(self.severity, "value") else self.severity,
            "matched_keywords": self.matched_keywords,
            "matched_patterns": self.matched_patterns,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class RuntimeSafetyHook:
    """A lightweight runtime safety check inspired by TrinityGuard monitors.

    Hooks perform deterministic pattern matching on action parameters,
    providing immediate safety signals at SARC enforcement sites.

    TrinityGuard's monitors use LLM-based analysis for nuanced detection;
    these hooks complement that with fast, deterministic first-pass filtering.
    """

    def __init__(
        self,
        risk_id: str,
        name: str,
        keywords: list[str] | None = None,
        patterns: list[str] | None = None,
        severity: HookSeverity = HookSeverity.MEDIUM,
        check_fn: Callable[[dict[str, Any]], SafetyHookResult] | None = None,
        target_fields: list[str] | None = None,
    ) -> None:
        self.risk_id = risk_id
        self.name = name
        self.keywords = [kw.lower() for kw in (keywords or [])]
        self.patterns = [re.compile(p, re.IGNORECASE) for p in (patterns or [])]
        self.severity = severity
        self.check_fn = check_fn
        self.target_fields = target_fields or ["action", "_action"]
        self._trigger_count: int = 0

    def check(self, context: dict[str, Any]) -> SafetyHookResult:
        """Run the safety hook against the given context.

        Checks both keyword matching and regex patterns against
        the target fields in the context.
        """
        if self.check_fn:
            return self.check_fn(context)

        matched_keywords: list[str] = []
        matched_patterns: list[str] = []

        # Extract text from context fields
        text_parts: list[str] = []
        for field_name in self.target_fields:
            value = context.get(field_name)
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, dict):
                text_parts.extend(str(v) for v in value.values() if isinstance(v, str))

        combined_text = " ".join(text_parts).lower()

        # Keyword matching
        for kw in self.keywords:
            if kw in combined_text:
                matched_keywords.append(kw)

        # Regex pattern matching
        for pattern in self.patterns:
            if pattern.search(combined_text):
                matched_patterns.append(pattern.pattern)

        triggered = bool(matched_keywords or matched_patterns)
        if triggered:
            self._trigger_count += 1

        return SafetyHookResult(
            hook_name=self.name,
            risk_id=self.risk_id,
            triggered=triggered,
            severity=self.severity if triggered else HookSeverity.LOW,
            matched_keywords=matched_keywords,
            matched_patterns=matched_patterns,
            details={
                "text_length": len(combined_text),
                "trigger_count": self._trigger_count,
            },
        )

    @property
    def trigger_count(self) -> int:
        return self._trigger_count

    def reset(self) -> None:
        self._trigger_count = 0


class SafetyHookRegistry:
    """Registry for runtime safety hooks.

    Hooks are organized by risk_id and can be checked individually
    or as a batch.
    """

    def __init__(self) -> None:
        self._hooks: dict[str, RuntimeSafetyHook] = {}

    def register(self, hook: RuntimeSafetyHook) -> None:
        """Register a safety hook."""
        self._hooks[hook.risk_id] = hook

    def unregister(self, risk_id: str) -> None:
        """Unregister a safety hook by risk_id."""
        self._hooks.pop(risk_id, None)

    def get(self, risk_id: str) -> RuntimeSafetyHook | None:
        """Get a hook by risk_id."""
        return self._hooks.get(risk_id)

    def all_hooks(self) -> list[RuntimeSafetyHook]:
        """Return all registered hooks."""
        return list(self._hooks.values())

    def check_all(self, context: dict[str, Any]) -> list[SafetyHookResult]:
        """Run all registered hooks against context."""
        return [hook.check(context) for hook in self._hooks.values()]

    def check_triggered(self, context: dict[str, Any]) -> list[SafetyHookResult]:
        """Run all hooks and return only triggered results."""
        return [r for r in self.check_all(context) if r.triggered]

    @classmethod
    def from_risk_definitions(cls, risk_defs) -> SafetyHookRegistry:
        """Create a hook registry from TrinityGuard risk definitions.

        Only risks with enable_safety_hook=True and hook_keywords will
        have hooks created.
        """
        registry = cls()
        for risk in risk_defs:
            if risk.enable_safety_hook and risk.hook_keywords:
                severity_map = {"high": HookSeverity.HIGH, "medium": HookSeverity.MEDIUM, "low": HookSeverity.LOW}
                hook = RuntimeSafetyHook(
                    risk_id=risk.risk_id,
                    name=f"tg_{risk.risk_id}_hook",
                    keywords=risk.hook_keywords,
                    severity=severity_map.get(risk.severity, HookSeverity.MEDIUM),
                )
                registry.register(hook)
        return registry

    def summary(self) -> dict[str, Any]:
        """Summary of all registered hooks."""
        return {
            "total_hooks": len(self._hooks),
            "hooks": {
                risk_id: {
                    "name": hook.name,
                    "severity": hook.severity.value,
                    "keywords_count": len(hook.keywords),
                    "patterns_count": len(hook.patterns),
                    "trigger_count": hook.trigger_count,
                }
                for risk_id, hook in self._hooks.items()
            },
        }
