"""
Safety Bridge — Main Integration Layer.

SafetyBridgeLoop wraps an agent executor with TrinityGuard safety
constraints compiled into SARC's enforcement architecture. Every
agent action passes through 4 enforcement sites with OWASP-aligned
safety checks.

This is the primary integration point — the "bridge" between
TrinityGuard's risk taxonomy and SARC's governance-by-architecture.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .safety_hooks import SafetyHookRegistry, SafetyHookResult


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    """Enforcement decision for an agent action."""
    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    ESCALATE = "escalate"


@dataclass
class AgentAction:
    """An action to be executed by an agent."""
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    source_agent_id: str | None = None  # For inter-agent actions (L2)


@dataclass
class EnforcementResult:
    """Result of enforcement processing for a single action."""
    decision: Decision
    constraint_id: str
    constraint_name: str
    passed: bool
    metadata: dict[str, Any] = field(default_factory=dict)
    response_protocol: str = ""


@dataclass
class SafetyAlert:
    """A safety alert generated when a constraint is violated."""
    alert_id: str
    risk_id: str
    severity: str  # "high", "medium", "low"
    decision: Decision
    constraint_name: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)
    hook_result: SafetyHookResult | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "alert_id": self.alert_id,
            "risk_id": self.risk_id,
            "severity": self.severity,
            "decision": self.decision.value,
            "constraint_name": self.constraint_name,
            "action": self.action,
            "details": self.details,
            "timestamp": self.timestamp,
        }
        if self.hook_result:
            d["hook_result"] = self.hook_result.to_dict()
        return d


@dataclass
class GatedResult:
    """The result of running an action through the safety bridge."""
    decision: Decision
    action: AgentAction
    enforcement_results: list[EnforcementResult] = field(default_factory=list)
    safety_alerts: list[SafetyAlert] = field(default_factory=list)
    execution_result: Any = None
    blocked_by: str | None = None
    duration_ms: float = 0.0
    trace_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def was_blocked(self) -> bool:
        return self.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# Executor & Safety Bridge Loop
# ---------------------------------------------------------------------------

# Default executor: just returns the action as a dict
_DEFAULT_EXECUTOR: Callable[[AgentAction], Any] = lambda a: {"action": a.action, "params": a.params}


class SafetyBridgeLoop:
    """Main integration of TrinityGuard safety with SARC governance.

    Wraps an agent executor with:
      1. SARC-style enforcement sites (Pre-Action Gate, Action-Time Monitor,
         Post-Action Auditor, Escalation Router)
      2. TrinityGuard-inspired safety hooks (keyword/pattern detection)
      3. Full audit trail for compliance reporting

    Usage:
        loop = SafetyBridgeLoop(constraints=constraints, agent_id="my_agent")
        result = loop.step(AgentAction(action="send_email", params={...}))
        if result.was_blocked:
            print(f"Blocked by: {result.blocked_by}")
    """

    def __init__(
        self,
        constraints: list[dict[str, Any]],
        agent_id: str = "",
        executor: Callable[[AgentAction], Any] | None = None,
        enable_safety_hooks: bool = True,
        hook_registry: SafetyHookRegistry | None = None,
        escalation_handler: Callable[[SafetyAlert], Decision] | None = None,
        audit_log: list[dict[str, Any]] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self._executor = executor or _DEFAULT_EXECUTOR
        self._constraints = constraints
        self._enable_safety_hooks = enable_safety_hooks
        self._escalation_handler = escalation_handler
        self._audit_log = audit_log or []

        # Build constraint lookup
        self._constraint_map: dict[str, dict[str, Any]] = {}
        for c in constraints:
            name = c.get("name", "")
            if name:
                self._constraint_map[name] = c

        # Safety hooks
        if hook_registry:
            self._hook_registry = hook_registry
        elif enable_safety_hooks:
            from .safety_hooks import SafetyHookRegistry
            from .risk_registry import TrinityGuardRiskRegistry
            registry = TrinityGuardRiskRegistry()
            self._hook_registry = SafetyHookRegistry.from_risk_definitions(
                registry.risks_with_hooks()
            )
        else:
            from .safety_hooks import SafetyHookRegistry
            self._hook_registry = SafetyHookRegistry()

        # State
        self.safety_alerts: list[SafetyAlert] = []
        self._action_count: int = 0
        self._block_count: int = 0
        self._escalation_count: int = 0
        self._alert_counter: int = 0

        # Periodic check state
        self._last_periodic_check: float = time.time()
        self._periodic_interval_seconds: float = 300.0  # 5 minutes

    def step(self, action: AgentAction) -> GatedResult:
        """Process an agent action through all enforcement sites.

        Enforcement order:
          1. Pre-Action Gate — hard constraints with PRE_ACTION verification
          2. Runtime Safety Hooks — keyword/pattern detection
          3. (Execute action if allowed)
          4. Post-Action Auditor — constraints with POST_ACTION verification
          5. Escalation Router — handle ESCALATE decisions
        """
        start = time.time()
        action.agent_id = action.agent_id or self.agent_id
        self._action_count += 1

        enforcement_results: list[EnforcementResult] = []
        alerts: list[SafetyAlert] = []

        # 1. PRE_ACTION enforcement
        pre_results = self._enforce_site(
            action, verification_point="pre_action", context=self._make_context(action)
        )
        enforcement_results.extend(pre_results)

        # Check for blocks
        for r in pre_results:
            if not r.passed and r.response_protocol == "block":
                return self._build_blocked_result(
                    action, enforcement_results, alerts, r, start
                )

        # 2. Safety hooks
        if self._enable_safety_hooks:
            hook_alerts = self._run_safety_hooks(action)
            alerts.extend(hook_alerts)
            for alert in hook_alerts:
                if alert.decision == Decision.BLOCK:
                    return self._build_blocked_result(
                        action, enforcement_results, alerts, None, start,
                        blocked_by=alert.constraint_name,
                    )

        # Store hook alerts (even if no block)
        self.safety_alerts.extend(alerts)

        # 3. Execute action
        try:
            execution_result = self._executor(action)
        except Exception as e:
            execution_result = {"error": str(e), "error_type": type(e).__name__}

        # 4. POST_ACTION enforcement
        post_results = self._enforce_site(
            action,
            verification_point="post_action",
            context=self._make_context(action, execution_result=execution_result),
        )
        enforcement_results.extend(post_results)

        # Generate alerts for violations
        for r in post_results:
            if not r.passed:
                alert = self._make_alert(action, r)
                alerts.append(alert)

        # 5. ACTION_TIME enforcement (concurrent check)
        action_time_results = self._enforce_site(
            action, verification_point="action_time", context=self._make_context(action)
        )
        enforcement_results.extend(action_time_results)

        # 6. PERIODIC enforcement (if interval elapsed)
        if time.time() - self._last_periodic_check > self._periodic_interval_seconds:
            periodic_results = self._enforce_site(
                action, verification_point="periodic", context=self._make_context(action)
            )
            enforcement_results.extend(periodic_results)
            self._last_periodic_check = time.time()

        # Handle escalations
        final_decision = Decision.ALLOW
        for r in enforcement_results:
            if not r.passed and r.response_protocol == "escalate":
                final_decision = Decision.ESCALATE
                self._escalation_count += 1
            elif not r.passed and r.response_protocol == "throttle":
                final_decision = Decision.THROTTLE

        # Build result
        duration = (time.time() - start) * 1000
        result = GatedResult(
            decision=final_decision,
            action=action,
            enforcement_results=enforcement_results,
            safety_alerts=alerts,
            execution_result=execution_result,
            duration_ms=round(duration, 2),
        )

        # Audit log
        self._audit_log.append({
            "trace_id": result.trace_id,
            "action": action.action,
            "agent_id": self.agent_id,
            "decision": final_decision.value,
            "alerts": [a.to_dict() for a in alerts],
            "duration_ms": result.duration_ms,
            "timestamp": time.time(),
        })

        # Store alerts
        self.safety_alerts.extend(alerts)

        return result

    def _enforce_site(
        self,
        action: AgentAction,
        verification_point: str,
        context: dict[str, Any],
    ) -> list[EnforcementResult]:
        """Run constraints matching a verification point."""
        results = []
        for constraint in self._constraints:
            vp = constraint.get("verification_point")
            # Handle enum comparison
            vp_str = getattr(vp, "value", str(vp)) if vp else ""
            if vp_str != verification_point:
                continue

            name = constraint.get("name", "unknown")
            predicate = constraint.get("predicate")
            response_protocol = constraint.get("response_protocol")
            rp_str = getattr(response_protocol, "value", str(response_protocol)) if response_protocol else "log_and_continue"

            if predicate is None:
                results.append(EnforcementResult(
                    decision=Decision.ALLOW,
                    constraint_id=name,
                    constraint_name=name,
                    passed=True,
                    metadata={"reason": "no_predicate"},
                    response_protocol=rp_str,
                ))
                continue

            try:
                passed, metadata = predicate(context)
                decision = Decision.ALLOW if passed else self._protocol_to_decision(rp_str)
                results.append(EnforcementResult(
                    decision=decision,
                    constraint_id=name,
                    constraint_name=name,
                    passed=bool(passed),
                    metadata=metadata if isinstance(metadata, dict) else {"result": metadata},
                    response_protocol=rp_str,
                ))
            except Exception as e:
                results.append(EnforcementResult(
                    decision=Decision.ESCALATE,
                    constraint_id=name,
                    constraint_name=name,
                    passed=False,
                    metadata={"error": str(e)},
                    response_protocol="escalate",
                ))

        return results

    def _run_safety_hooks(self, action: AgentAction) -> list[SafetyAlert]:
        """Run safety hooks and generate alerts for triggers."""
        context = {
            "action": action.action,
            "_action": action.action,
            "params": action.params,
        }
        hook_results = self._hook_registry.check_triggered(context)
        alerts = []
        for hr in hook_results:
            self._alert_counter += 1
            # Map hook severity to decision
            from .safety_hooks import HookSeverity
            sev = hr.severity if isinstance(hr.severity, str) else hr.severity.value
            if sev in (HookSeverity.HIGH.value, HookSeverity.CRITICAL.value) or hr.severity in (HookSeverity.HIGH, HookSeverity.CRITICAL):
                decision = Decision.BLOCK
            elif sev == HookSeverity.MEDIUM.value or hr.severity == HookSeverity.MEDIUM:
                decision = Decision.THROTTLE
            else:
                decision = Decision.ALLOW

            alerts.append(SafetyAlert(
                alert_id=f"hook_{self._alert_counter}",
                risk_id=hr.risk_id,
                severity=sev,
                decision=decision,
                constraint_name=hr.hook_name,
                action=action.action,
                details=hr.to_dict(),
                hook_result=hr,
            ))
        return alerts

    def _make_context(
        self,
        action: AgentAction,
        execution_result: Any = None,
    ) -> dict[str, Any]:
        """Build the enforcement context dict."""
        ctx = {
            "action": action.action,
            "_action": action.action,
            "params": action.params,
            "agent_id": action.agent_id,
            "source_agent_id": action.source_agent_id,
            "action_count": self._action_count,
            "bridge": self,
        }
        if execution_result is not None:
            ctx["execution_result"] = execution_result
        return ctx

    def _build_blocked_result(
        self,
        action: AgentAction,
        enforcement_results: list[EnforcementResult],
        alerts: list[SafetyAlert],
        blocking_result: EnforcementResult | None,
        start: float,
        blocked_by: str | None = None,
    ) -> GatedResult:
        self._block_count += 1
        name = blocked_by or (blocking_result.constraint_name if blocking_result else "unknown")
        # Store alerts from blocked actions
        self.safety_alerts.extend(alerts)
        self._audit_log.append({
            "trace_id": "",
            "action": action.action,
            "agent_id": self.agent_id,
            "decision": "block",
            "alerts": [a.to_dict() for a in alerts],
            "duration_ms": round((time.time() - start) * 1000, 2),
            "timestamp": time.time(),
        })
        return GatedResult(
            decision=Decision.BLOCK,
            action=action,
            enforcement_results=enforcement_results,
            safety_alerts=alerts,
            blocked_by=name,
            duration_ms=round((time.time() - start) * 1000, 2),
        )

    def _make_alert(self, action: AgentAction, result: EnforcementResult) -> SafetyAlert:
        self._alert_counter += 1
        return SafetyAlert(
            alert_id=f"alert_{self._alert_counter}",
            risk_id=result.constraint_name.replace("tg_", ""),
            severity="high" if result.response_protocol == "escalate" else "medium",
            decision=result.decision,
            constraint_name=result.constraint_name,
            action=action.action,
            details={"metadata": result.metadata, "protocol": result.response_protocol},
        )

    @staticmethod
    def _protocol_to_decision(protocol: str) -> Decision:
        mapping = {
            "block": Decision.BLOCK,
            "throttle": Decision.THROTTLE,
            "escalate": Decision.ESCALATE,
            "log_and_continue": Decision.ALLOW,
            "rollback": Decision.ESCALATE,
        }
        return mapping.get(protocol, Decision.ALLOW)

    def get_stats(self) -> dict[str, Any]:
        """Get bridge runtime statistics."""
        return {
            "agent_id": self.agent_id,
            "actions_processed": self._action_count,
            "actions_blocked": self._block_count,
            "escalations": self._escalation_count,
            "total_alerts": len(self.safety_alerts),
            "constraints_loaded": len(self._constraints),
            "hooks_active": len(self._hook_registry.all_hooks()),
            "audit_entries": len(self._audit_log),
        }

    def get_audit_trail(self) -> list[dict[str, Any]]:
        """Return the full audit trail."""
        return list(self._audit_log)

    def reset_stats(self) -> None:
        """Reset runtime counters."""
        self._action_count = 0
        self._block_count = 0
        self._escalation_count = 0
        self.safety_alerts = []
        self._audit_log = []
