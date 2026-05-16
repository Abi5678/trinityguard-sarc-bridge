"""Basic Usage — Quick-start example for TrinityGuard-SARC Safety Bridge."""

from trinityguard_sarc_bridge import (
    SafetyBridgeLoop,
    TrinityGuardRiskRegistry,
    RiskLevel,
    UnifiedSafetyReport,
)
from trinityguard_sarc_bridge.bridge import AgentAction


def main():
    # 1. Create the risk registry (all 20 TrinityGuard risks)
    registry = TrinityGuardRiskRegistry()
    print(f"Loaded {len(registry.all_risks())} risks")
    print(f"  L1 (Single-Agent):  {len(registry.by_level(RiskLevel.L1))}")
    print(f"  L2 (Inter-Agent):   {len(registry.by_level(RiskLevel.L2))}")
    print(f"  L3 (System-Level):  {len(registry.by_level(RiskLevel.L3))}")
    print()

    # 2. Compile risks into SARC constraints
    constraints = registry.to_sarc_constraints(
        levels=[RiskLevel.L1, RiskLevel.L2, RiskLevel.L3],
    )
    print(f"Compiled {len(constraints)} SARC constraints")
    print(f"  Hard: {sum(1 for c in constraints if str(c.get('constraint_class')) == 'ConstraintClass.HARD')}")
    print(f"  Soft: {sum(1 for c in constraints if str(c.get('constraint_class')) == 'ConstraintClass.SOFT')}")
    print()

    # 3. Create the safety bridge loop
    def my_executor(action: AgentAction):
        print(f"  → Executing: {action.action}({action.params})")
        return {"status": "success", "action": action.action}

    loop = SafetyBridgeLoop(
        constraints=constraints,
        agent_id="demo_agent",
        executor=my_executor,
        enable_safety_hooks=True,
    )

    # 4. Run safe actions
    print("Running safe actions:")
    safe_actions = [
        AgentAction(action="read_document", params={"doc_id": "123"}),
        AgentAction(action="summarize", params={"text": "Hello world"}),
    ]
    for action in safe_actions:
        result = loop.step(action)
        status = "✅ ALLOWED" if result.allowed else f"🚫 {result.decision.value.upper()}"
        print(f"  {status}: {action.action}")

    print()

    # 5. Run actions that trigger safety hooks
    print("Running actions with safety implications:")
    risky_actions = [
        AgentAction(action="DELETE ALL records", params={"target": "database"}),
        AgentAction(action="execute_code", params={"code": "import os; os.system('rm -rf /')"}),
    ]
    for action in risky_actions:
        result = loop.step(action)
        status = "✅ ALLOWED" if result.allowed else f"🚫 {result.decision.value.upper()}"
        print(f"  {status}: {action.action}")
        if not result.allowed:
            print(f"    Blocked by: {result.blocked_by}")

    print()

    # 6. Generate report
    print("Generating safety report...")
    report = UnifiedSafetyReport.from_loop(loop, agent_id="demo_agent")
    print(report.to_text())

    # Stats
    stats = loop.get_stats()
    print(f"\nBridge stats: {stats}")


if __name__ == "__main__":
    main()
