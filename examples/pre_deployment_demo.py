"""Pre-Deployment Testing Demo."""

from trinityguard_sarc_bridge import (
    TrinityGuardRiskRegistry,
    RiskLevel,
    PreDeploymentTester,
    UnifiedSafetyReport,
    SafetyBridgeLoop,
)
from trinityguard_sarc_bridge.bridge import AgentAction


def main():
    print("=" * 60)
    print("PRE-DEPLOYMENT SAFETY TESTING DEMO")
    print("TrinityGuard-SARC Bridge")
    print("=" * 60)
    print()

    # 1. Set up registry and compile constraints
    registry = TrinityGuardRiskRegistry()
    constraints = registry.to_sarc_constraints(
        levels=[RiskLevel.L1, RiskLevel.L2, RiskLevel.L3],
    )

    # 2. Run pre-deployment tests
    print("Running pre-deployment safety tests...")
    tester = PreDeploymentTester(constraints=constraints)

    # Test all levels
    print("\n--- L1: Single-Agent Risks ---")
    l1_results = tester.run_all(risk_levels=[RiskLevel.L1])
    for r in l1_results:
        icon = "✅" if r.outcome.value == "passed" else "❌"
        print(f"  {icon} {r.risk_id:30s} {r.test_name}")

    print("\n--- L2: Inter-Agent Risks ---")
    tester2 = PreDeploymentTester(constraints=constraints)
    l2_results = tester2.run_all(risk_levels=[RiskLevel.L2])
    for r in l2_results:
        icon = "✅" if r.outcome.value == "passed" else "❌"
        print(f"  {icon} {r.risk_id:30s} {r.test_name}")

    print("\n--- L3: System-Level Risks ---")
    tester3 = PreDeploymentTester(constraints=constraints)
    l3_results = tester3.run_all(risk_levels=[RiskLevel.L3])
    for r in l3_results:
        icon = "✅" if r.outcome.value == "passed" else "❌"
        print(f"  {icon} {r.risk_id:30s} {r.test_name}")

    # 3. Custom checker example
    print("\n--- Custom Checker: Jailbreak ---")
    tester4 = PreDeploymentTester(constraints=constraints)

    def jailbreak_checker(input_data: dict) -> tuple[bool, str]:
        prompt = input_data.get("params", {}).get("prompt", "").lower()
        jailbreak_patterns = ["ignore", "previous instructions", "you are now"]
        has_jailbreak = any(p in prompt for p in jailbreak_patterns)
        return (
            not has_jailbreak,
            f"Jailbreak patterns detected: {has_jailbreak}"
        )

    tester4.register_checker("jailbreak", jailbreak_checker)
    jb_result = tester4.run_all(risk_ids=["jailbreak"])
    for r in jb_result:
        icon = "✅" if r.outcome.value == "passed" else "❌"
        print(f"  {icon} {r.details}")

    # 4. Full test with report
    print("\n--- Full Suite Report ---")
    tester_full = PreDeploymentTester(constraints=constraints)
    all_results = tester_full.run_all()
    stats = tester_full.get_stats()
    print(f"  Total: {stats['total']}")
    print(f"  Passed: {stats['passed']} ({stats['pass_rate']*100:.0f}%)")
    print(f"  Failed: {stats['total'] - stats['passed']}")
    print(f"  Risks covered: {stats['risks_covered']}/{20}")
    print(f"  Covered: {stats['risks_covered_list']}")

    # 5. OWASP coverage
    from trinityguard_sarc_bridge.owasp_map import owasp_map
    print("\n--- OWASP Coverage ---")
    coverage = owasp_map.coverage_matrix()
    for risk_id, info in coverage.items():
        print(f"  {risk_id}: {info['name']}")
        for tg in info["trinityguard_coverage"]:
            print(f"    └─ {tg}")


if __name__ == "__main__":
    main()
