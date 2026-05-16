"""Tests for the TrinityGuard Risk Registry."""

import pytest

from trinityguard_sarc_bridge.risk_registry import (
    RiskLevel,
    TrinityGuardRiskRegistry,
    OWASPReference,
)
from trinityguard_sarc_bridge.owasp_map import owasp_map


class TestTrinityGuardRiskRegistry:
    """Tests for the risk registry."""

    def setup_method(self):
        self.registry = TrinityGuardRiskRegistry()

    def test_total_risk_count(self):
        """Registry should contain all 24 TrinityGuard risks (20 original + 4 OS-level)."""
        assert len(self.registry.all_risks()) == 24

    def test_l1_count(self):
        """L1 should have exactly 8 single-agent risks."""
        assert len(self.registry.by_level(RiskLevel.L1)) == 8

    def test_l2_count(self):
        """L2 should have exactly 6 inter-agent risks."""
        assert len(self.registry.by_level(RiskLevel.L2)) == 6

    def test_l3_count(self):
        """L3 should have exactly 6 system-level risks."""
        assert len(self.registry.by_level(RiskLevel.L3)) == 6

    def test_all_levels_sum_to_24(self):
        counts = self.registry.count_by_level()
        total = sum(counts.values())
        assert total == 24

    def test_all_risk_ids_unique(self):
        ids = [r.risk_id for r in self.registry.all_risks()]
        assert len(ids) == len(set(ids))

    def test_each_risk_has_owasp_refs(self):
        """Every risk should reference at least one OWASP risk."""
        for risk in self.registry.all_risks():
            assert len(risk.owasp_refs) >= 1, f"{risk.risk_id} has no OWASP refs"

    def test_hard_soft_distribution(self):
        """Should have both hard and soft constraints."""
        hard = self.registry.by_class("hard")
        soft = self.registry.by_class("soft")
        assert len(hard) > 0
        assert len(soft) > 0
        assert len(hard) + len(soft) == 24

    def test_risk_has_correct_level(self):
        """Risk levels should match their category."""
        l1_ids = {r.risk_id for r in self.registry.by_level(RiskLevel.L1)}
        l2_ids = {r.risk_id for r in self.registry.by_level(RiskLevel.L2)}
        l3_ids = {r.risk_id for r in self.registry.by_level(RiskLevel.L3)}

        # Known L1 risks
        assert "jailbreak" in l1_ids
        assert "prompt_injection" in l1_ids
        assert "hallucination" in l1_ids

        # Known L2 risks
        assert "message_tampering" in l2_ids
        assert "goal_drift" in l2_ids

        # Known L3 risks
        assert "cascading_failures" in l3_ids
        assert "rogue_agent" in l3_ids

    def test_lookup_by_id(self):
        """Should be able to look up risks by ID."""
        jailbreak = self.registry.get("jailbreak")
        assert jailbreak is not None
        assert jailbreak.name == "Jailbreak"
        assert jailbreak.level == RiskLevel.L1
        assert jailbreak.constraint_class == "hard"
        assert jailbreak.verification_point == "pre_action"
        assert jailbreak.response_protocol == "block"

    def test_lookup_nonexistent(self):
        """Looking up nonexistent risk returns None."""
        assert self.registry.get("nonexistent_risk") is None

    def test_to_sarc_constraint_kwargs(self):
        """Each risk should produce valid SARC constraint kwargs."""
        for risk in self.registry.all_risks():
            kwargs = risk.to_sarc_constraint_kwargs()
            assert "constraint_class" in kwargs
            assert "verification_point" in kwargs
            assert "response_protocol" in kwargs
            assert "tags" in kwargs
            assert any("trinityguard:" in t for t in kwargs["tags"])

    def test_owasp_coverage_all_10(self):
        """All 10 OWASP risks should have TrinityGuard coverage."""
        coverage = self.registry.owasp_coverage()
        for i in range(1, 11):
            owasp_id = f"ASI-{i:02d}"
            assert owasp_id in coverage, f"OWASP {owasp_id} has no TG coverage"

    def test_to_sarc_constraints_all_levels(self):
        """Compiling all levels should produce 24 constraints."""
        constraints = self.registry.to_sarc_constraints()
        assert len(constraints) == 24

    def test_to_sarc_constraints_filtered(self):
        """Filtering by level should produce correct count."""
        l1 = self.registry.to_sarc_constraints(levels=[RiskLevel.L1])
        l2 = self.registry.to_sarc_constraints(levels=[RiskLevel.L2])
        l3 = self.registry.to_sarc_constraints(levels=[RiskLevel.L3])
        assert len(l1) == 8
        assert len(l2) == 6
        assert len(l3) == 6

    def test_to_sarc_constraints_overrides(self):
        """Overrides should modify constraint properties."""
        constraints = self.registry.to_sarc_constraints(
            levels=[RiskLevel.L1],
            overrides={"hallucination": {"constraint_class": "hard"}},
        )
        hallucination = [c for c in constraints if "hallucination" in c.get("name", "")]
        assert len(hallucination) == 1
        # After override, hallucination should be hard
        from sarc import ConstraintClass
        assert hallucination[0]["constraint_class"] == ConstraintClass.HARD

    def test_verification_point_distribution(self):
        """All verification points should be used."""
        vp_set = {r.verification_point for r in self.registry.all_risks()}
        assert "pre_action" in vp_set
        assert "action_time" in vp_set
        assert "post_action" in vp_set
        assert "periodic" in vp_set

    def test_response_protocol_distribution(self):
        """Multiple response protocols should be used."""
        rp_set = {r.response_protocol for r in self.registry.all_risks()}
        assert "block" in rp_set
        assert "escalate" in rp_set
        assert "log_and_continue" in rp_set

    def test_risks_with_hooks(self):
        """Some risks should have safety hooks enabled."""
        hooked = self.registry.risks_with_hooks()
        assert len(hooked) > 0
        # Jailbreak should have hook keywords
        jailbreak = self.registry.get("jailbreak")
        assert jailbreak.enable_safety_hook is True
        assert len(jailbreak.hook_keywords) > 0


class TestOWASPMap:
    """Tests for OWASP mapping."""

    def test_all_10_risks_present(self):
        risks = owasp_map.all_risks()
        assert len(risks) == 10

    def test_lookup(self):
        risk = owasp_map.get("ASI-01")
        assert risk is not None
        assert risk.name == "Indirect Prompt Injection"

    def test_lookup_case_insensitive(self):
        risk = owasp_map.get("asi-01")
        assert risk is not None

    def test_coverage_matrix(self):
        matrix = owasp_map.coverage_matrix()
        assert len(matrix) == 10
        for risk_id in matrix:
            assert "name" in matrix[risk_id]
            assert "trinityguard_coverage" in matrix[risk_id]

    def test_risks_covering(self):
        """ASI-01 should be covered by jailbreak and prompt_injection."""
        covering = owasp_map.risks_covering("jailbreak")
        assert "ASI-01" in covering

    def test_total_coverage(self):
        stats = owasp_map.total_coverage()
        assert stats["total_owasp_risks"] == 10
        assert stats["fully_covered"] == 10
