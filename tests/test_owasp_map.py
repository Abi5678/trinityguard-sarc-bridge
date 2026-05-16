"""Tests for OWASP mapping module."""

import pytest

from trinityguard_sarc_bridge.owasp_map import OWASPMap, owasp_map


class TestOWASPMap:
    """Tests for OWASP ASI mapping."""

    def test_singleton_exists(self):
        assert owasp_map is not None

    def test_all_10_risks(self):
        assert len(owasp_map.all_risks()) == 10

    def test_risk_ids_sequential(self):
        risks = owasp_map.all_risks()
        ids = [r.id for r in risks]
        expected = [f"ASI-{i:02d}" for i in range(1, 11)]
        assert sorted(ids) == expected

    def test_each_risk_has_name(self):
        for risk in owasp_map.all_risks():
            assert risk.name, f"{risk.id} has no name"

    def test_each_risk_has_description(self):
        for risk in owasp_map.all_risks():
            assert risk.description, f"{risk.id} has no description"

    def test_each_risk_has_tg_coverage(self):
        for risk in owasp_map.all_risks():
            assert len(risk.trinityguard_coverage) > 0, (
                f"{risk.id} ({risk.name}) has no TrinityGuard coverage"
            )

    def test_each_risk_has_sarc_guidance(self):
        for risk in owasp_map.all_risks():
            assert risk.sarc_enforcement_guidance, (
                f"{risk.id} ({risk.name}) has no SARC guidance"
            )

    def test_get_valid(self):
        risk = owasp_map.get("ASI-01")
        assert risk is not None
        assert "Indirect" in risk.name

    def test_get_invalid(self):
        assert owasp_map.get("ASI-99") is None

    def test_coverage_matrix_keys(self):
        matrix = owasp_map.coverage_matrix()
        for i in range(1, 11):
            assert f"ASI-{i:02d}" in matrix

    def test_coverage_matrix_has_tg_ids(self):
        matrix = owasp_map.coverage_matrix()
        for risk_id, info in matrix.items():
            assert isinstance(info["trinityguard_coverage"], list)
            assert info["coverage_count"] > 0

    def test_risks_covering(self):
        covering = owasp_map.risks_covering("jailbreak")
        assert "ASI-01" in covering

    def test_total_coverage(self):
        stats = owasp_map.total_coverage()
        assert stats["total_owasp_risks"] == 10
        assert stats["fully_covered"] == 10
        assert stats["coverage_entries"] > 10

    def test_no_duplicate_tg_coverage(self):
        """Each TG risk should map to unique OWASP coverage entries."""
        matrix = owasp_map.coverage_matrix()
        for risk_id, info in matrix.items():
            coverage = info["trinityguard_coverage"]
            assert len(coverage) == len(set(coverage)), (
                f"{risk_id} has duplicate TG coverage entries"
            )
