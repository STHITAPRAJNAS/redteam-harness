import unittest

import rtharness.probes  # noqa: F401  registers probes
from rtharness.core import registry
from rtharness.core.tier import Tier
from rtharness.core.runner import Runner
from examples.mock_agent import (
    build_callable_target, build_secure_target, DEFAULT_PROFILE,
)


class TestRegistry(unittest.TestCase):
    def test_tiering(self):
        basic = registry.select(Tier.BASIC)
        adaptive = registry.select(Tier.ADAPTIVE)
        self.assertTrue(len(adaptive) >= len(basic) > 0)
        # Indirect injection is intermediate+, absent at basic.
        ids_basic = {p.id for p in basic}
        self.assertNotIn("prompt_injection.indirect", ids_basic)
        self.assertIn("prompt_injection.direct", ids_basic)

    def test_include_exclude(self):
        only = registry.select(Tier.ADAPTIVE, include=["prompt_injection"])
        self.assertTrue(all(p.id.startswith("prompt_injection") for p in only))
        no_a2a = registry.select(Tier.ADAPTIVE, exclude=["a2a"])
        self.assertTrue(all(not p.id.startswith("a2a") for p in no_a2a))

    def test_tag_filter(self):
        exfil = registry.select(Tier.ADAPTIVE, tags=["exfil"])
        self.assertTrue(all("exfil" in p.tags for p in exfil))
        self.assertTrue(len(exfil) >= 1)


class TestAgainstVulnerableMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = build_callable_target()
        probes = registry.select(Tier.ADVANCED, profile=dict(DEFAULT_PROFILE))
        cls.result = Runner(target, tier=Tier.ADVANCED).run(probes)
        cls.fired = {f.probe_id for f in cls.result.vulnerable_findings}

    def test_core_vulns_detected(self):
        for pid in ("prompt_injection.direct", "disclosure.system_prompt",
                    "jailbreak.refusal_suppression", "exfil.markdown_beacon",
                    "agency.gated_tool"):
            self.assertIn(pid, self.fired, "expected %s to fire on mock" % pid)

    def test_risk_score_nonzero(self):
        self.assertGreater(self.result.risk_score(), 0)
        self.assertGreaterEqual(len(self.result.vulnerable_findings), 5)

    def test_report_dict_roundtrip(self):
        d = self.result.to_dict()
        self.assertEqual(d["target"], "mock-vulnerable-agent")
        self.assertIn("findings", d)


class TestAgainstSecureMock(unittest.TestCase):
    def test_secure_agent_has_fewer_findings(self):
        target = build_secure_target()
        probes = registry.select(Tier.ADVANCED, profile=dict(DEFAULT_PROFILE))
        result = Runner(target, tier=Tier.ADVANCED).run(probes)
        # The secure agent refuses; chat-based content probes should not fire.
        chat_fired = [f for f in result.vulnerable_findings
                      if not f.probe_id.startswith("a2a")]
        self.assertEqual(chat_fired, [], "secure agent should not trip content probes")


if __name__ == "__main__":
    unittest.main()
