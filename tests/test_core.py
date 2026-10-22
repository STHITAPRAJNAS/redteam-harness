import unittest

from rtharness.core.tier import Tier
from rtharness.core.target import Turn
from rtharness.core.result import Severity, Attempt, Finding, RunResult
from rtharness.targets import CallableTarget


class TestTier(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(Tier.parse("basic"), Tier.BASIC)
        self.assertEqual(Tier.parse(3), Tier.ADVANCED)
        self.assertEqual(Tier.parse("MAX"), Tier.ADAPTIVE)
        with self.assertRaises(ValueError):
            Tier.parse("nope")

    def test_order(self):
        self.assertTrue(Tier.ADAPTIVE > Tier.BASIC)


class TestResultModel(unittest.TestCase):
    def _finding(self, sev, vuln):
        a = Attempt("p", 1, "direct", [{"role": "user", "content": "x"}],
                    "resp", vuln, "det", 1.0)
        return Finding("p", "t", sev, ["LLM01:2025"], ["AML.T0051"], attempts=[a])

    def test_severity_parse(self):
        self.assertEqual(Severity.parse("high"), Severity.HIGH)

    def test_risk_and_counts(self):
        r = RunResult("t", 1)
        r.findings = [self._finding(Severity.CRITICAL, True),
                      self._finding(Severity.LOW, True),
                      self._finding(Severity.HIGH, False)]
        self.assertEqual(r.severity_counts()["Critical"], 1)
        self.assertEqual(r.severity_counts()["High"], 0)  # not vulnerable
        self.assertEqual(r.highest_severity(), Severity.CRITICAL)
        self.assertTrue(0 < r.risk_score() <= 100)
        self.assertEqual(len(r.vulnerable_findings), 2)
        d = r.to_dict()
        self.assertIn("risk_score", d)
        self.assertEqual(d["findings"][0]["owasp"], ["LLM01:2025"])


class TestCallableTargetAndSession(unittest.TestCase):
    def test_multiturn_session_history(self):
        seen = {}

        def agent(messages):
            seen["n"] = len(messages)
            return "turn %d" % len(messages)

        t = CallableTarget(agent)
        s = t.new_session()
        s.send("hi")
        self.assertEqual(seen["n"], 1)
        s.send("again")
        # Second send includes prior user+assistant turns: 3 messages.
        self.assertEqual(seen["n"], 3)
        self.assertEqual(len(s.responses), 2)

    def test_dict_return_with_tool_calls(self):
        t = CallableTarget(lambda m: {"text": "ok", "tool_calls": [{"name": "foo"}]})
        resp = t.ask("x")
        self.assertEqual(resp.text, "ok")
        self.assertEqual(resp.tool_calls[0]["name"], "foo")

    def test_error_capture(self):
        def boom(messages):
            raise RuntimeError("nope")
        resp = CallableTarget(boom).ask("x")
        self.assertFalse(resp.ok)
        self.assertIn("nope", resp.error)


if __name__ == "__main__":
    unittest.main()
