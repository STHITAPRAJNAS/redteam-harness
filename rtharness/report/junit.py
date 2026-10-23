"""JUnit XML report — for CI dashboards (Jenkins/GitLab/GitHub test summaries).

One <testcase> per probe: a confirmed vulnerability is a <failure>, a clean
probe passes, an errored probe is an <error>. classname carries the OWASP
mapping so results group sensibly.
"""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from ..core.result import RunResult


def to_junit(result: RunResult) -> str:
    cases = []
    failures = errors = 0
    for f in result.findings:
        classname = (", ".join(f.owasp) or "rtharness") + " :: " + result.target_name
        name = "%s (%s)" % (f.probe_id, f.title)
        attr = "classname=%s name=%s" % (quoteattr(classname), quoteattr(name))
        errored = all(a.error for a in f.attempts) and f.attempts
        if f.vulnerable:
            failures += 1
            fired = next((a for a in f.attempts if a.vulnerable), None)
            msg = "%s severity=%s %d/%d attempts" % (
                f.probe_id, f.severity.label, f.n_vulnerable, f.n_attempts)
            detail = escape((fired.rationale if fired else "") + "\n\n" +
                            (fired.response_text[:1000] if fired else ""))
            cases.append("    <testcase %s>\n      <failure message=%s>%s</failure>\n    </testcase>"
                         % (attr, quoteattr(msg), detail))
        elif errored:
            errors += 1
            cases.append("    <testcase %s>\n      <error message=%s/>\n    </testcase>"
                         % (attr, quoteattr("probe errored (transport)")))
        else:
            cases.append("    <testcase %s/>" % attr)

    suite = (
        '<testsuite name="rtharness:%s" tests="%d" failures="%d" errors="%d" time="%.3f">'
        % (escape(result.target_name), len(result.findings), failures, errors,
           result.duration_s))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n  %s\n%s\n  </testsuite>\n</testsuites>\n'
            % (suite, "\n".join(cases)))


def write_junit(result: RunResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_junit(result))
    return path
