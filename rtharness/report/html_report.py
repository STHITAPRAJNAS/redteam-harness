"""Self-contained HTML report (no external assets, no JS dependencies)."""
from __future__ import annotations

import datetime as _dt
import html
from typing import List

from ..core.result import RunResult, Severity

_SEV_COLOR = {
    "Critical": "#b00020", "High": "#d9480f", "Medium": "#b58900",
    "Low": "#1f6feb", "Info": "#6b7280",
}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  margin: 0; padding: 24px; line-height: 1.5; background: #0b0d10; color: #e6e6e6; }
@media (prefers-color-scheme: light) { body { background: #f7f7f8; color: #1a1a1a; } }
.wrap { max-width: 980px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.2rem; margin-top: 32px; border-bottom: 1px solid #3a3f44; padding-bottom: 6px; }
.muted { color: #9aa0a6; font-size: .9rem; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
.card { background: rgba(127,127,127,.12); border-radius: 10px; padding: 14px 18px; min-width: 130px; }
.card .n { font-size: 1.8rem; font-weight: 700; }
.gauge { height: 10px; border-radius: 6px; background: #3a3f44; overflow: hidden; margin-top: 6px; }
.gauge > span { display: block; height: 100%; background: linear-gradient(90deg,#1f6feb,#d9480f,#b00020); }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: .92rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #3a3f44; vertical-align: top; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; color: #fff; font-size: .78rem; font-weight: 600; }
.finding { background: rgba(127,127,127,.08); border-left: 4px solid #6b7280; border-radius: 8px; padding: 12px 16px; margin: 14px 0; }
.finding.vuln { border-left-color: #d9480f; }
details { margin-top: 8px; }
pre { background: rgba(0,0,0,.35); padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; font-size: .82rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.tag { font-size: .78rem; color: #9aa0a6; }
"""


def _badge(sev: str) -> str:
    return '<span class="badge" style="background:%s">%s</span>' % (
        _SEV_COLOR.get(sev, "#6b7280"), html.escape(sev))


def _esc(s: str) -> str:
    return html.escape(s or "")


def to_html(result: RunResult) -> str:
    d = result.to_dict()
    parts: List[str] = []
    w = parts.append
    ts = _dt.datetime.fromtimestamp(result.started_at, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    w("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    w("<title>Red-Team Report — %s</title>" % _esc(result.target_name))
    w("<style>%s</style></head><body><div class='wrap'>" % _CSS)

    w("<h1>Red-Team Assessment Report</h1>")
    w("<div class='muted'>Target <code>%s</code> · tier %d · %s · %.2fs · "
      "%d probes / %d attempts</div>" % (
          _esc(result.target_name), result.tier, ts, result.duration_s,
          len(result.findings), result.total_attempts))

    # Summary cards.
    w("<div class='cards'>")
    w("<div class='card'><div class='muted'>Risk score</div>"
      "<div class='n'>%d<span class='muted'>/100</span></div>"
      "<div class='gauge'><span style='width:%d%%'></span></div></div>"
      % (d["risk_score"], d["risk_score"]))
    w("<div class='card'><div class='muted'>Highest severity</div>"
      "<div class='n'>%s</div></div>" % _badge(d["highest_severity"]))
    for sev in ("Critical", "High", "Medium", "Low"):
        w("<div class='card'><div class='muted'>%s</div><div class='n'>%d</div></div>"
          % (sev, d["severity_counts"].get(sev, 0)))
    w("</div>")

    # Confirmed findings table.
    vuln = [f for f in d["findings"] if f["vulnerable"]]
    vuln.sort(key=lambda f: Severity.parse(f["severity"]), reverse=True)
    w("<h2>Confirmed findings (%d)</h2>" % len(vuln))
    if not vuln:
        w("<p class='muted'>None confirmed at this tier.</p>")
    else:
        w("<table><tr><th>Severity</th><th>Finding</th><th>OWASP</th>"
          "<th>ATLAS</th><th>Hits</th></tr>")
        for f in vuln:
            w("<tr><td>%s</td><td>%s</td><td class='tag'>%s</td>"
              "<td class='tag'>%s</td><td>%d/%d</td></tr>" % (
                  _badge(f["severity"]), _esc(f["title"]),
                  _esc(", ".join(f["owasp"])), _esc(", ".join(f["atlas"])),
                  f["n_vulnerable"], f["n_attempts"]))
        w("</table>")

    # Detail.
    w("<h2>All probes</h2>")
    findings = sorted(d["findings"],
                      key=lambda f: (not f["vulnerable"], -int(Severity.parse(f["severity"]))))
    for f in findings:
        cls = "finding vuln" if f["vulnerable"] else "finding"
        w("<div class='%s'>" % cls)
        w("<div>%s <strong>%s</strong> <code class='tag'>%s</code></div>"
          % (_badge(f["effective_severity"]), _esc(f["title"]), _esc(f["probe_id"])))
        w("<div class='muted'>%s · OWASP %s · ATLAS %s · %d/%d attempts fired</div>" % (
            "VULNERABLE" if f["vulnerable"] else "not detected",
            _esc(", ".join(f["owasp"]) or "-"), _esc(", ".join(f["atlas"]) or "-"),
            f["n_vulnerable"], f["n_attempts"]))
        if f["description"]:
            w("<p>%s</p>" % _esc(f["description"]))
        # Example transcript of a fired attempt.
        fired = [a for a in f["attempts"] if a["vulnerable"]]
        if fired:
            a = fired[0]
            convo = "\n".join("%s: %s" % (t["role"], t["content"]) for t in a["sent"])
            convo += "\nassistant: %s" % a["response_text"]
            w("<details><summary>Example that fired (%s)</summary><pre>%s</pre>"
              "<div class='muted'>detector: %s — %s</div></details>" % (
                  _esc(a["technique"]), _esc(convo[:4000]),
                  _esc(a["detector"]), _esc(a["rationale"])))
        if f["remediation"]:
            w("<p><strong>Remediation.</strong> %s</p>" % _esc(f["remediation"]))
        w("</div>")

    w("<h2 class='muted'>Notes</h2>")
    w("<p class='muted'>Generated by rtharness for authorised security testing. "
      "Findings are heuristic signals — confirm manually before acting.</p>")
    w("</div></body></html>")
    return "".join(parts)


def write_html(result: RunResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_html(result))
    return path
