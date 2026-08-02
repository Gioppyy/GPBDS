from datetime import datetime
from pathlib import Path
import webbrowser

def _build_finding_blocks(findings: list) -> str:
    blocks = []

    for f in findings:
        path    = f["path"]
        sev     = f["severity"]
        score   = f["score"]
        matches = f["matches"]

        checks_str = " ".join(m["check"] for m in matches).lower()

        match_rows = []
        for m in matches:
            msev    = m["severity"]
            snippet = m.get("snippet", "")
            match_rows.append(f"""\
                <div class="match">
                    <div class="match-dot {msev}"></div>
                    <div class="match-check-name">{m['check']}</div>
                    <div class="match-snippet">{snippet}</div>
                </div>""")

        matches_html = "\n".join(match_rows)
        n_matches    = len(matches)

        blocks.append(f"""\
<div class="finding" data-sev="{sev}" data-path="{path.lower()}" data-checks="{checks_str}">
    <div class="finding-head">
        <span class="sev-tag {sev}">{sev}</span>
        <span class="score-chip">s:{score}</span>
        <span class="finding-path" title="{path}">{path}</span>
        <span class="match-count">{n_matches} match{"es" if n_matches != 1 else ""}</span>
        <span class="chevron">▶</span>
    </div>
    <div class="finding-body">
{matches_html}
    </div>
</div>""")

    return "\n".join(blocks)

def generate_html_report(findings):
    if not findings:
        print("✔ No threats found")
        return

    template = Path("./utils/template.html").read_text(encoding="utf-8")

    critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
    medium_count = sum(1 for f in findings if f['severity'] == 'MEDIUM')
    low_count = sum(1 for f in findings if f['severity'] == 'LOW')

    risk_score = sum(f['score'] for f in findings) / len(findings) if findings else 0
    risk_percentage = min(100, risk_score)

    html = template \
        .replace("{{TITLE}}", "Lua Backdoor Scan Report") \
        .replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")) \
        .replace("{{TOTAL}}", str(len(findings))) \
        .replace("{{FILE_COUNT}}", str(len(findings))) \
        .replace("{{CRITICAL_COUNT}}", str(critical_count)) \
        .replace("{{HIGH_COUNT}}", str(high_count)) \
        .replace("{{MEDIUM_COUNT}}", str(medium_count)) \
        .replace("{{LOW_COUNT}}", str(low_count)) \
        .replace("{{RISK_SCORE}}", f"{risk_score:.1f}") \
        .replace("{{RISK_PERCENTAGE}}", str(risk_percentage)) \
        .replace("{{VERSION}}", "1.0.0") \
        .replace("{{DURATION}}", "N/A") \
        .replace("{{TIMESTAMP}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")) \
        .replace("{{FINDINGS}}", _build_finding_blocks(findings))

    reports = Path("reports")
    reports.mkdir(exist_ok=True)

    out = reports / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out.write_text(html, encoding="utf-8")

    webbrowser.open(out.resolve().as_uri())
