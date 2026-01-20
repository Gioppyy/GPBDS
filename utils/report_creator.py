from datetime import datetime
from pathlib import Path
import webbrowser

def generate_html_report(findings):
    if not findings:
        print("✔ No threats found")
        return

    template = Path("./utils/template.html").read_text(encoding="utf-8")

    blocks = []
    for f in findings:
        block = f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="path-container">
                    <div class="path">{f['path']}</div>
                </div>
                <div class="score-badge {f['severity']}">
                    Score: {f['score']} · {f['severity']}
                </div>
            </div>

            <div class="finding-content">
        """

        for m in f["matches"]:
            block += f"""
                <div class="match-item" style="border-left-color: var(--{m['severity'].lower()})">
                    <div class="match-header">
                        <span class="severity-dot {m['severity']}"></span>
                        <span class="match-check">{m['check']}</span>
                    </div>
                    <div class="snippet">
                        <pre>{m['snippet']}</pre>
                    </div>
                </div>
            """

        block += """
            </div>
        </div>
        """
        blocks.append(block)

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
        .replace("{{FINDINGS}}", "\n".join(blocks))

    reports = Path("reports")
    reports.mkdir(exist_ok=True)

    out = reports / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out.write_text(html, encoding="utf-8")

    webbrowser.open(out.resolve().as_uri())
