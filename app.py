#basic app to be updated

from flask import Flask, render_template
from collections import Counter
from wazuh_client import get_alerts
from playbook_engine import get_playbook
from ai_triage import triage_summary
from threat_intel import enrich_ip

app = Flask(__name__)

@app.route("/")
def index():
    alerts = get_alerts()

    # Calculate severity counts
    severity_counts = {
        "low": len([a for a in alerts if a["rule"]["level"] < 5]),
        "medium": len([a for a in alerts if 5 <= a["rule"]["level"] < 10]),
        "high": len([a for a in alerts if 10 <= a["rule"]["level"] < 15]),
        "critical": len([a for a in alerts if a["rule"]["level"] >= 15])
    }

    # Count source IPs
    src_ips = [a.get("data", {}).get("srcip") for a in alerts if "srcip" in a.get("data", {})]
    ip_counts = dict(Counter(src_ips))

    return render_template(
        "index.html",
        alerts=alerts,
        severity_counts=severity_counts,
        ip_counts=ip_counts
    )


@app.route("/alert/<int:alert_id>")
def alert(alert_id):
    alerts = get_alerts()
    alert = alerts[alert_id]
    summary = triage_summary(alert)
    playbook = get_playbook(alert["rule"]["description"])

    intel = None
    if "srcip" in alert.get("data", {}):
        intel = enrich_ip(alert["data"]["srcip"])

    return render_template("alert.html", alert=alert, summary=summary, playbook=playbook, intel=intel)

if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(debug=True)
