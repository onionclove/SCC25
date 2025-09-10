def triage_summary(alert):
    # Use .get() to avoid KeyError
    agent = alert.get("agent", {}).get("name", "Unknown Agent")
    rule_desc = alert.get("rule", {}).get("description", "No description")
    src_ip = alert.get("data", {}).get("srcip", "N/A")

    return f"Alert from {agent}: {rule_desc}. Source IP: {src_ip}"
 