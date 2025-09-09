import json

def get_alerts():
    with open("sample_alerts.json") as f:
        return json.load(f)
