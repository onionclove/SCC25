# filepath: d:\SCC_25\SCC25\mock_wazuh_api.py
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/alerts", methods=["GET"])
def get_alerts():
    sample_alerts = [
        {
            "timestamp": "2025-09-08T10:00:00Z",
            "rule": {"level": 3, "description": "User login from unusual IP"},
            "data": {"srcip": "8.8.8.8"}
        },
        {
            "timestamp": "2025-09-08T11:00:00Z",
            "rule": {"level": 12, "description": "Multiple failed SSH logins"},
            "data": {"srcip": "1.1.1.1"}
        }
    ]
    return jsonify({"data": sample_alerts})

if __name__ == "__main__":
    app.run(port=55000)