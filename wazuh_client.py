import requests

def get_alerts():
    try:
        response = requests.get("http://127.0.0.1:55000/alerts", timeout=10)
        response.raise_for_status()  # Raise an error for HTTP issues
        return response.json()["data"]
    except requests.RequestException as e:
        print(f"Error fetching alerts: {e}")
        return []
