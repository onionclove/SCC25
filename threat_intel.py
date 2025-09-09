import requests

API_KEY = "82d918e2063762340b4c179d06131dc193f00337f71fc60113acbe3dbf25fb26ed99e166a357e0f0"  

def enrich_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        data = response.json()["data"]
        return {
            "abuseConfidenceScore": data["abuseConfidenceScore"],
            "countryCode": data.get("countryCode", "Unknown"),
            "totalReports": data.get("totalReports", 0)
        }
    except Exception as e:
        return {"error": str(e)}
