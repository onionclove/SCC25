#final
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
import json
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import uuid
import requests
from dotenv import load_dotenv


# Optional Gemini import (installed via requirements)
try:
    import google.generativeai as genai
except Exception:
    genai = None

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global storage for alerts (in production, use a database)
alerts_data = []

# VirusTotal API configuration
VT_API_KEY = os.getenv('virustotal_api')
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
VT_HEADERS = {'x-apikey': VT_API_KEY} if VT_API_KEY else {}

# Cache for VirusTotal results to avoid repeated API calls
vt_cache = {}

# Gemini configuration
GEMINI_API_KEY = os.getenv('gemini_api')
GEMINI_MODEL_NAME = os.getenv('gemini_model', 'gemini-1.5-flash')

def init_gemini_client():
    """Configure the Gemini client if available and API key is set."""
    if not genai or not GEMINI_API_KEY:
        return None
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        return genai.GenerativeModel(GEMINI_MODEL_NAME)
    except Exception as e:
        print(f"Error initializing Gemini client: {e}")
        return None

def build_playbook_prompt(alerts_subset):
    """Create a structured prompt for Gemini to generate a DUAL-FORMAT incident response output.
    
    Generates a human-readable guide for SMEs and a technical JSON playbook for IT.
    The model will output both a clear Markdown document and a structured JSON playbook.
    """
    sample = {
        "context": "You are a Senior Cybersecurity Incident Commander. You must analyze the provided Wazuh alerts and generate TWO SEPARATE, DISTINCT outputs. Your first priority is a clear, calming guide for a non-technical business owner. Your second output is a technical playbook for an IT team. YOU MUST FOLLOW THE OUTPUT FORMAT EXACTLY.",
        "output_format": {
            "human_guide_markdown": "# Incident Response Guide: [Title]\n\n## 🚨 What's Happening?\n* **Alert Severity:** [Level]\n* **In Simple Terms:** [Plain English explanation]\n\n## 🤔 Why Should You Care?\n* **What This Protects:** [Business impact explanation]\n\n## 📋 Your Immediate Action Plan\n1. **Step 1: [Action]**\n   * **What to do:** [Instruction]\n   * **Why & What it protects:** [Rationale for peace of mind]\n2. **Step 2: [Action]**\n   * **What to do:** [Instruction]\n   * **Why & What it protects:** [Rationale]\n\n## 🔧 For Your IT Pro (What We Found)\n* **Technical Summary:** [Brief technical details from alert data]\n* **Key Evidence:** [IPs, Users, Timestamps from alert]",
            "technical_playbook_json": {
                "title": "string",
                "summary": ["bullet points"],
                "severity": "Low|Medium|High|Critical",
                "assumptions": ["short bullets"],
                "prerequisites": ["tools, accesses, data needed"],
                "playbook_steps": [
                    {"id": 1, "name": "Step name", "owner": "SOC|IR|IT", "goal": "what it achieves", "commands": ["example commands"], "evidence_to_collect": ["artifacts"], "success_criteria": ["verifications"], "rollback": ["if needed"], "estimated_time_min": 5}
                ],
                "containment_actions": ["bullets"],
                "eradication_actions": ["bullets"],
                "recovery_actions": ["bullets"],
                "post_incident": ["lessons learned, tuning"]
            }
        }
    }
    return (
        "**CRITICAL INSTRUCTION: YOU MUST GENERATE TWO SEPARATE OUTPUTS. DO NOT MIX THEM. YOUR RESPONSE MUST CONTAIN THE TWO SECTIONS DEMARCATED BY '---BEGIN HUMAN GUIDE---' AND '---BEGIN TECHNICAL PLAYBOOK---'.**\n"
        "\n"
        "**THINKING PROCESS:**\n"
        "1.  First, analyze the Wazuh alerts to understand the technical severity and root cause.\n"
        "2.  Second, translate this into a simple, actionable plan for a non-technical business owner. Focus on 'what to do' and 'why'.\n"
        "3.  Third, create a detailed technical playbook for an IT team based on the same analysis.\n"
        "4.  Finally, output both results in the required formats.\n"
        "\n"
        "**HUMAN GUIDE (For SME):**\n"
        "- **Tone:** Empathetic, reassuring, and directive. Avoid fear-mongering.\n"
        "- **Language:** ZERO jargon. Use simple analogies (e.g., 'This is like a burglar checking your door locks').\n"
        "- **Content:** Provide a numbered, step-by-step action plan. For each step, include:\n"
        "    - **What to do:** A clear, imperative instruction.\n"
        "    - **Why & What it protects:** A one-sentence plain-English rationale (e.g., 'This stops the infection from spreading to other computers and protects your customer data.').\n"
        "- **Output Format:** Write this guide in Markdown, following the structure below.\n"
        "\n"
        "**TECHNICAL PLAYBOOK (For IT):**\n"
        "- **Precision:** Be technically specific. Use data from the alerts: `rule.description`, `rule.level`, `rule.groups`, `srcip`, `user`.\n"
        "- **Commands:** Include concrete OS commands (Linux/Windows) for investigation and remediation.\n"
        "- **Output Format:** Output a JSON object that strictly follows the schema below.\n"
        "\n"
        "**YOU MUST NOT OUTPUT A SINGLE BLOCK OF TEXT. YOU MUST USE THE FOLLOWING FORMAT:**\n"
        "\n"
        "---BEGIN HUMAN GUIDE---\n"
        "# Incident Response Guide: [Clear Title Based on the Primary Threat]\n\n... [Your complete Markdown guide here] ...\n"
        "---END HUMAN GUIDE---\n"
        "\n"
        "---BEGIN TECHNICAL PLAYBOOK---\n"
        "{\n  \"title\": \"...\",\n  \"summary\": [\"...\"],\n  ... [Your complete JSON playbook here] ...\n}\n"
        "---END TECHNICAL PLAYBOOK---\n"
        "\n"
        "**ALERTS TO ANALYZE:**\n"
        f"{json.dumps(alerts_subset, indent=2)}"
    )

def generate_playbook_from_alerts(all_alerts):
    """Use Gemini to generate a playbook from current alerts."""
    model = init_gemini_client()
    if not model:
        return {"error": "Gemini not configured. Ensure google-generativeai is installed and gemini_api is set in .env"}
    if not all_alerts:
        return {"error": "No alerts loaded"}

    # Take top N by rule level for stronger signal
    try:
        sorted_alerts = sorted(all_alerts, key=lambda a: a.get('rule', {}).get('level', 0), reverse=True)
        subset = sorted_alerts[:25]
    except Exception:
        subset = all_alerts[:25]

    prompt = build_playbook_prompt(subset)
    try:
        response = model.generate_content(prompt)
        text = response.text if hasattr(response, 'text') else str(response)
        # Try to parse JSON if the model complied
        try:
            return json.loads(text)
        except Exception:
            return {"raw": text}
    except Exception as e:
        print(f"Gemini generation error: {e}")
        return {"error": f"Gemini error: {e}"}

def allowed_file(filename):
    """Check if the uploaded file is a JSON file."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'json'

def vt_get_ip_report(ip_address):
    """
    Get VirusTotal report for an IP address.
    
    Args:
        ip_address (str): IP address to check
    
    Returns:
        dict: VirusTotal report data or None if not found/error
    """
    if not VT_API_KEY or not ip_address or ip_address in ['Unknown', 'None', '']:
        return None
    
    # Check cache first
    cache_key = f"ip_{ip_address}"
    if cache_key in vt_cache:
        return vt_cache[cache_key]
    
    try:
        response = requests.get(
            f'{VT_BASE_URL}/ip_addresses/{ip_address}',
            headers=VT_HEADERS,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            categories = attributes.get('categories', {})
            
            vt_result = {
                'type': 'ip',
                'address': ip_address,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'categories': categories,
                'last_analysis_date': attributes.get('last_analysis_date'),
                'link': f'https://www.virustotal.com/gui/ip-address/{ip_address}',
                'reputation': 'malicious' if stats.get('malicious', 0) > 0 else 'suspicious' if stats.get('suspicious', 0) > 0 else 'clean'
            }
            
            # Cache the result
            vt_cache[cache_key] = vt_result
            return vt_result
            
        elif response.status_code == 404:
            # IP not found in VirusTotal
            vt_result = {
                'type': 'ip',
                'address': ip_address,
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'categories': {},
                'reputation': 'unknown',
                'link': f'https://www.virustotal.com/gui/ip-address/{ip_address}',
                'not_found': True
            }
            vt_cache[cache_key] = vt_result
            return vt_result
            
    except Exception as e:
        print(f"Error fetching VirusTotal data for IP {ip_address}: {e}")
    
    return None

def vt_get_url_report(url):
    """
    Get VirusTotal report for a URL.
    
    Args:
        url (str): URL to check
    
    Returns:
        dict: VirusTotal report data or None if not found/error
    """
    if not VT_API_KEY or not url or url in ['Unknown', 'None', '']:
        return None
    
    # Check cache first
    cache_key = f"url_{url}"
    if cache_key in vt_cache:
        return vt_cache[cache_key]
    
    try:
        # First, submit URL for analysis if needed
        submit_response = requests.post(
            f'{VT_BASE_URL}/urls',
            headers=VT_HEADERS,
            data={'url': url},
            timeout=10
        )
        
        if submit_response.status_code == 200:
            analysis_id = submit_response.json().get('data', {}).get('id', '')
            
            # Get the analysis results
            analysis_response = requests.get(
                f'{VT_BASE_URL}/analyses/{analysis_id}',
                headers=VT_HEADERS,
                timeout=10
            )
            
            if analysis_response.status_code == 200:
                data = analysis_response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('stats', {})
                
                vt_result = {
                    'type': 'url',
                    'url': url,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': 'malicious' if stats.get('malicious', 0) > 0 else 'suspicious' if stats.get('suspicious', 0) > 0 else 'clean',
                    'link': f'https://www.virustotal.com/gui/url/{url}'
                }
                
                # Cache the result
                vt_cache[cache_key] = vt_result
                return vt_result
                
    except Exception as e:
        print(f"Error fetching VirusTotal data for URL {url}: {e}")
    
    return None

def vt_get_hash_report(file_hash):
    """
    Get VirusTotal report for a file hash.
    
    Args:
        file_hash (str): File hash (MD5, SHA1, or SHA256)
    
    Returns:
        dict: VirusTotal report data or None if not found/error
    """
    if not VT_API_KEY or not file_hash or file_hash in ['Unknown', 'None', '']:
        return None
    
    # Check cache first
    cache_key = f"hash_{file_hash}"
    if cache_key in vt_cache:
        return vt_cache[cache_key]
    
    try:
        response = requests.get(
            f'{VT_BASE_URL}/files/{file_hash}',
            headers=VT_HEADERS,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            vt_result = {
                'type': 'file',
                'hash': file_hash,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'file_type': attributes.get('type_description', 'Unknown'),
                'reputation': 'malicious' if stats.get('malicious', 0) > 0 else 'suspicious' if stats.get('suspicious', 0) > 0 else 'clean',
                'link': f'https://www.virustotal.com/gui/file/{file_hash}'
            }
            
            # Cache the result
            vt_cache[cache_key] = vt_result
            return vt_result
            
        elif response.status_code == 404:
            # Hash not found in VirusTotal
            vt_result = {
                'type': 'file',
                'hash': file_hash,
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'reputation': 'unknown',
                'link': f'https://www.virustotal.com/gui/file/{file_hash}',
                'not_found': True
            }
            vt_cache[cache_key] = vt_result
            return vt_result
            
    except Exception as e:
        print(f"Error fetching VirusTotal data for hash {file_hash}: {e}")
    
    return None

def classify_alert_data(alert):
    """
    Classify a Wazuh alert dictionary into severity and type.
    Returns a dict like {"severity": "...", "type": "...", "color": "..."}
    """
    try:
        # Extract Wazuh alert data
        rule_level = alert.get('rule', {}).get('level', 0)
        rule_groups = alert.get('rule', {}).get('groups', [])
        rule_description = alert.get('rule', {}).get('description', '').lower()
        
        # Determine severity based on rule level and context
        if rule_level >= 12:
            severity = "Critical"
            color = "danger"
            alert_type = "Incident"
        elif rule_level >= 8:
            severity = "High" 
            color = "warning"
            alert_type = "Alert"
        elif rule_level >= 5:
            severity = "Medium"
            color = "info"
            alert_type = "Alert"
        else:
            severity = "Low"
            color = "secondary"
            alert_type = "Event"
        
        # Adjust severity based on rule groups and description
        critical_keywords = ['attack', 'malware', 'intrusion', 'compromise', 'breach', 'ransomware']
        high_keywords = ['bruteforce', 'exploit', 'privilege', 'escalation', 'lateral']
        
        # Check for critical indicators
        if any(keyword in rule_description for keyword in critical_keywords):
            severity = "Critical"
            color = "danger"
            alert_type = "Incident"
        elif any(keyword in rule_description for keyword in high_keywords):
            if severity == "Low" or severity == "Medium":
                severity = "High"
                color = "warning"
                alert_type = "Alert"
        
        # Check rule groups for additional context
        if 'attack' in rule_groups or 'malware' in rule_groups:
            severity = "Critical"
            color = "danger"
            alert_type = "Incident"
        elif 'authentication_failed' in rule_groups and rule_level >= 7:
            if severity != "Critical":
                severity = "High"
                color = "warning"
                alert_type = "Alert"
        
        return {
            "severity": severity,
            "type": alert_type,
            "color": color
        }
        
    except Exception as e:
        print(f"Error classifying alert: {e}")
        return {
            "severity": "Low",
            "type": "Event", 
            "color": "secondary"
        }


def enrich_alert(alert_data):
    """
    Enrich alert with additional threat intelligence and analysis.
    
    Args:
        alert_data (dict): Single Wazuh alert data
    
    Returns:
        dict: Enriched alert information
    """
    enrichment = {
        'attack_type': 'Unknown',
        'motive': 'Unknown',
        'target_service': 'Unknown',
        'target_user': 'Unknown',
        'risk_score': 1,
        'recommendations': []
    }
    
    try:
        rule_description = alert_data.get('rule', {}).get('description', '').lower()
        rule_groups = alert_data.get('rule', {}).get('groups', [])
        rule_level = alert_data.get('rule', {}).get('level', 0)
        
        # Extract target information
        data = alert_data.get('data', {})
        if 'dstuser' in data:
            enrichment['target_user'] = data['dstuser']
        elif 'user' in data:
            enrichment['target_user'] = data['user']
        
        # Determine attack type and motive based on patterns
        if 'ssh' in rule_description or 'ssh' in rule_groups:
            enrichment.update({
                'attack_type': 'SSH Bruteforce',
                'motive': 'Credential Theft',
                'target_service': 'SSH (Port 22)',
                'risk_score': rule_level * 1.2
            })
            enrichment['recommendations'].append('Block source IP on firewall')
            enrichment['recommendations'].append('Enable SSH key-based authentication')
        
        elif 'http' in rule_description or 'web' in rule_groups:
            enrichment.update({
                'attack_type': 'Web Application Attack',
                'motive': 'Data Breach / Defacement',
                'target_service': 'HTTP/HTTPS',
                'risk_score': rule_level * 1.1
            })
            enrichment['recommendations'].append('Review web application logs')
            enrichment['recommendations'].append('Update web application security patches')
        
        elif 'authentication_failed' in rule_groups:
            enrichment.update({
                'attack_type': 'Authentication Attack',
                'motive': 'Unauthorized Access',
                'target_service': 'Authentication Service',
                'risk_score': rule_level * 1.3
            })
            enrichment['recommendations'].append('Implement account lockout policies')
            enrichment['recommendations'].append('Enable multi-factor authentication')
        
        elif 'malware' in rule_groups:
            enrichment.update({
                'attack_type': 'Malware Activity',
                'motive': 'System Compromise',
                'target_service': 'System Files',
                'risk_score': rule_level * 1.5
            })
            enrichment['recommendations'].append('Isolate affected system')
            enrichment['recommendations'].append('Run full antivirus scan')
        
        elif 'rootcheck' in rule_groups:
            enrichment.update({
                'attack_type': 'System Integrity Violation',
                'motive': 'Privilege Escalation',
                'target_service': 'System Configuration',
                'risk_score': rule_level * 1.1
            })
            enrichment['recommendations'].append('Review system configuration changes')
            enrichment['recommendations'].append('Verify file integrity')
        
        # Cap risk score at 15
        enrichment['risk_score'] = min(enrichment['risk_score'], 15)
        
        # VirusTotal enrichment
        source_ip = get_source_ip(alert_data)
        vt_data = vt_get_ip_report(source_ip)
        
        if vt_data:
            enrichment['virustotal'] = vt_data
            
            # Adjust risk score based on VirusTotal reputation
            if vt_data['reputation'] == 'malicious':
                enrichment['risk_score'] = min(15, enrichment['risk_score'] + 3)
                enrichment['recommendations'].append('BLOCK IP: VirusTotal indicates malicious activity')
            elif vt_data['reputation'] == 'suspicious':
                enrichment['risk_score'] = min(15, enrichment['risk_score'] + 1.5)
                enrichment['recommendations'].append('MONITOR IP: VirusTotal indicates suspicious activity')
            
            # Add VT categories if available
            if vt_data.get('categories'):
                enrichment['vt_categories'] = vt_data['categories']
        
        # Check for other observables in the alert data
        data = alert_data.get('data', {})
        
        # Look for URLs in the data
        for key, value in data.items():
            if isinstance(value, str) and ('http://' in value or 'https://' in value):
                url_vt = vt_get_url_report(value)
                if url_vt:
                    enrichment['virustotal_url'] = url_vt
                    if url_vt['reputation'] == 'malicious':
                        enrichment['risk_score'] = min(15, enrichment['risk_score'] + 2)
                        enrichment['recommendations'].append('BLOCK URL: VirusTotal indicates malicious URL')
                    break
        
        # Look for file hashes in the data
        for key, value in data.items():
            if isinstance(value, str) and len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value):
                hash_vt = vt_get_hash_report(value)
                if hash_vt:
                    enrichment['virustotal_hash'] = hash_vt
                    if hash_vt['reputation'] == 'malicious':
                        enrichment['risk_score'] = min(15, enrichment['risk_score'] + 4)
                        enrichment['recommendations'].append('QUARANTINE FILE: VirusTotal indicates malicious file hash')
                    break
        
        # Cap risk score again after VT adjustments
        enrichment['risk_score'] = min(enrichment['risk_score'], 15)
        
    except Exception as e:
        print(f"Error enriching alert: {e}")
    
    return enrichment

def correlate_ip(ip_address, all_alerts):
    """
    Find all alerts related to a specific IP address.
    
    Args:
        ip_address (str): IP address to correlate
        all_alerts (list): List of all alerts
    
    Returns:
        list: List of correlated alerts
    """
    correlated_alerts = []
    
    try:
        for alert in all_alerts:
            # Check various IP fields in the alert
            alert_ips = []
            
            # Common IP fields in Wazuh alerts
            if 'srcip' in alert.get('data', {}):
                alert_ips.append(alert['data']['srcip'])
            if 'dstip' in alert.get('data', {}):
                alert_ips.append(alert['data']['dstip'])
            if 'src_ip' in alert.get('data', {}):
                alert_ips.append(alert['data']['src_ip'])
            if 'dst_ip' in alert.get('data', {}):
                alert_ips.append(alert['data']['dst_ip'])
            
            # Check if target IP matches any IP in the alert
            if ip_address in alert_ips:
                correlated_alerts.append(alert)
    
    except Exception as e:
        print(f"Error correlating IP {ip_address}: {e}")
    
    return correlated_alerts

def get_source_ip(alert_data):
    """Extract source IP from alert data."""
    data = alert_data.get('data', {})
    return data.get('srcip', data.get('src_ip', 'Unknown'))

def parse_timestamp(timestamp_str):
    """Parse Wazuh timestamp and return formatted string."""
    try:
        # Common Wazuh timestamp formats
        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
        return timestamp_str
    except:
        return 'Unknown'
@app.route('/api/classify', methods=['POST'])
def classify_alert():
    try:
        data = request.get_json(force=True, silent=False)
        if not data:
            return jsonify({"error": "Invalid or missing JSON input"}), 400

        # Handle both Wazuh alerts and questionnaire-style inputs
        if 'answers' in data:
            # Legacy questionnaire format - convert to Wazuh-like structure
            answers = data['answers']
            mock_alert = {
                'rule': {
                    'level': 8 if answers.get('automated_system') == 'yes' else 5,
                    'description': 'User classification input',
                    'groups': ['user_input']
                }
            }
            if answers.get('malicious_activity') == 'yes':
                mock_alert['rule']['groups'].append('attack')
                mock_alert['rule']['level'] = 12
            if answers.get('assets_affected', 0) > 5:
                mock_alert['rule']['level'] = 12
                mock_alert['rule']['groups'].append('attack')
            
            classification = classify_alert_data(mock_alert)
        else:
            # Direct Wazuh alert format
            classification = classify_alert_data(data)
        
        return jsonify(classification), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/api/storyboard', methods=['GET'])
def api_storyboard():
    """Build an offline-first storyboard from current alerts. Optional Gemini polish via ?ai=yes."""
    # Phase mapping heuristics
    PHASES = [
        ("Reconnaissance", ["web", "scanner", "nmap", "http", "crawl", "recon"]),
        ("Initial Access", ["authentication_failed", "ssh", "rdp", "login", "phishing"]),
        ("Execution", ["malware", "process_creation", "command", "powershell", "bash"]),
        ("Persistence", ["registry_persistence", "autorun", "startup", "persistence"]),
        ("Privilege Escalation", ["sudo", "su", "token", "kernel", "privilege"]),
        ("Defense Evasion", ["rootcheck", "policy_monitoring", "tamper", "evasion"]),
        ("Lateral Movement", ["smb", "winrm", "rpc", "remote", "lateral"]),
        ("Collection/Exfiltration", ["data_exfiltration", "ftp", "curl", "upload", "exfil"]),
        ("Impact", ["ransomware", "encryption", "wiper", "ddos", "impact"])
    ]

    def phase_of(alert):
        desc = (alert.get('rule', {}).get('description') or '').lower()
        groups = [str(g).lower() for g in alert.get('rule', {}).get('groups', [])]
        for name, hints in PHASES:
            for h in hints:
                if h in desc or h in groups:
                    return name
        level = alert.get('rule', {}).get('level', 0)
        return "Initial Access" if level >= 6 else "Reconnaissance"

    # Helper time parsing using existing formatter + strict parse
    from datetime import datetime as _dt, timedelta as _td
    def _ts(alert):
        return parse_timestamp(alert.get('timestamp', ''))
    def _to_dt(s):
        try:
            return _dt.strptime(s, '%Y-%m-%d %H:%M:%S')
        except Exception:
            return _dt.min

    window = _td(minutes=45)
    alerts_sorted = sorted(alerts_data, key=lambda a: _to_dt(_ts(a)))
    clusters = []
    index_by_alert = {id(a): i for i, a in enumerate(alerts_data)}
    for a in alerts_sorted:
        sip = get_source_ip(a)
        t = _to_dt(_ts(a))
        if not clusters or clusters[-1]['source_ip'] != sip or (t - clusters[-1]['end']) > window:
            clusters.append({'source_ip': sip, 'start': t, 'end': t, 'alerts': [], 'phases_count': {}})
        cl = clusters[-1]
        cl['end'] = max(cl['end'], t)
        cl['alerts'].append(index_by_alert[id(a)])
        ph = phase_of(a)
        cl['phases_count'][ph] = cl['phases_count'].get(ph, 0) + 1

    frames = []
    for cl in clusters:
        top_phase = max(cl['phases_count'].items(), key=lambda kv: kv[1])[0] if cl['phases_count'] else "Reconnaissance"
        rule_levels = [alerts_data[i].get('rule', {}).get('level', 0) for i in cl['alerts']]
        caption = f"{top_phase} activity from {cl['source_ip']} across {len(cl['alerts'])} alert(s)."
        tech = f"Levels min={min(rule_levels) if rule_levels else 0}, max={max(rule_levels) if rule_levels else 0}"
        frames.append({
            "source_ip": cl['source_ip'],
            "start": cl['start'].strftime('%Y-%m-%d %H:%M:%S') if cl['start'] != _dt.min else "Unknown",
            "end": cl['end'].strftime('%Y-%m-%d %H:%M:%S') if cl['end'] != _dt.min else "Unknown",
            "phase": top_phase,
            "caption": caption,
            "technical": tech,
            "alert_ids": cl['alerts']
        })

    result = {"frames": frames, "total_clusters": len(clusters)}

    # Optional Gemini polish (single batched call)
    if request.args.get('ai', 'no').lower() == 'yes' and frames:
        model = init_gemini_client()
        if model:
            try:
                prompt = (
                    "Return a JSON array of short human-friendly titles for these incident frames in the same order. "
                    "Do not include any explanation, only a JSON array of strings.\n" + json.dumps(frames[:12], indent=2)
                )
                resp = model.generate_content(prompt)
                text = resp.text if hasattr(resp, 'text') else str(resp)
                try:
                    titles = json.loads(text)
                    if isinstance(titles, list):
                        for i, t in enumerate(titles[:len(frames)]):
                            if isinstance(t, str):
                                frames[i]['title'] = t
                except Exception:
                    pass
            except Exception:
                pass

    return jsonify(result)

@app.route('/api/evidence_pack', methods=['POST'])
def api_evidence_pack():
    """Create a ZIP evidence pack without external API calls."""
    body = request.get_json(silent=True) or {}
    actions_audit = body.get('actions_audit', {})
    storyboard = body.get('storyboard')

    from io import BytesIO
    import zipfile, csv

    mem = BytesIO()
    with zipfile.ZipFile(mem, mode='w', compression=zipfile.ZIP_DEFLATED) as z:
        # alerts.json
        z.writestr('alerts.json', json.dumps(alerts_data, indent=2))

        # correlated.csv
        csv_bytes = BytesIO()
        writer = csv.writer(csv_bytes)
        writer.writerow(['source_ip', 'alert_id', 'timestamp', 'rule_description', 'rule_level'])
        for i, a in enumerate(alerts_data):
            writer.writerow([
                get_source_ip(a),
                i,
                parse_timestamp(a.get('timestamp', '')),
                a.get('rule', {}).get('description', ''),
                a.get('rule', {}).get('level', 0)
            ])
        z.writestr('correlated.csv', csv_bytes.getvalue().decode('utf-8', errors='ignore'))

        # storyboard.md (generate if not provided)
        if not storyboard:
            # Compute a minimal storyboard locally
            # Reuse function above by direct call
            try:
                sb_frames = api_storyboard().json  # type: ignore
            except Exception:
                sb_frames = {"frames": []}
            storyboard = sb_frames
        md = ["# Incident Storyboard"]
        for f in storyboard.get('frames', []):
            title = f.get('title') or f"{f.get('phase')} from {f.get('source_ip')}"
            md.append(f"## {title}")
            md.append(f"- Time: {f.get('start')} → {f.get('end')}")
            md.append(f"- Summary: {f.get('caption')}")
            md.append(f"- Technical: {f.get('technical')}")
            md.append(f"- Alerts: {len(f.get('alert_ids', []))}")
            md.append("")
        z.writestr('storyboard.md', "\n".join(md))

        # actions_audit.json
        z.writestr('actions_audit.json', json.dumps(actions_audit, indent=2))

        # summary.txt
        counts = {"total": len(alerts_data), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts_data:
            sev = classify_alert_data(a)['severity'].lower()
            if sev in counts:
                counts[sev] += 1
        z.writestr('summary.txt', "\n".join([f"{k}: {v}" for k, v in counts.items()]))

        # vt_cache.json (existing cache only)
        z.writestr('vt_cache.json', json.dumps(vt_cache, indent=2))

    mem.seek(0)
    filename = f"evidence_pack_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
    return send_file(mem, mimetype='application/zip', as_attachment=True, download_name=filename)

@app.route('/api/noise_suggestions', methods=['GET'])
def api_noise_suggestions():
    """Return top noisy patterns and simulate muting effect."""
    from collections import Counter, defaultdict

    def noise_key(a):
        r = a.get('rule', {})
        agent = a.get('agent', {}).get('name', 'unknown')
        return (str(r.get('id', '')), r.get('description', ''), agent)

    counts = Counter()
    examples = {}
    severities = defaultdict(list)
    for i, a in enumerate(alerts_data):
        k = noise_key(a)
        counts[k] += 1
        if k not in examples:
            examples[k] = i
        severities[k].append(classify_alert_data(a)['severity'])

    def score(k, c):
        sev = severities[k]
        hi = sum(1 for s in sev if s in ['High', 'Critical'])
        return (c, -hi)

    ranked = sorted(counts.items(), key=lambda kv: score(kv[0], kv[1]), reverse=True)[:10]

    suggestions = []
    total = len(alerts_data)
    for (rule_id, rule_desc, agent), c in ranked:
        sev_list = severities[(rule_id, rule_desc, agent)]
        highish = sum(1 for s in sev_list if s in ['High', 'Critical'])
        if highish > 0:
            continue
        xml = f'<rule id="{rule_id}" level="0"><if_agent_name>{agent}</if_agent_name><description>{rule_desc}</description></rule>'
        projected = total - c
        suggestions.append({
            "pattern": {"rule_id": rule_id, "rule_description": rule_desc, "agent": agent},
            "count": c,
            "share": round(c / max(total, 1), 3),
            "wazuh_filter_snippet": xml,
            "projected_total_after_mute": projected,
            "example_alert_id": examples[(rule_id, rule_desc, agent)]
        })

    return jsonify({
        "total": total,
        "suggestions": suggestions[:5],
        "note": "Review carefully before muting; avoid suppressing security-relevant alerts."
    })

@app.route('/')
def dashboard():
    """Main dashboard showing all alerts."""
    processed_alerts = []
    
    for i, alert in enumerate(alerts_data):
        classification = classify_alert_data(alert)
        processed_alert = {
            'id': i,
            'timestamp': parse_timestamp(alert.get('timestamp', '')),
            'source_ip': get_source_ip(alert),
            'rule_description': alert.get('rule', {}).get('description', 'Unknown Rule'),
            'rule_level': alert.get('rule', {}).get('level', 0),
            'classification': classification,
            'agent': alert.get('agent', {}).get('name', 'Unknown')
        }
        processed_alerts.append(processed_alert)
    
    # Sort by rule level (highest first)
    processed_alerts.sort(key=lambda x: x['rule_level'], reverse=True)
    
    return render_template('dashboard.html', alerts=processed_alerts, total_alerts=len(alerts_data))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle JSON file upload."""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                # Read and parse JSON data
                json_data = json.load(file)
                
                # Handle both single alerts and arrays of alerts
                if isinstance(json_data, list):
                    alerts_data.extend(json_data)
                    flash(f'Successfully uploaded {len(json_data)} alerts', 'success')
                else:
                    alerts_data.append(json_data)
                    flash('Successfully uploaded 1 alert', 'success')
                
                return redirect(url_for('dashboard'))
                
            except json.JSONDecodeError:
                flash('Invalid JSON file format', 'error')
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
        else:
            flash('Please upload a valid JSON file', 'error')
    
    return render_template('upload.html')

@app.route('/alert/<int:alert_id>')
def alert_detail(alert_id):
    """Show detailed view of a specific alert."""
    if alert_id >= len(alerts_data):
        flash('Alert not found', 'error')
        return redirect(url_for('dashboard'))
    
    alert = alerts_data[alert_id]
    classification = classify_alert_data(alert)
    enrichment = enrich_alert(alert)
    
    # Get source IP for correlation
    source_ip = get_source_ip(alert)
    correlated_alerts = correlate_ip(source_ip, alerts_data)
    
    # Process correlated alerts for display
    correlated_display = []
    for i, corr_alert in enumerate(correlated_alerts):
        if i != alert_id:  # Don't include the current alert
            correlated_display.append({
                'id': alerts_data.index(corr_alert),
                'timestamp': parse_timestamp(corr_alert.get('timestamp', '')),
                'rule_description': corr_alert.get('rule', {}).get('description', 'Unknown Rule'),
                'rule_level': corr_alert.get('rule', {}).get('level', 0)
            })
    
    alert_detail_data = {
        'id': alert_id,
        'timestamp': parse_timestamp(alert.get('timestamp', '')),
        'source_ip': source_ip,
        'agent': alert.get('agent', {}).get('name', 'Unknown'),
        'rule': alert.get('rule', {}),
        'data': alert.get('data', {}),
        'classification': classification,
        'enrichment': enrichment,
        'correlated_alerts': correlated_display,
        'raw_alert': json.dumps(alert, indent=2)
    }
    
    return render_template('alert_detail.html', alert=alert_detail_data)

@app.route('/clear')
def clear_alerts():
    """Clear all loaded alerts."""
    global alerts_data
    alerts_data = []
    flash('All alerts cleared', 'info')
    return redirect(url_for('dashboard'))

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics."""
    stats = {
        'total_alerts': len(alerts_data),
        'critical_alerts': 0,
        'high_alerts': 0,
        'medium_alerts': 0,
        'low_alerts': 0
    }
    
    for alert in alerts_data:
        classification = classify_alert_data(alert)
        severity = classification['severity'].lower()
        if severity == 'critical':
            stats['critical_alerts'] += 1
        elif severity == 'high':
            stats['high_alerts'] += 1
        elif severity == 'medium':
            stats['medium_alerts'] += 1
        else:
            stats['low_alerts'] += 1
    
    return jsonify(stats), 200


@app.route('/actions', methods=['GET'])
def actions_page():
    """Render actions page with option to generate playbook."""
    return render_template('actions.html', total_alerts=len(alerts_data))

@app.route('/api/generate_playbook', methods=['POST'])
def api_generate_playbook():
    """API to generate a playbook via Gemini from loaded alerts."""
    result = generate_playbook_from_alerts(alerts_data)
    status = 200 if 'error' not in result else 400
    return jsonify(result), status

@app.route('/api/ask_gemini', methods=['POST'])
def api_ask_gemini():
    """API to process a user form: optionally call Gemini with guideline + content.

    Expected JSON body:
    {
        "connect": "yes"|"no",
        "content": "..."
    }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        return jsonify({"error": f"Invalid JSON body: {e}"}), 400

    connect = str(data.get('connect', 'yes')).lower()
    content = data.get('content', '').strip()
    region = data.get('region', 'Other')
    industry = data.get('industry', 'Other')
    role = data.get('role', 'Employee')
    critical = str(data.get('critical', 'no')).lower()
    has_team = str(data.get('has_team', 'yes')).lower()

    if connect not in ['yes', 'no']:
        return jsonify({"error": "Field 'connect' must be 'yes' or 'no'"}), 400

    if connect == 'no':
        return jsonify({
            "skipped": True,
            "message": "User chose not to contact Gemini. No request was made.",
            "echo": {"content": content}
        }), 200

    # connect == 'yes' path
    model = init_gemini_client()
    if not model:
        return jsonify({"error": "Gemini not configured. Set gemini_api in .env and install google-generativeai."}), 400

    # Hardcoded guideline (not shown to user). Customize as needed.
    HARDCODED_GUIDELINE = (
        "You are a SOC assistant. Provide concise, actionable outputs. "
        "Do not include markdown fences unless asked. Prefer bullet lists. "
        "If JSON is appropriate, return valid JSON only. "
        "Even when received alerts are too many, return a playbook with instructions consolidate to a few steps."
        "If the form has 'no' selected for 'Internal IT/Security team available?' option, MAKE SUGGESTIONS FOR NON-TECH PEOPLE."
    )

    # Build prompt combining hardcoded guideline, user content, and current alerts
    try:
        # Limit number/size to avoid overly long prompts
        sorted_alerts = sorted(alerts_data, key=lambda a: a.get('rule', {}).get('level', 0), reverse=True)
        alerts_subset = sorted_alerts[:25]
        alerts_json = json.dumps(alerts_subset, indent=2)
    except Exception:
        alerts_json = json.dumps(alerts_data[:25], indent=2)

    # Regulatory overlays / context hints
    regulatory_notes = []
    if region == 'EU':
        regulatory_notes.append('Consider GDPR for data handling and breach notification timelines.')
    if region == 'Asia':
        regulatory_notes.append('Consider Singapore PDPA and, for finance, MAS TRM requirements.')
    if region == 'North America':
        if industry == 'Healthcare':
            regulatory_notes.append('HIPAA security/privacy safeguards may apply.')
        if industry == 'Finance':
            regulatory_notes.append('PCI DSS obligations may apply for cardholder data.')
    if industry == 'Finance' and 'PCI DSS obligations may apply for cardholder data.' not in regulatory_notes:
        regulatory_notes.append('Finance sector: consider PCI DSS if processing payments.')

    operational_context = {
        "region": region,
        "industry": industry,
        "role": role,
        "business_critical": (critical == 'yes'),
        "has_internal_team": (has_team == 'yes'),
        "regulatory_notes": regulatory_notes
    }

    prompt = (
        f"Guideline (follow strictly):\n{HARDCODED_GUIDELINE}\n\n"
        f"User submission:\n{content if content else '(empty)'}\n\n"
        f"Organization context (JSON):\n{json.dumps(operational_context, indent=2)}\n\n"
        f"Current Wazuh alerts (truncated to 25):\n{alerts_json}"
    )

    try:
        resp = model.generate_content(prompt)
        text = resp.text if hasattr(resp, 'text') else str(resp)
        # Try parse JSON; otherwise return text
        try:
            parsed = json.loads(text)
            return jsonify({"skipped": False, "model_output": parsed}), 200
        except Exception:
            return jsonify({"skipped": False, "model_output_text": text}), 200
    except Exception as e:
        return jsonify({"error": f"Gemini error: {e}"}), 400

@app.route('/api/virustotal/<int:alert_id>/<observable_type>/<observable_value>')
def api_virustotal_lookup(alert_id, observable_type, observable_value):
    """API endpoint for on-demand VirusTotal lookups."""
    if alert_id >= len(alerts_data):
        return jsonify({'error': 'Alert not found'}), 404
    
    if observable_type == 'ip':
        result = vt_get_ip_report(observable_value)
    elif observable_type == 'url':
        result = vt_get_url_report(observable_value)
    elif observable_type == 'hash':
        result = vt_get_hash_report(observable_value)
    else:
        return jsonify({'error': 'Invalid observable type'}), 400
    
    return jsonify(result) if result else jsonify({'error': 'No VirusTotal data available'}), 404


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)