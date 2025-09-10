from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global storage for alerts (in production, use a database)
alerts_data = []

def allowed_file(filename):
    """Check if the uploaded file is a JSON file."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'json'

def classify_alert(alert_data):
    """
    Classify alerts based on simple rules.
    
    Args:
        alert_data (dict): Single Wazuh alert data
    
    Returns:
        dict: Classification with severity and type
    """
    classification = {
        'severity': 'Low',
        'type': 'Information',
        'color': 'success'
    }
    
    try:
        rule_level = alert_data.get('rule', {}).get('level', 0)
        rule_groups = alert_data.get('rule', {}).get('groups', [])
        rule_description = alert_data.get('rule', {}).get('description', '').lower()
        
        # High severity classification
        if rule_level >= 10:
            classification.update({
                'severity': 'Critical',
                'type': 'Critical Threat',
                'color': 'danger'
            })
        elif rule_level >= 7:
            classification.update({
                'severity': 'High',
                'type': 'Suspicious Activity',
                'color': 'warning'
            })
        elif rule_level >= 5:
            classification.update({
                'severity': 'Medium',
                'type': 'Potential Issue',
                'color': 'info'
            })
        
        # Specific threat type classification
        if 'authentication_failed' in rule_groups or 'authentication_failures' in rule_groups:
            classification.update({
                'type': 'Potential Bruteforce',
                'color': 'warning' if classification['severity'] == 'Low' else classification['color']
            })
        
        if 'web' in rule_groups and rule_level >= 6:
            classification.update({
                'type': 'Web Attack',
                'color': 'danger'
            })
        
        if 'malware' in rule_groups:
            classification.update({
                'severity': 'Critical',
                'type': 'Malware Detected',
                'color': 'danger'
            })
        
        if 'rootcheck' in rule_groups or 'policy_monitoring' in rule_groups:
            classification.update({
                'type': 'Policy Violation',
                'color': 'warning'
            })
        
    except Exception as e:
        print(f"Error classifying alert: {e}")
    
    return classification

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

@app.route('/')
def dashboard():
    """Main dashboard showing all alerts."""
    processed_alerts = []
    
    for i, alert in enumerate(alerts_data):
        classification = classify_alert(alert)
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
    classification = classify_alert(alert)
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
        classification = classify_alert(alert)
        severity = classification['severity'].lower()
        if severity == 'critical':
            stats['critical_alerts'] += 1
        elif severity == 'high':
            stats['high_alerts'] += 1
        elif severity == 'medium':
            stats['medium_alerts'] += 1
        else:
            stats['low_alerts'] += 1
    
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)