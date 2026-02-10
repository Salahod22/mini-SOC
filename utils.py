import json
import time
import os
import datetime

LOG_FILE = 'notebooks/network_logs.json'

def append_log(source_ip, dest_ip, port, action, details):
    # Use ISO 8601 format for Wazuh compatibility (e.g., 2023-10-27T10:00:00.123456)
    timestamp = datetime.datetime.utcnow().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'port': port,
        'action': action,
        'details': details
    }
    
    with open(LOG_FILE, 'a') as f:
        json.dump(log_entry, f)
        f.write('\n')

def get_logs_and_threats():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            logs.reverse() 
    
    threats = detect_threats(logs)
    return logs, threats

def detect_threats(logs):
    threats = []
    
    # 1. Signature-Based
    for log in logs[:200]:
        details = log.get('details', '')
        action = log.get('action', '')
        ip = log.get('source_ip', 'unknown')
        ts = log.get('timestamp', str(time.time()))

        if action == 'LOGIN_ATTEMPT':
            if any(s in details.upper() for s in ["' OR", "UNION SELECT", "--", "1=1"]):
                threats.append({
                    'type': 'SQL Injection', 
                    'details': f'{ip} tried SQLi payload: {details}',
                    'id': f"{ts}-{ip}-SQLI"
                })

        # Check for XSS in Search
        if action == 'SEARCH_QUERY':
            if any(s in details.lower() for s in ["<script>", "alert(", "onerror="]):
                threats.append({
                    'type': 'XSS Attempt', 
                    'details': f'{ip} tried XSS payload',
                    'id': f"{ts}-{ip}-XSS"
                })
            # Also check for Command Injection in Search (Reflected CI)
            if any(s in details for s in [";", "|", "&&", "$(", "/etc/passwd"]):
                 threats.append({
                     'type': 'Command Injection', 
                     'details': f'{ip} tried RCE payload: {details}',
                     'details': f'{ip} tried RCE payload: {details}',
                     'id': f"{ts}-{ip}-CI"
                 })
                 
        # Check for Scanner Fingerprint (Port Scan)
        if action == 'HTTP_REQUEST' and ('CyberSim-Scanner' in details or 'Nmap' in details):
             threats.append({
                 'type': 'Network Reconnaissance', 
                 'details': f'{ip} performed a Port Scan/Probe',
                 'id': f"{ts}-{ip}-SCAN"
             })

        if action == 'DNS_LOOKUP':
            if any(s in details for s in [";", "|", "&&", "$(", "/etc/passwd"]):
                 threats.append({
                     'type': 'Command Injection', 
                     'details': f'{ip} tried RCE payload: {details}',
                     'id': f"{ts}-{ip}-CI"
                 })

    # 2. Anomaly/Threshold
    dos_counts = {}
    last_dos_timestamps = {} 
    login_counts = {}
    last_login_timestamps = {} 

    for log in logs[:200]:
        ip = log.get('source_ip', 'unknown')
        action = log.get('action', '')
        ts = log.get('timestamp', '')
        details = log.get('details', '')
        
        if action == 'HTTP_REQUEST':
            dos_counts[ip] = dos_counts.get(ip, 0) + 1
            if ip not in last_dos_timestamps:
                last_dos_timestamps[ip] = ts

        if action == 'LOGIN_ATTEMPT' and 'Failed login' in details:
            login_counts[ip] = login_counts.get(ip, 0) + 1
            if ip not in last_login_timestamps:
                last_login_timestamps[ip] = ts

    # Detect DoS
    for ip, count in dos_counts.items():
        if count > 10: 
            threats.append({
                'type': 'DoS Detected', 
                'details': f'{ip} sent {count} requests',
                'id': f"DoS-{ip}-{last_dos_timestamps.get(ip,'')}" 
            })

    # Detect Brute Force
    for ip, count in login_counts.items():
        if count > 3:
            threats.append({
                'type': 'Brute Force Detected', 
                'details': f'{ip} failed login {count} times',
                'id': f"BF-{ip}-{last_login_timestamps.get(ip,'')}" 
            })
            
    return threats
