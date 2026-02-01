from flask import Flask, render_template, request, redirect, url_for, jsonify
import csv
import time
import random
from datetime import datetime
import os
import logging
import requests
import socket

app = Flask(__name__)

# Configuration
LOG_DIR = 'notebooks'
LOG_FILE = os.path.join(LOG_DIR, 'network_logs.csv')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'source_ip', 'dest_ip', 'port', 'action', 'details'])

def append_log(source_ip, dest_ip, port, action, details):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, source_ip, dest_ip, port, action, details])
    except Exception as e:
        print(f"Logging Error: {e}")

# Middleware to log EVERY request (The "IDS" Sensor)
@app.before_request
@app.before_request
def log_request_info():
    if request.path.startswith('/static') or request.path.startswith('/victim') or request.path == '/favicon.ico' or request.path == '/api/data' or request.path == '/api/attack':
        return

    # Classify Traffic & Capture Payload
    action = 'HTTP_REQUEST'
    details = f"{request.method} {request.path}"
    
    # 1. Login (Potential SQLi target)
    if request.path == '/login' and request.method == 'POST':
        action = 'LOGIN_ATTEMPT'
        data = request.get_json(silent=True) or request.form
        user = data.get('username', 'unknown')
        details = f"User: {user}"

    # 2. Search (Potential XSS target)
    elif request.path == '/search':
        action = 'SEARCH_QUERY'
        query = request.args.get('q', '')
        if query:
            details = f"Query: {query}"

    # 3. DNS Lookup (Potential Command Injection target)
    elif request.path == '/dns-lookup':
        action = 'DNS_LOOKUP'
        data = request.get_json(silent=True) or request.form
        domain = data.get('domain', '')
        details = f"Target: {domain}"
    
    src_ip = request.remote_addr 
    append_log(src_ip, 'Server', 5000, action, details)


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attacker')
def attacker():
    # The Web UI Attacker Panel
    return render_template('attacker.html')

def get_logs_and_threats():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            reader = csv.DictReader(f)
            logs = list(reader)
            logs.reverse() 
    
    threats = detect_threats(logs)
    return logs, threats

@app.route('/victim')
def victim():
    # The Web UI Victim Dashboard
    logs, threats = get_logs_and_threats()
    return render_template('victim.html', logs=logs[:100], threats=threats)

@app.route('/api/data')
def api_data():
    # JSON Endpoint for Real-Time Updates
    logs, threats = get_logs_and_threats()
    return jsonify({
        'logs': logs[:50], 
        'threats': threats
    })


# --- Vulnerable Endpoints (Traffic Targets) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        time.sleep(0.1) 
        data = request.form
        username = data.get('username')
        password = data.get('password')
        
        # Hardcoded Credentials
        if username == 'admin' and password == 'password':
            return render_template('login.html', success="Welcome back, Administrator.")
        else:
            return render_template('login.html', error="Invalid credentials. Intrusion attempt logged.")
    return render_template('login.html')

@app.route('/search')
def search():
    # Vulnerable to XSS (Reflected)
    query = request.args.get('q', '')
    return render_template('search.html', query=query) 

@app.route('/dns-lookup', methods=['POST'])
def dns_lookup():
    # Vulnerable to Command Injection
    # In a real vulnerable app: os.system(f"ping {domain}")
    return jsonify({"status": "completed", "output": "Ping output..."})


# --- API for Web-Based Attacks (Self-Simulation) ---
@app.route('/api/attack', methods=['POST'])
def api_attack():
    attack_type = request.json.get('type')
    target_ip = request.json.get('target', '127.0.0.1')
    base_url = f"http://{target_ip}:5000"
    
    try:
        if attack_type == 'port_scan':
            # Real Port Scan
            ports = [21, 22, 80, 443, 8080, 5000]
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect_ex((target_ip, port))
                    sock.close()
                except:
                    pass
                
        elif attack_type == 'brute_force':
            # Real Brute Force
            url = f"{base_url}/login"
            for _ in range(5):
                try:
                    requests.post(url, json={'username': 'admin', 'password': 'wrongpassword'}, timeout=1)
                except: pass
                
        elif attack_type == 'dos':
            try:
                count = int(request.json.get('count', 50))
            except:
                count = 50
            # Real DoS
            for _ in range(count):
                try:
                    requests.get(base_url, timeout=0.1)
                except: pass

        elif attack_type == 'sqli':
            # Real SQLi
            requests.post(f"{base_url}/login", json={'username': "admin' OR 1=1 --", 'password': 'x'}, timeout=1)

        elif attack_type == 'xss':
            # Real XSS
            requests.get(f"{base_url}/search", params={'q': "<script>alert('XSS')</script>"}, timeout=1)

        elif attack_type == 'command_injection':
            # Real RCE
            requests.post(f"{base_url}/dns-lookup", json={'domain': "8.8.8.8; cat /etc/passwd"}, timeout=1)
            
        return jsonify({'status': 'success', 'message': f'{attack_type} execution completed'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Attack failed: {str(e)}'}), 500


# --- IDS Logic ---
def detect_threats(logs):
    threats = []
    
    # 1. Signature-Based Detection (Strings)
    for log in logs[:200]:
        details = log.get('details', '')
        action = log.get('action', '')
        ip = log.get('source_ip', 'unknown')
        ts = log.get('timestamp', str(time.time()))

        # SQL Injection Signatures
        if action == 'LOGIN_ATTEMPT':
            if any(s in details.upper() for s in ["' OR", "UNION SELECT", "--", "1=1"]):
                threats.append({
                    'type': 'SQL Injection', 
                    'details': f'{ip} tried SQLi payload: {details}',
                    'id': f"{ts}-{ip}-SQLI" # Unique ID
                })

        # XSS Signatures
        if action == 'SEARCH_QUERY':
            if any(s in details.lower() for s in ["<script>", "alert(", "onerror="]):
                threats.append({
                    'type': 'XSS Attempt', 
                    'details': f'{ip} tried XSS payload',
                    'id': f"{ts}-{ip}-XSS"
                })

        # Command Injection Signatures
        if action == 'DNS_LOOKUP':
            if any(s in details for s in [";", "|", "&&", "$(", "/etc/passwd"]):
                 threats.append({
                     'type': 'Command Injection', 
                     'details': f'{ip} tried RCE payload: {details}',
                     'id': f"{ts}-{ip}-CI"
                 })

    # 2. Anomaly/Threshold Detection
    dos_counts = {}
    last_dos_timestamps = {} # Track latest HTTP_REQUEST per IP
    
    login_counts = {}
    last_login_timestamps = {} # Track latest LOGIN per IP

    for log in logs[:200]:
        ip = log.get('source_ip', 'unknown')
        action = log.get('action', '')
        ts = log.get('timestamp', '')
        details = log.get('details', '')
        
        # Track DoS metrics (HTTP_REQUEST)
        if action == 'HTTP_REQUEST':
            dos_counts[ip] = dos_counts.get(ip, 0) + 1
            if ip not in last_dos_timestamps:
                last_dos_timestamps[ip] = ts

        # Track Brute Force metrics (LOGIN_ATTEMPT) - ONLY 'Failed login'
        # This prevents SQLi (which logs 'User: payload') from counting as Brute Force
        if action == 'LOGIN_ATTEMPT' and 'Failed login' in details:
            login_counts[ip] = login_counts.get(ip, 0) + 1
            if ip not in last_login_timestamps:
                last_login_timestamps[ip] = ts

    # Detect DoS
    for ip, count in dos_counts.items():
        if count > 10: # Lowered threshold for simulation sensitivity
            threats.append({
                'type': 'DoS Detected', 
                'details': f'{ip} sent {count} requests',
                'id': f"DoS-{ip}-{last_dos_timestamps.get(ip,'')}" # ID based on latest HTTP_REQUEST time
            })

    # Detect Brute Force
    for ip, count in login_counts.items():
        if count > 3:
            threats.append({
                'type': 'Brute Force Detected', 
                'details': f'{ip} failed login {count} times',
                'id': f"BF-{ip}-{last_login_timestamps.get(ip,'')}" # ID based on latest LOGIN time
            })
            
    return threats

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
