from flask import Flask, render_template, request, redirect, url_for, jsonify
import csv
import time
import random
from datetime import datetime
import os
import logging

app = Flask(__name__)

# Configuration
# Use absolute path to ensure notebooks can find it easily if running locally
# In a real VM setup, this would be relative to the app
LOG_DIR = 'notebooks'
LOG_FILE = os.path.join(LOG_DIR, 'network_logs.csv')

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Initialize CSV if not exists
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
def log_request_info():
    # Skip logging static files or internal dashboard calls to avoid noise
    if request.path.startswith('/static') or request.path.startswith('/victim') or request.path == '/favicon.ico':
        return

    # Classify Traffic
    action = 'HTTP_REQUEST'
    details = f"{request.method} {request.path}"
    
    if request.path == '/login' and request.method == 'POST':
        action = 'LOGIN_ATTEMPT'
        # Capture username for detail
        data = request.get_json(silent=True) or request.form
        user = data.get('username', 'unknown')
        details = f"User: {user}"
    
    # In a real VM, remote_addr is the Attacker IP
    src_ip = request.remote_addr 
    # For local testing, it might be 127.0.0.1
    
    append_log(src_ip, 'Server', 5000, action, details)


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attacker')
def attacker():
    # The Web UI Attacker Panel
    return render_template('attacker.html')

@app.route('/victim')
def victim():
    # The Web UI Victim Dashboard
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            reader = csv.DictReader(f)
            logs = list(reader)
            logs.reverse() 
    
    threats = detect_threats(logs)
    return render_template('victim.html', logs=logs[:100], threats=threats)


# --- Vulnerable Endpoints (Traffic Targets) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simulate processing time
        time.sleep(0.1) 
        return jsonify({"status": "failed", "message": "Invalid credentials"}), 401
    return "Login Page"


# --- API for Web-Based Attacks (Self-Simulation) ---
# This allows the "Attacker Console" to work even without a second VM
@app.route('/api/attack', methods=['POST'])
def api_attack():
    attack_type = request.json.get('type')
    target_ip = '127.0.0.1' # Self
    
    if attack_type == 'port_scan':
        # Log synthetic scan traffic
        for port in [21, 22, 80, 443, 8080]:
            append_log('192.168.1.50', target_ip, port, 'SCAN_SYN', 'Creating Synthetic Log')
            
    elif attack_type == 'brute_force':
        # Actually hit the login endpoint to generate REAL logs too? 
        # For simplicity in "Web Mode", we just log synthetic events 
        # to ensure the Dashboard looks good instantly.
        for _ in range(5):
            append_log('192.168.1.50', target_ip, 5000, 'LOGIN_ATTEMPT', 'Failed login admin:123')
            
    elif attack_type == 'dos':
        for _ in range(50):
            append_log('192.168.1.50', target_ip, 5000, 'HTTP_REQUEST', 'GET / HTTP/1.1')
            
    return jsonify({'status': 'success', 'message': f'{attack_type} executed'})


# --- IDS Logic ---
def detect_threats(logs):
    threats = []
    # 1. DoS: > 50 requests from same IP in last batch
    ip_counts = {}
    for log in logs[:200]: # Analyze recent logs
        ip = log['source_ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
    for ip, count in ip_counts.items():
        if count > 50:
            threats.append({'type': 'DoS Detected', 'details': f'{ip} sent {count} requests'})

    # 2. Brute Force
    login_counts = {}
    for log in logs[:200]:
        if log['action'] == 'LOGIN_ATTEMPT':
            ip = log['source_ip']
            login_counts[ip] = login_counts.get(ip, 0) + 1
            
    for ip, count in login_counts.items():
        if count > 5:
            threats.append({'type': 'Brute Force', 'details': f'{ip}: {count} failed logins'})
            
    return threats

if __name__ == '__main__':
    # Host=0.0.0.0 is CRITICAL for VM accessibility
    app.run(debug=True, host='0.0.0.0', port=5000)
