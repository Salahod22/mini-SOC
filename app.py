from flask import Flask, render_template, request, redirect, url_for, jsonify
import csv
import time
import random
from datetime import datetime
import os

app = Flask(__name__)

# Configuration
LOG_FILE = os.path.join('notebooks', 'network_logs.csv')
ATTACKER_IP = '192.168.1.50'
TARGET_IP = '192.168.1.100'

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    os.makedirs('notebooks', exist_ok=True)
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'source_ip', 'dest_ip', 'port', 'action', 'details'])

def log_traffic(source_ip, dest_ip, port, action, details):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, source_ip, dest_ip, port, action, details])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attacker')
def attacker():
    return render_template('attacker.html')

@app.route('/victim')
def victim():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            reader = csv.DictReader(f)
            logs = list(reader)
            logs.reverse() # Show newest first
    
    # Simple IDS Logic for the Dashboard
    threats = detect_threats(logs)
    
    return render_template('victim.html', logs=logs[:50], threats=threats) # Show last 50 logs

@app.route('/api/attack', methods=['POST'])
def api_attack():
    attack_type = request.json.get('type')
    
    if attack_type == 'port_scan':
        # Simulate a quick small scan
        open_ports = [22, 80, 443]
        for port in range(20, 30):
            status = 'OPEN' if port in open_ports else 'CLOSED'
            log_traffic(ATTACKER_IP, TARGET_IP, port, 'SCAN_SYN', f'Port {status}')
            
    elif attack_type == 'brute_force':
        usernames = ['admin', 'root']
        passwords = ['123', 'password', 'admin']
        for _ in range(5):
            u = random.choice(usernames)
            p = random.choice(passwords)
            log_traffic(ATTACKER_IP, TARGET_IP, 22, 'LOGIN_ATTEMPT', f'Failed login {u}:{p}')
            
    elif attack_type == 'dos':
        for _ in range(20):
            log_traffic(ATTACKER_IP, TARGET_IP, 80, 'HTTP_REQUEST', 'GET / HTTP/1.1')
            
    return jsonify({'status': 'success', 'message': f'{attack_type} executed'})

def detect_threats(logs):
    threats = []
    # Simplified detection logic for the web view
    # 1. Count HTTP requests (DoS)
    http_count = sum(1 for log in logs if log['action'] == 'HTTP_REQUEST')
    if http_count > 100: # Arbitrary threshold for demo
        threats.append({'type': 'DoS Detected', 'details': f'High volume of HTTP requests ({http_count})'})
        
    # 2. Count Login Attempts (Brute Force)
    login_count = sum(1 for log in logs if log['action'] == 'LOGIN_ATTEMPT')
    if login_count > 10:
         threats.append({'type': 'Brute Force Detected', 'details': f'Multiple failed logins ({login_count})'})
         
    return threats

if __name__ == '__main__':
    app.run(debug=True, port=5000)
