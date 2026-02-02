from flask import Flask, request, render_template, redirect, url_for
from database import init_db
from utils import append_log
import os

# Create App
app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session' # Needed for session management in Student Portal

# Initialize Database
if not os.path.exists('students.db'):
    init_db()

# Register Blueprints
from routes.victim import victim_bp
from routes.soc import soc_bp
from routes.attacker import attacker_bp

app.register_blueprint(victim_bp)
app.register_blueprint(soc_bp)
app.register_blueprint(attacker_bp)

# --- GLOBAL IDS SENSOR (Middleware) ---
@app.before_request
def log_request_info():
    # Exclude internal/static traffic from logging
    if request.path.startswith('/static') or request.path == '/favicon.ico':
        return
        
    # Exclude SOC and Attacker traffic from the logs (Self-Noise)
    # This prevents the dashboard's own polling (/soc/api/data) from triggering alerts or spamming logs
    if request.path.startswith('/soc') or request.path.startswith('/attacker'):
        return

    # Classify Traffic & Capture Payload
    action = 'HTTP_REQUEST'
    details = f"{request.method} {request.path} UA:{request.headers.get('User-Agent','')} "
    
    # 1. Login (Potential SQLi target)
    if request.path == '/portal/login' and request.method == 'POST':
        action = 'LOGIN_ATTEMPT'
        user = request.form.get('username', 'unknown')
        if user == 'admin' and "OR" in request.form.get('password', ''): # Simple heuristic for simulation
             details = f"User: {user} Payload: {request.form.get('password')}"
        else:
             details = f"Failed login: {user}"

    # 2. Search (Potential XSS target)
    elif request.path == '/portal/search':
        action = 'SEARCH_QUERY'
        query = request.args.get('q', '')
        if query:
            details = f"Query: {query}"
    
    src_ip = request.remote_addr 
    append_log(src_ip, 'Server', 5000, action, details)

# Root Route - Landing Page
@app.route('/')
def index():
    return render_template('index.html')

# --- LEGACY REDIRECTS (For backward compatibility) ---
@app.route('/login', methods=['GET', 'POST'])
def old_login():
    return redirect(url_for('victim_bp.login'))

@app.route('/search')
def old_search():
    return redirect(url_for('victim_bp.search'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
