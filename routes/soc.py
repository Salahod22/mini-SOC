from flask import Blueprint, render_template, jsonify
from utils import get_logs_and_threats

soc_bp = Blueprint('soc_bp', __name__, url_prefix='/soc')

@soc_bp.route('/')
def dashboard():
    # The Web UI Victim Dashboard
    logs, threats = get_logs_and_threats()
    return render_template('victim.html', logs=logs[:100], threats=threats)

@soc_bp.route('/api/data')
def api_data():
    # JSON Endpoint for Real-Time Updates
    logs, threats = get_logs_and_threats()
    return jsonify({
        'logs': logs[:50], 
        'threats': threats
    })
