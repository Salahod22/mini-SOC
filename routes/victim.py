from flask import Blueprint, render_template, request, redirect, url_for, session
from database import get_db_connection
import time

victim_bp = Blueprint('victim_bp', __name__, url_prefix='/portal')

@victim_bp.route('/')
def portal_home():
    if 'user_id' in session:
        return redirect(url_for('victim_bp.dashboard'))
    return redirect(url_for('victim_bp.login'))

@victim_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # --- VULNERABILITY: SQL INJECTION ---
        # The query string is constructed directly from user input
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            # Execute unsafe query
            c.execute(query) 
            user = c.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('victim_bp.dashboard'))
            else:
                error = "Invalid credentials."
        except Exception as e:
            conn.close()
            # In a real attack, seeing the error helps the attacker.
            error = f"Database Error: {str(e)}"
            
    return render_template('portal/login.html', error=error)

@victim_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('victim_bp.login'))
    
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students').fetchall()
    conn.close()
    
    return render_template('portal/dashboard.html', students=students, user=session.get('username'))

@victim_bp.route('/search')
def search():
    # --- VULNERABILITY: REFLECTED XSS ---
    query = request.args.get('q', '')
    
    results = []
    if query:
        conn = get_db_connection()
        # Using parameterized query here just to show mixed security, 
        # but the Output in the template will be Unescaped for XSS.
        results = conn.execute("SELECT * FROM students WHERE name LIKE ?", ('%' + query + '%',)).fetchall()
        conn.close()
        
    return render_template('portal/search.html', query=query, results=results)

@victim_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('victim_bp.login'))
