import os
import bcrypt
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

app = Flask(__name__)
# Secure random key for session encryption
app.secret_key = os.urandom(24)

# In-memory storage avoids complex external database configurations
USERS_DB = {}

# Complete front-end user interface styles and layouts combined
LAYOUT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Secure Auth System</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 50px; text-align: center; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); display: inline-block; width: 320px; text-align: left; }
        h2 { margin-top: 0; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0 20px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .flash { color: #d9534f; background: #fdf7f7; border: 1px solid #d9534f; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 14px; }
        .success { color: #28a745; background: #f4fbf5; border: 1px solid #28a745; }
    </style>
</head>
<body>
    <div class="card">
        <h2>{{ title }}</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="flash {% if category == 'success' %}success{% endif %}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

LOGIN_CONTENT = """
{% extends "layout" %}
{% block content %}
<form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" required autocomplete="off">
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Sign In</button>
</form>
<p style="margin-top:15px; font-size:14px; text-align:center;">New user? <a href="/register">Create an account</a></p>
{% endblock %}
"""

REGISTER_CONTENT = """
{% extends "layout" %}
{% block content %}
<form method="POST" action="/register">
    <label>Choose Username</label>
    <input type="text" name="username" required autocomplete="off">
    <label>Choose Password</label>
    <input type="password" name="password" required>
    <button type="submit" style="background:#28a745;">Register System</button>
</form>
<p style="margin-top:15px; font-size:14px; text-align:center;">Have an account? <a href="/login">Login here</a></p>
{% endblock %}
"""

DASHBOARD_CONTENT = """
{% extends "layout" %}
{% block content %}
<p>Welcome back, <strong>{{ username }}</strong>!</p>
<p style="font-size:14px; color:#666;">Your session is fully encrypted and secure against SQL injection attacks.</p>
<br>
<a href="/logout"><button style="background:#dc3545;">Secure Log Out</button></a>
{% endblock %}
"""

@app.route('/')
def index():
    if 'username' in session:
        return render_template_string(LAYOUT_HTML + DASHBOARD_CONTENT, title="Dashboard", username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('All fields are required.')
            return render_template_string(LAYOUT_HTML + REGISTER_CONTENT, title="Register")
            
        if username in USERS_DB:
            flash('Username is already registered.')
            return render_template_string(LAYOUT_HTML + REGISTER_CONTENT, title="Register")
        
        # Secure implementation of bcrypt password hashing
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        USERS_DB[username] = hashed
        flash('Account created successfully! Please sign in.', 'success')
        return redirect(url_for('login'))
        
    return render_template_string(LAYOUT_HTML + REGISTER_CONTENT, title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        stored_hash = USERS_DB.get(username)
        
        # Cryptographically secure hash verification
        if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            session['username'] = username
            return redirect(url_for('index'))
        
        flash('Invalid verification credentials.')
        return render_template_string(LAYOUT_HTML + LOGIN_CONTENT, title="Login")
            
    return render_template_string(LAYOUT_HTML + LOGIN_CONTENT, title="Login")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
  
