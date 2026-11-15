"""
Vulnerable Flask application — intentionally contains security issues
for demonstrating SecureFlow's scanning capabilities.

DO NOT USE IN PRODUCTION. This is for educational/demo purposes only.
"""
import os
import pickle
import subprocess
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for
import hashlib
import random
import yaml

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # B105: Hardcoded secret

# Hardcoded database credentials (B106)
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASS = "password123"  # noqa: S106 — intentional for demo
API_KEY = "sk-1234567890abcdef"  # noqa: S105 — intentional for demo

# Weak hashing (B303)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# SQL Injection vulnerability (B608)
def get_user(username):
    conn = sqlite3.connect("vulnerable.db")
    cursor = conn.cursor()
    # VULNERABLE: direct string formatting
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

@app.route("/")
def index():
    return render_template_string("""
    <h1>Vulnerable Demo App</h1>
    <p><a href='/login'>Login</a> | <a href='/admin'>Admin</a></p>
    """)

# XSS vulnerability (reflected)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: unescaped user input
    return f"<h1>Search results for: {query}</h1>"

# Command injection (B602)
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell injection
    result = subprocess.run(f"ping -n 1 {host}", shell=True,
                            capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre>"

# Insecure deserialization (B301)
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # VULNERABLE: pickle deserialization of user input
    obj = pickle.loads(data)
    return str(obj)

# eval() usage (B307)
@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    # VULNERABLE: eval on user input
    result = eval(expression)
    return str(result)

# Weak random (B311)
@app.route("/token")
def generate_token():
    # VULNERABLE: not cryptographically secure
    token = random.randint(100000, 999999)
    return str(token)

# YAML unsafe load (B506)
@app.route("/config", methods=["POST"])
def load_config():
    config_data = request.get_data(as_text=True)
    # VULNERABLE: yaml.load without Loader
    config = yaml.load(config_data)  # noqa
    return str(config)

# Debug mode enabled (B201)
if __name__ == "__main__":
    app.run(debug=True)  # B201: Flask debug enabled
