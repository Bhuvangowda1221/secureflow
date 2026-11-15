"""
Secure Flask application — demonstrates security best practices.
This version fixes all vulnerabilities from the vulnerable demo.
"""
import os
import secrets
import sqlite3
from flask import Flask, request, escape, abort
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

app = Flask(__name__)
# Secure: secret key from environment variable
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


# Secure password hashing with bcrypt/PBKDF2 (not MD5)
def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256:260000")


def verify_password(password: str, hash_: str) -> bool:
    return check_password_hash(hash_, password)


# Parameterized query — prevents SQL injection
def get_user(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # SECURE: parameterized query with placeholder
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


# XSS-safe output — escape user input
@app.route("/search")
def search():
    query = request.args.get("q", "")
    safe_query = escape(query)
    return f"<h1>Search results for: {safe_query}</h1>"


# No command injection — whitelist of allowed hosts
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "example.com"}

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    if host not in ALLOWED_HOSTS:
        abort(400, "Host not allowed")
    import subprocess
    # SECURE: list form, no shell=True
    result = subprocess.run(["ping", "-n", "1", host],
                            capture_output=True, text=True, timeout=5)
    return f"<pre>{escape(result.stdout)}</pre>"


# No insecure deserialization — use JSON instead
@app.route("/load", methods=["POST"])
def load_data():
    import json
    try:
        data = request.get_json(force=True)
        return str(data)
    except Exception:
        abort(400, "Invalid JSON")


# No eval — safe expression evaluation with ast.literal_eval
@app.route("/calc")
def calc():
    import ast
    expression = request.args.get("expr", "1+1")
    try:
        # SECURE: literal_eval only accepts literals, not arbitrary code
        result = ast.literal_eval(expression)
        if not isinstance(result, (int, float)):
            raise ValueError("Only numeric expressions allowed")
        return str(result)
    except Exception:
        abort(400, "Invalid expression")


# Cryptographically secure token
@app.route("/token")
def generate_token():
    # SECURE: secrets module for cryptographic randomness
    token = secrets.token_urlsafe(32)
    return token


# YAML safe_load — prevents YAML deserialization attacks
@app.route("/config", methods=["POST"])
def load_config():
    import yaml
    config_data = request.get_data(as_text=True)
    try:
        # SECURE: yaml.safe_load restricts to safe types
        config = yaml.safe_load(config_data)
        return str(config)
    except yaml.YAMLError:
        abort(400, "Invalid YAML")


@app.route("/")
def index():
    return "<h1>Secure Demo App</h1><p>All vulnerabilities fixed!</p>"


if __name__ == "__main__":
    # SECURE: debug=False in production
    app.run(debug=False, host="127.0.0.1")
