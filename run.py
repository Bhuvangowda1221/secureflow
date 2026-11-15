"""
SecureFlow Application Entry Point
Run with: python run.py
"""
import os
import sys

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print("=" * 56)
    print("  SecureFlow DevSecOps Platform  v1.0.0")
    print("  Detect Early. Secure Always. Deploy Confidently.")
    print("=" * 56)
    print(f"  Dashboard : http://localhost:{port}")
    print(f"  Admin     : admin@secureflow.local / Admin@SecureFlow1")
    print(f"  Debug     : {debug}")
    print("=" * 56)
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
