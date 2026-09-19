import hashlib
import os
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "users.db")

# intentional TP: hardcoded live-looking secret (Semgrep p/secrets + Trivy secret scanner)
STRIPE_KEY = "sk_live_51H8xk2Jz9abcdefghijklmnopqrstuvwxyz0123"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT OR IGNORE INTO users (id, name, email) VALUES (1, 'ken', 'ken@example.com')")
    conn.commit()
    conn.close()


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    # intentional TP: SQL injection via string formatting
    row = conn.execute("SELECT id, name, email FROM users WHERE name = '%s'" % name).fetchone()
    conn.close()
    return jsonify(row)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # intentional TP: command injection (shell=True + user input)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # intentional TP: SSRF (user-controlled URL, no allowlist)
    r = requests.get(url, timeout=3)
    return r.text[:200]


@app.route("/config", methods=["POST"])
def load_config():
    # SafeLoader is used -> if a rule flags this, it is a FP
    cfg = yaml.load(request.data, Loader=yaml.SafeLoader)
    return jsonify(cfg)


def cache_key(payload: bytes) -> str:
    # md5 as a non-security cache key -> SAST flags "insecure hash" (FP in context)
    return hashlib.md5(payload).hexdigest()


def retry_jitter() -> float:
    # random used for backoff jitter, not for security (FP in context)
    return random.random() * 0.5


@app.route("/debug/eval")
def debug_eval():
    expr = request.args.get("expr", "1+1")
    # intentional TP (added in PR #1): eval() on user input -> RCE
    return str(eval(expr))


@app.route("/health")
def health():
    return jsonify({"key": cache_key(b"health"), "jitter": retry_jitter()})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
