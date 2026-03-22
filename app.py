from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

DB_FILE = "users.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "message": "Backend is running"}), 200


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    key = str(data.get("key", "")).upper().strip()

    if not username or not password or not key:
        return jsonify({"success": False, "error": "Fill all fields"}), 400

    if len(key) != 16:
        return jsonify({"success": False, "error": "Invalid key format"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Username exists"}), 400

    cur.execute(
        "SELECT id, expires_at, used FROM keys WHERE license_key = ?",
        (key,)
    )
    key_row = cur.fetchone()

    if not key_row:
        conn.close()
        return jsonify({"success": False, "error": "Invalid key"}), 400

    if key_row["used"] == 1:
        conn.close()
        return jsonify({"success": False, "error": "Key already used"}), 400

    if key_row["expires_at"] < int(time.time()):
        conn.close()
        return jsonify({"success": False, "error": "Key expired"}), 400

    password_hash = generate_password_hash(password)

    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )

    cur.execute(
        "UPDATE keys SET used = 1 WHERE id = ?",
        (key_row["id"],)
    )

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,)
    )
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "error": "Invalid login"}), 401

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid login"}), 401

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    })


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)