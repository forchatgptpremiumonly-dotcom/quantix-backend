from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

DB_FILE = os.environ.get("DB_FILE", "users.db")
BOT_API_TOKEN = os.environ.get("BOT_API_TOKEN", "")


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cur, table_name, column_name):
    cur.execute(f"PRAGMA table_info({table_name})")
    columns = cur.fetchall()
    return any(col["name"] == column_name for col in columns)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL UNIQUE,
            user_id TEXT,
            added_by TEXT,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            used_by_username TEXT,
            used_at INTEGER
        )
    """)

    if not column_exists(cur, "users", "license_key"):
        cur.execute("ALTER TABLE users ADD COLUMN license_key TEXT")

    conn.commit()
    conn.close()


def require_bot_auth():
    auth_header = request.headers.get("Authorization", "")
    expected = f"Bearer {BOT_API_TOKEN}"

    if not BOT_API_TOKEN:
        return False, (
            jsonify({"success": False, "error": "BOT_API_TOKEN is not configured on server"}),
            500
        )

    if auth_header != expected:
        return False, (
            jsonify({"success": False, "error": "Unauthorized"}),
            401
        )

    return True, None


def get_user_and_license_status(username: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, license_key
        FROM users
        WHERE username = ?
    """, (username,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return {"exists": False, "valid": False, "error": "User not found"}

    license_key = user["license_key"]
    if not license_key:
        conn.close()
        return {"exists": True, "valid": False, "error": "No license assigned"}

    cur.execute("""
        SELECT license_key, expires_at, used
        FROM keys
        WHERE license_key = ?
    """, (license_key,))
    key_row = cur.fetchone()
    conn.close()

    if not key_row:
        return {"exists": True, "valid": False, "error": "License key deleted"}

    now = int(time.time())
    if key_row["expires_at"] < now:
        return {"exists": True, "valid": False, "error": "License expired"}

    return {
        "exists": True,
        "valid": True,
        "error": None,
        "license_key": license_key,
        "expires_at": key_row["expires_at"]
    }


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

    cur.execute("""
        SELECT id, license_key, expires_at, used
        FROM keys
        WHERE license_key = ?
    """, (key,))
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
    now = int(time.time())

    cur.execute("""
        INSERT INTO users (username, password_hash, created_at, license_key)
        VALUES (?, ?, ?, ?)
    """, (username, password_hash, now, key))

    cur.execute("""
        UPDATE keys
        SET used = 1,
            used_by_username = ?,
            used_at = ?
        WHERE id = ?
    """, (username, now, key_row["id"]))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Account created successfully"}), 200


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({"success": False, "error": "Fill all fields"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, password_hash, license_key
        FROM users
        WHERE username = ?
    """, (username,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "error": "Invalid login"}), 401

    if not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid login"}), 401

    license_status = get_user_and_license_status(username)
    if not license_status["valid"]:
        return jsonify({
            "success": False,
            "error": license_status["error"] or "License invalid"
        }), 403

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "license_key": user["license_key"]
        }
    }), 200


@app.route("/api/check_access/<username>", methods=["GET"])
def check_access(username):
    username = str(username).strip()

    if not username:
        return jsonify({"success": False, "valid": False, "error": "Username is required"}), 400

    status = get_user_and_license_status(username)

    if not status["exists"]:
        return jsonify({"success": False, "valid": False, "error": status["error"]}), 404

    if not status["valid"]:
        return jsonify({"success": False, "valid": False, "error": status["error"]}), 403

    return jsonify({
        "success": True,
        "valid": True,
        "license_key": status["license_key"],
        "expires_at": status["expires_at"]
    }), 200


@app.route("/api/bot/add_key", methods=["POST"])
def bot_add_key():
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    data = request.get_json(silent=True) or {}

    license_key = str(data.get("license_key", "")).upper().strip()
    user_id = str(data.get("user_id", "")).strip()
    added_by = str(data.get("added_by", "")).strip()
    expires_at = data.get("expires_at")
    created_at = data.get("created_at")

    if not license_key or not user_id or not added_by or expires_at is None or created_at is None:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    try:
        expires_at = int(expires_at)
        created_at = int(created_at)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid timestamp values"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM keys WHERE license_key = ?", (license_key,))
    existing_key = cur.fetchone()
    if existing_key:
        conn.close()
        return jsonify({"success": False, "error": "Key already exists"}), 409

    cur.execute("SELECT id FROM keys WHERE user_id = ?", (user_id,))
    existing_user_key = cur.fetchone()
    if existing_user_key:
        conn.close()
        return jsonify({"success": False, "error": "This user already has a key"}), 409

    cur.execute("""
        INSERT INTO keys (
            license_key, user_id, added_by, expires_at, created_at, used
        ) VALUES (?, ?, ?, ?, ?, 0)
    """, (license_key, user_id, added_by, expires_at, created_at))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Key added"}), 201


@app.route("/api/bot/update_key", methods=["POST"])
def bot_update_key():
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    data = request.get_json(silent=True) or {}

    license_key = str(data.get("license_key", "")).upper().strip()
    expires_at = data.get("expires_at")

    if not license_key or expires_at is None:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    try:
        expires_at = int(expires_at)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid expires_at"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM keys WHERE license_key = ?", (license_key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Key not found"}), 404

    cur.execute("""
        UPDATE keys
        SET expires_at = ?
        WHERE license_key = ?
    """, (expires_at, license_key))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Key updated"}), 200


@app.route("/api/bot/delete_key", methods=["POST"])
def bot_delete_key():
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    data = request.get_json(silent=True) or {}
    license_key = str(data.get("license_key", "")).upper().strip()

    if not license_key:
        return jsonify({"success": False, "error": "Missing license_key"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM keys WHERE license_key = ?", (license_key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Key not found"}), 404

    cur.execute("DELETE FROM keys WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Key deleted"}), 200


@app.route("/api/bot/info_key/<license_key>", methods=["GET"])
def bot_info_key(license_key):
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    license_key = str(license_key).upper().strip()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            license_key,
            user_id,
            added_by,
            expires_at,
            created_at,
            used,
            used_by_username,
            used_at
        FROM keys
        WHERE license_key = ?
    """, (license_key,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Key not found"}), 404

    return jsonify({
        "success": True,
        "key": {
            "license_key": row["license_key"],
            "user_id": row["user_id"],
            "added_by": row["added_by"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "used": row["used"],
            "used_by_username": row["used_by_username"],
            "used_at": row["used_at"]
        }
    }), 200


@app.route("/api/bot/info_keys", methods=["GET"])
def bot_info_keys():
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            license_key,
            user_id,
            added_by,
            expires_at,
            created_at,
            used,
            used_by_username,
            used_at
        FROM keys
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()

    return jsonify({
        "success": True,
        "keys": [
            {
                "license_key": row["license_key"],
                "user_id": row["user_id"],
                "added_by": row["added_by"],
                "expires_at": row["expires_at"],
                "created_at": row["created_at"],
                "used": row["used"],
                "used_by_username": row["used_by_username"],
                "used_at": row["used_at"]
            }
            for row in rows
        ]
    }), 200


@app.route("/api/bot/user_key/<user_id>", methods=["GET"])
def bot_user_key(user_id):
    ok, error_response = require_bot_auth()
    if not ok:
        return error_response

    user_id = str(user_id).strip()

    if not user_id:
        return jsonify({"success": False, "error": "Missing user_id"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            license_key,
            user_id,
            added_by,
            expires_at,
            created_at,
            used,
            used_by_username,
            used_at
        FROM keys
        WHERE user_id = ?
        LIMIT 1
    """, (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Key not found"}), 404

    return jsonify({
        "success": True,
        "key": {
            "license_key": row["license_key"],
            "user_id": row["user_id"],
            "added_by": row["added_by"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "used": row["used"],
            "used_by_username": row["used_by_username"],
            "used_at": row["used_at"]
        }
    }), 200


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
