from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import os
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Environment Variables από το Render
DATABASE_URL = os.environ.get("DATABASE_URL")
BOT_API_TOKEN = os.environ.get("BOT_API_TOKEN", "")

# Connection Pool για μέγιστη ταχύτητα και αντοχή
try:
    db_pool = psycopg2.pool.SimpleConnectionPool(1, 10, dsn=DATABASE_URL)
except Exception as e:
    print(f"FAILED TO CONNECT TO DB: {e}")

def get_db_conn():
    return db_pool.getconn()

def release_db_conn(conn):
    db_pool.putconn(conn)

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    # Δημιουργία πινάκων σε PostgreSQL format
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            license_key TEXT,
            created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id SERIAL PRIMARY KEY,
            license_key TEXT NOT NULL UNIQUE,
            user_id TEXT,
            added_by TEXT,
            expires_at BIGINT NOT NULL,
            created_at BIGINT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            used_by_username TEXT,
            used_at BIGINT
        )
    """)
    conn.commit()
    cur.close()
    release_db_conn(conn)

def require_bot_auth():
    auth_header = request.headers.get("Authorization", "")
    if not BOT_API_TOKEN or auth_header != f"Bearer {BOT_API_TOKEN}":
        return False, (jsonify({"success": False, "error": "Unauthorized"}), 401)
    return True, None

def get_user_status(username):
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if not user or not user["license_key"]:
            return {"exists": False, "valid": False, "error": "User/License not found"}

        cur.execute("SELECT * FROM keys WHERE license_key = %s", (user["license_key"],))
        key_row = cur.fetchone()
        
        if not key_row: return {"exists": True, "valid": False, "error": "Key deleted"}
        if key_row["expires_at"] < int(time.time()): return {"exists": True, "valid": False, "error": "Expired"}
        
        return {"exists": True, "valid": True, "license_key": user["license_key"], "expires_at": key_row["expires_at"]}
    finally:
        cur.close()
        release_db_conn(conn)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "message": "Backend is online"}), 200

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username, password, key = str(data.get("username", "")).strip(), str(data.get("password", "")).strip(), str(data.get("key", "")).upper().strip()

    if not username or not password or len(key) != 16:
        return jsonify({"success": False, "error": "Invalid input/key"}), 400

    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM keys WHERE license_key = %s", (key,))
        k = cur.fetchone()
        if not k or k["used"] == 1 or k["expires_at"] < int(time.time()):
            return jsonify({"success": False, "error": "Key invalid/used/expired"}), 400

        cur.execute("BEGIN") # Ταυτόχρονη εγγραφή χρήστη και "κάψιμο" κλειδιού
        now = int(time.time())
        cur.execute("INSERT INTO users (username, password_hash, created_at, license_key) VALUES (%s,%s,%s,%s)", 
                    (username, generate_password_hash(password), now, key))
        cur.execute("UPDATE keys SET used=1, used_by_username=%s, used_at=%s WHERE license_key=%s", (username, now, key))
        conn.commit()
        return jsonify({"success": True}), 200
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"success": False, "error": "User already exists"}), 400
    finally:
        cur.close()
        release_db_conn(conn)

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    u, p = str(data.get("username", "")).strip(), str(data.get("password", "")).strip()
    
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM users WHERE username = %s", (u,))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], p):
            status = get_user_status(u)
            if not status["valid"]: return jsonify({"success": False, "error": status["error"]}), 403
            return jsonify({"success": True, "user": {"id": user["id"], "username": u, "license_key": user["license_key"]}}), 200
        return jsonify({"success": False, "error": "Invalid login"}), 401
    finally:
        cur.close()
        release_db_conn(conn)

# --- BOT API ENDPOINTS ---

@app.route("/api/bot/add_key", methods=["POST"])
def bot_add_key():
    ok, err = require_bot_auth()
    if not ok: return err
    data = request.get_json(silent=True) or {}
    
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO keys (license_key, user_id, added_by, expires_at, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (data.get("license_key"), data.get("user_id"), data.get("added_by"), data.get("expires_at"), data.get("created_at")))
        conn.commit()
        return jsonify({"success": True}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        cur.close()
        release_db_conn(conn)

@app.route("/api/bot/delete_key", methods=["POST"])
def bot_delete_key():
    ok, err = require_bot_auth()
    if not ok: return err
    key = request.get_json().get("license_key")
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM keys WHERE license_key = %s", (key,))
    conn.commit()
    cur.close()
    release_db_conn(conn)
    return jsonify({"success": True}), 200

@app.route("/api/bot/info_keys", methods=["GET"])
def bot_info_keys():
    ok, err = require_bot_auth()
    if not ok: return err
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM keys ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    release_db_conn(conn)
    return jsonify({"success": True, "keys": rows}), 200

@app.route("/api/bot/user_key/<user_id>", methods=["GET"])
def bot_user_key(user_id):
    ok, err = require_bot_auth()
    if not ok: return err
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM keys WHERE user_id = %s LIMIT 1", (user_id,))
    row = cur.fetchone()
    cur.close()
    release_db_conn(conn)
    return jsonify({"success": True, "key": row}) if row else (jsonify({"success": False}), 404)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
