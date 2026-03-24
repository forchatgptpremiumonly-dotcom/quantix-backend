from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ΤΟ CONNECTION STRING ΣΟΥ
MONGO_URI = "mongodb+srv://forchatgptpremiumonly_db_user:e6WVHbswCyLIXVdP@cluster0.6tyqxdb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
BOT_API_TOKEN = os.environ.get("BOT_API_TOKEN", "quantix_super_secret_928374923")

client = MongoClient(MONGO_URI)
db = client['quantix_database']
users_col = db['users']
keys_col = db['keys']

def require_bot_auth():
    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {BOT_API_TOKEN}":
        return False, (jsonify({"success": False, "error": "Unauthorized"}), 401)
    return True, None

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "message": "Backend is running on MongoDB"}), 200

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    key = str(data.get("key", "")).upper().strip()

    if not username or not password or not key:
        return jsonify({"success": False, "error": "Fill all fields"}), 400

    if users_col.find_one({"username": username}):
        return jsonify({"success": False, "error": "Username exists"}), 400

    key_data = keys_col.find_one({"license_key": key})
    if not key_data:
        return jsonify({"success": False, "error": "Invalid key"}), 400
    if key_data.get("used") == 1:
        return jsonify({"success": False, "error": "Key already used"}), 400
    if key_data.get("expires_at") < int(time.time()):
        return jsonify({"success": False, "error": "Key expired"}), 400

    now = int(time.time())
    users_col.insert_one({
        "username": username,
        "password_hash": generate_password_hash(password),
        "license_key": key,
        "created_at": now
    })

    keys_col.update_one(
        {"license_key": key},
        {"$set": {"used": 1, "used_by_username": username, "used_at": now}}
    )

    return jsonify({"success": True, "message": "Account created"}), 200

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    user = users_col.find_one({"username": username})
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid login"}), 401

    key_info = keys_col.find_one({"license_key": user["license_key"]})
    if not key_info or key_info["expires_at"] < int(time.time()):
        return jsonify({"success": False, "error": "License expired or invalid"}), 403

    return jsonify({
        "success": True, 
        "user": {"username": username, "license_key": user["license_key"]}
    }), 200

# BOT API
@app.route("/api/bot/add_key", methods=["POST"])
def bot_add_key():
    ok, err = require_bot_auth()
    if not ok: return err
    data = request.get_json(silent=True) or {}
    
    if keys_col.find_one({"license_key": data.get("license_key")}):
        return jsonify({"success": False, "error": "Key exists"}), 409

    keys_col.insert_one({
        "license_key": data.get("license_key"),
        "user_id": data.get("user_id"),
        "added_by": data.get("added_by"),
        "expires_at": int(data.get("expires_at")),
        "created_at": int(data.get("created_at")),
        "used": 0
    })
    return jsonify({"success": True}), 201

@app.route("/api/bot/info_keys", methods=["GET"])
def bot_info_keys():
    ok, err = require_bot_auth()
    if not ok: return err
    all_keys = list(keys_col.find({}, {"_id": 0}))
    return jsonify({"success": True, "keys": all_keys}), 200

@app.route("/api/bot/user_key/<user_id>", methods=["GET"])
def bot_user_key(user_id):
    ok, err = require_bot_auth()
    if not ok: return err
    key = keys_col.find_one({"user_id": str(user_id)}, {"_id": 0})
    if not key: return jsonify({"success": False}), 404
    return jsonify({"success": True, "key": key}), 200

@app.route("/api/bot/delete_key", methods=["POST"])
def bot_delete_key():
    ok, err = require_bot_auth()
    if not ok: return err
    key = request.get_json().get("license_key")
    keys_col.delete_one({"license_key": key})
    return jsonify({"success": True}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
