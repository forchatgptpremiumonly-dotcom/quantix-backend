from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os
import time
import urllib.parse
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ΣΤΟΙΧΕΙΑ ΣΥΝΔΕΣΗΣ - ΤΑ ΒΑΖΟΥΜΕ ΚΑΘΑΡΑ
raw_user = "forchatgptpremiumonly_db_user"
raw_pass = "e6WVHbswCyLlXVdP" # Σιγουρέψου ότι αυτό είναι το τρέχον password στο MongoDB Atlas
cluster_url = "cluster0.6tyqxdb.mongodb.net"
db_name = "quantix_database"

# Κωδικοποίηση για να μην "σπάει" το URL
safe_user = urllib.parse.quote_plus(raw_user)
safe_pass = urllib.parse.quote_plus(raw_pass)

MONGO_URI = f"mongodb+srv://{safe_user}:{safe_pass}@{cluster_url}/{db_name}?retryWrites=true&w=majority&appName=Cluster0"

# ΣΥΝΔΕΣΗ ΜΕ ΤΗ ΒΑΣΗ
try:
    # Προσθήκη ρυθμίσεων για να μην αποτυγχάνει το TLS/SSL στο Render
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, tlsAllowInvalidCertificates=True)
    db = client[db_name]
    users_col = db['users']
    keys_col = db['keys']
    # Test connection
    client.admin.command('ping')
    print("--- SUCCESS: CONNECTED TO MONGODB ATLAS ---")
except Exception as e:
    print(f"--- DATABASE CONNECTION ERROR: {e} ---")

BOT_API_TOKEN = os.environ.get("BOT_API_TOKEN", "quantix_super_secret_928374923")

def require_bot_auth():
    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {BOT_API_TOKEN}":
        return False, (jsonify({"success": False, "error": "Unauthorized"}), 401)
    return True, None

@app.route("/api/health")
def health():
    return jsonify({"success": True, "status": "Stable"}), 200

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    u, p, k = str(data.get("username", "")).strip(), str(data.get("password", "")).strip(), str(data.get("key", "")).upper().strip()
    if not u or not p or not k: return jsonify({"success": False, "error": "Missing fields"}), 400
    if users_col.find_one({"username": u}): return jsonify({"success": False, "error": "User exists"}), 400
    key_data = keys_col.find_one({"license_key": k})
    if not key_data or key_data.get("used") == 1 or key_data.get("expires_at") < int(time.time()):
        return jsonify({"success": False, "error": "Key invalid/used/expired"}), 400
    now = int(time.time())
    users_col.insert_one({"username": u, "password_hash": generate_password_hash(p), "license_key": k, "created_at": now})
    keys_col.update_one({"license_key": k}, {"$set": {"used": 1, "used_by_username": u, "used_at": now}})
    return jsonify({"success": True}), 200

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    u, p = str(data.get("username", "")).strip(), str(data.get("password", "")).strip()
    user = users_col.find_one({"username": u})
    if user and check_password_hash(user["password_hash"], p):
        key = keys_col.find_one({"license_key": user["license_key"]})
        if not key or key["expires_at"] < int(time.time()): return jsonify({"success": False, "error": "Expired"}), 403
        return jsonify({"success": True, "user": {"username": u, "key": user["license_key"]}}), 200
    return jsonify({"success": False, "error": "Invalid auth"}), 401

# BOT API
@app.route("/api/bot/add_key", methods=["POST"])
def bot_add_key():
    ok, err = require_bot_auth(); 
    if not ok: return err
    data = request.get_json()
    keys_col.insert_one({
        "license_key": data.get("license_key"), "user_id": str(data.get("user_id")),
        "added_by": str(data.get("added_by")), "expires_at": int(data.get("expires_at")),
        "created_at": int(data.get("created_at")), "used": 0
    })
    return jsonify({"success": True}), 201

@app.route("/api/bot/info_keys", methods=["GET"])
def bot_info_keys():
    ok, err = require_bot_auth(); 
    if not ok: return err
    return jsonify({"success": True, "keys": list(keys_col.find({}, {"_id": 0}))}), 200

@app.route("/api/bot/user_key/<user_id>", methods=["GET"])
def bot_user_key(user_id):
    ok, err = require_bot_auth(); 
    if not ok: return err
    k = keys_col.find_one({"user_id": str(user_id)}, {"_id": 0})
    return jsonify({"success": True, "key": k}) if k else (jsonify({"success": False}), 404)

@app.route("/api/bot/info_key/<license_key>", methods=["GET"])
def bot_info_key(license_key):
    ok, err = require_bot_auth(); 
    if not ok: return err
    k = keys_col.find_one({"license_key": license_key.upper()}, {"_id": 0})
    return jsonify({"success": True, "key": k}) if k else (jsonify({"success": False}), 404)

@app.route("/api/bot/update_key", methods=["POST"])
def bot_update_key():
    ok, err = require_bot_auth(); 
    if not ok: return err
    data = request.get_json()
    keys_col.update_one({"license_key": data.get("license_key")}, {"$set": {"expires_at": int(data.get("expires_at"))}})
    return jsonify({"success": True}), 200

@app.route("/api/bot/delete_key", methods=["POST"])
def bot_delete_key():
    ok, err = require_bot_auth(); 
    if not ok: return err
    keys_col.delete_one({"license_key": request.get_json().get("license_key")})
    return jsonify({"success": True}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
