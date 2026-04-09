from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from database import get_db, init_db, hash_password, verify_password
from hasher import generate_hash
from scheduler import start_scheduler
import os
import uuid
import jwt
import datetime
import psycopg2

load_dotenv()

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

init_db()

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")


# ── AUTH HELPER ────────────────────────────────────────────────────
def get_current_user(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except Exception:
        return None


# ── SIGNUP ─────────────────────────────────────────────────────────
@app.route("/auth/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
            (email, hash_password(password))
        )
        user_id = cursor.fetchone()["id"]  # postgres returns id via RETURNING
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        conn.close()
        return jsonify({"error": "Email already registered"}), 409
    finally:
        cursor.close()
        conn.close()

    token = jwt.encode(
        {
            "user_id": user_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    return jsonify({"token": token, "user_id": user_id}), 201


# ── LOGIN ──────────────────────────────────────────────────────────
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            "user_id": user["id"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
        },
        JWT_SECRET,
        algorithm="HS256"
    )
    return jsonify({"token": token, "user_id": user["id"]}), 200


# ── REGISTER OFFICIAL CONTENT ──────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register_content():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    name = request.form.get("name", file.filename)

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = f"{uuid.uuid4()}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    phash = generate_hash(filepath)
    if not phash:
        return jsonify({"error": "Could not generate hash for this image"}), 500

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO registered_content (user_id, name, filename, phash) VALUES (%s, %s, %s, %s) RETURNING id",
        (user_id, name, filename, phash)
    )
    registered_id = cursor.fetchone()["id"]
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "message": "Content registered successfully",
        "id": registered_id,
        "name": name,
        "phash": phash
    }), 201


# ── GET ALL REGISTERED CONTENT ─────────────────────────────────────
@app.route("/api/registered", methods=["GET"])
def get_registered():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM registered_content WHERE user_id = %s ORDER BY uploaded_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200


# ── GET ALL FLAGGED CONTENT ────────────────────────────────────────
@app.route("/api/flagged", methods=["GET"])
def get_flagged():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM flagged_content WHERE user_id = %s ORDER BY flagged_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200


# ── UPDATE FLAG STATUS ─────────────────────────────────────────────
@app.route("/api/flagged/<int:flag_id>/status", methods=["PATCH"])
def update_status(flag_id):
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    new_status = data.get("status")

    allowed_statuses = ["Allowed", "Flagged", "Ignored"]
    if new_status not in allowed_statuses:
        return jsonify({"error": "Invalid status. Use Allowed, Flagged, or Ignored"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE flagged_content SET status = %s WHERE id = %s AND user_id = %s",
        (new_status, flag_id, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": f"Status updated to {new_status}"}), 200


# ── GET ANOMALIES ──────────────────────────────────────────────────
@app.route("/api/anomaly", methods=["GET"])
def get_anomalies():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM anomalies WHERE user_id = %s ORDER BY total_flags DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200


# ── SEED ANOMALY DATA FOR DEMO ─────────────────────────────────────
@app.route("/api/anomaly/seed", methods=["POST"])
def seed_anomaly():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    demo_anomalies = [
        {
            "content_name": "Virat Kohli Century Celebration",
            "total_flags": 47,
            "first_seen": "2025-04-04 08:12:00",
            "last_seen": "2025-04-04 09:10:00"
        },
        {
            "content_name": "IPL 2025 Official Poster",
            "total_flags": 31,
            "first_seen": "2025-04-04 10:00:00",
            "last_seen": "2025-04-04 10:45:00"
        },
        {
            "content_name": "Champions Trophy Final Highlight",
            "total_flags": 22,
            "first_seen": "2025-04-04 06:30:00",
            "last_seen": "2025-04-04 07:20:00"
        }
    ]

    conn = get_db()
    cursor = conn.cursor()
    for anomaly in demo_anomalies:
        cursor.execute("""
            INSERT INTO anomalies (user_id, content_name, total_flags, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, anomaly["content_name"], anomaly["total_flags"],
              anomaly["first_seen"], anomaly["last_seen"]))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Anomaly demo data seeded successfully"}), 201


# ── DASHBOARD STATS ────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) as total FROM registered_content WHERE user_id = %s",
        (user_id,)
    )
    registered = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(DISTINCT source_url) as total FROM flagged_content WHERE user_id = %s",
        (user_id,)
    )
    flagged = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(*) as total FROM flagged_content WHERE status = 'Pending' AND user_id = %s",
        (user_id,)
    )
    pending = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(*) as total FROM flagged_content WHERE status = 'Allowed' AND user_id = %s",
        (user_id,)
    )
    allowed = cursor.fetchone()["total"]

    cursor.execute(
        "SELECT COUNT(*) as total FROM anomalies WHERE user_id = %s",
        (user_id,)
    )
    anomalies = cursor.fetchone()["total"]

    cursor.close()
    conn.close()

    return jsonify({
        "registered_content": registered,
        "total_flags": flagged,
        "pending_review": pending,
        "marked_allowed": allowed,
        "active_anomalies": anomalies
    }), 200


# ── DELETE REGISTERED CONTENT ──────────────────────────────────────
@app.route("/api/registered/<int:content_id>", methods=["DELETE"])
def delete_registered(content_id):
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM registered_content WHERE id = %s AND user_id = %s",
        (content_id, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Content deleted successfully"}), 200


# ── START SCHEDULER & RUN ──────────────────────────────────────────
scheduler = start_scheduler()

if __name__ == "__main__":
    app.run(debug=True, port=5000, use_reloader=False)