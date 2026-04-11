from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from hasher import generate_hash
from database import get_db, get_cursor, init_db, hash_password, verify_password
import os
import uuid
import jwt
import datetime

load_dotenv()

app = Flask(__name__)
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Authorization", "Content-Type"],
     methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
     supports_credentials=False)
@app.route("/")
def index():
    return jsonify({"status": "ok"}), 200

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

JWT_SECRET = os.getenv("JWT_SECRET", "secret")

# ✅ safely init DB
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")

# 🔐 AUTH HELPER
def get_current_user(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except:
        return None

# SIGNUP
@app.route("/auth/signup", methods=["POST"])
def signup():
    data = request.get_json()
    conn = get_db()
    cursor = get_cursor(conn)
    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
            (data["email"], hash_password(data["password"]))
        )
        user_id = cursor.fetchone()["id"]
        conn.commit()
    except:
        conn.rollback()
        return jsonify({"error": "User exists"}), 400
    finally:
        cursor.close()
        conn.close()
    token = jwt.encode(
        {"user_id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
        JWT_SECRET, algorithm="HS256"
    )
    return jsonify({"token": token})

# LOGIN
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM users WHERE email=%s", (data["email"],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if not user or not verify_password(data["password"], user["password_hash"]):
        return jsonify({"error": "Invalid"}), 401
    token = jwt.encode(
        {"user_id": user["id"], "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
        JWT_SECRET, algorithm="HS256"
    )
    return jsonify({"token": token})

# REGISTER CONTENT
@app.route("/api/register", methods=["POST"])
def register():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    file = request.files["file"]
    name = request.form.get("name", file.filename)
    filename = str(uuid.uuid4()) + "_" + file.filename
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    phash = generate_hash(path)
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute(
        "INSERT INTO registered_content (user_id, name, filename, phash) VALUES (%s,%s,%s,%s)",
        (user_id, name, filename, phash)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "uploaded"})

# GET REGISTERED
@app.route("/api/registered", methods=["GET"])
def get_registered():
    user_id = get_current_user(request)
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM registered_content WHERE user_id=%s", (user_id,))
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

# GET FLAGGED
@app.route("/api/flagged", methods=["GET"])
def get_flagged():
    user_id = get_current_user(request)
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM flagged_content WHERE user_id=%s", (user_id,))
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

# STATS
@app.route("/api/stats", methods=["GET"])
def stats():
    user_id = get_current_user(request)
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("SELECT COUNT(*) as c FROM registered_content WHERE user_id=%s", (user_id,))
    registered = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(DISTINCT source_url) as c FROM flagged_content WHERE user_id=%s", (user_id,))
    flagged = cursor.fetchone()["c"]
    cursor.close()
    conn.close()
    return jsonify({"registered": registered, "flagged": flagged})


@app.route("/admin/users", methods=["GET"])
def get_users():
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("SELECT id, email FROM users")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route("/api/registered/bulk-delete", methods=["DELETE"])
def bulk_delete_registered():
    user_id = get_current_user(request)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "No ids provided"}), 400
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute(
        "DELETE FROM flagged_content WHERE registered_id = ANY(%s::int[]) AND user_id = %s",
        (ids, user_id)
    )
    cursor.execute(
        "DELETE FROM registered_content WHERE id = ANY(%s::int[]) AND user_id = %s",
        (ids, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": f"{len(ids)} fingerprints deleted"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
