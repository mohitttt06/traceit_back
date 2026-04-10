import os
import psycopg2
import psycopg2.extras
import bcrypt

DATABASE_URL = os.getenv("DATABASE_URL")  # ✅ just the variable NAME
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set!")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')  # ✅ SSL required for Render
    return conn

def get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

def init_db():
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registered_content (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            name TEXT,
            filename TEXT,
            phash TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flagged_content (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            source_url TEXT,
            matched_filename TEXT,
            phash TEXT,
            flagged_at TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

init_db()
