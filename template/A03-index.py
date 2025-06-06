from flask import Flask, request, jsonify, render_template
import sqlite3
import os

app = Flask(__name__)


# Khởi tạo database SQLite
def init_db():
    if os.path.exists("../users.db"):
        os.remove("../users.db")

    conn = sqlite3.connect("../users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL
        )
    """)
    sample_users = [
        ("alice", "alice@example.com"),
        ("bob", "bob@example.com"),
        ("charlie", "charlie@example.com")
    ]
    cursor.executemany("INSERT OR IGNORE INTO users (username, email) VALUES (?, ?)", sample_users)
    conn.commit()
    conn.close()


init_db()


# Tìm kiếm người dùng - Phiên bản không an toàn (SQL Injection)
@app.route("/search/insecure", methods=["GET"])
def search_insecure():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Missing username parameter"}), 400

    conn = sqlite3.connect("../users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()
    if not results:
        return jsonify({"message": "No users found"}), 404

    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in results]
    return jsonify(users)


# Tìm kiếm người dùng - Phiên bản an toàn (Parameterized Query)
@app.route("/search/secure", methods=["GET"])
def search_secure():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Missing username parameter"}), 400

    conn = sqlite3.connect("../users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    try:
        cursor.execute(query, (username,))
        results = cursor.fetchall()
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

    conn.close()
    if not results:
        return jsonify({"message": "No users found"}), 404

    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in results]
    return jsonify(users)


# Route chính với giao diện web
@app.route("/", methods=["GET"])
def index():
    username = request.args.get("username", "")
    mode = request.args.get("mode", "insecure")
    users = None
    error = None
    message = None

    if username:
        conn = sqlite3.connect("../users.db")
        cursor = conn.cursor()

        if mode == "insecure":
            # Phiên bản không an toàn
            query = f"SELECT * FROM users WHERE username = '{username}'"
            try:
                cursor.execute(query)
                results = cursor.fetchall()
            except sqlite3.Error as e:
                error = str(e)
                results = None
        else:
            # Phiên bản an toàn
            query = "SELECT * FROM users WHERE username = ?"
            try:
                cursor.execute(query, (username,))
                results = cursor.fetchall()
            except sqlite3.Error as e:
                error = str(e)
                results = None

        conn.close()

        if results:
            users = [{"id": row[0], "username": row[1], "email": row[2]} for row in results]
        elif not error:
            message = "No users found"

    return render_template("index.html", username=username, mode=mode, users=users, error=error, message=message)


if __name__ == "__main__":
    app.run(debug=True, port=5000)