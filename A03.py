from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# Khởi tạo database SQLite
def init_db():
    # Xóa file database cũ nếu tồn tại (cho demo)
    #if os.path.exists("users.db"):
        #os.remove("users.db")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Tạo bảng users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL
        )
    """)
    # Thêm dữ liệu mẫu
    sample_users = [
        ("alice", "alice@example.com"),
        ("bob", "bob@example.com"),
        ("charlie", "charlie@example.com")
    ]
    cursor.executemany("INSERT OR IGNORE INTO users (username, email) VALUES (?, ?)", sample_users)
    conn.commit()
    conn.close()

# Gọi hàm khởi tạo database khi khởi động
init_db()

# Tìm kiếm người dùng - Phiên bản không an toàn (SQL Injection)
@app.route("/search/insecure", methods=["GET"])
def search_insecure():
    """
    Lỗ hổng: Dữ liệu đầu vào được nối trực tiếp vào câu truy vấn SQL,
    cho phép kẻ tấn công chèn mã SQL độc hại.
    """
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Missing username parameter"}), 400  

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Lỗ hổng SQL Injection: Nối trực tiếp username vào query
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

    # Trả về kết quả (id, username, email)
    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in results]
    return jsonify(users)

# Tìm kiếm người dùng - Phiên bản an toàn (Parameterized Query)
@app.route("/search/secure", methods=["GET"])
def search_secure():
    """
    An toàn: Sử dụng parameterized query để ngăn chặn SQL Injection.
    """
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Missing username parameter"}), 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # An toàn: Sử dụng parameterized query
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

    # Trả về kết quả (id, username, email)
    users = [{"id": row[0], "username": row[1], "email": row[2]} for row in results]
    return jsonify(users)

# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A03:2021 - Injection Demo (SQL Injection)</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>Test the Demo with Postman</li>
    </ol>
    <p><strong>Postman Setup:</strong></p>
    <p>1. Finding user ( insecure - normal )</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/search/insecure?username=alice</li>
        <li>Expected Response: [{"id": 1, "username": "alice", "email": "alice@example.com"}] - Status 200 OK</li>
    </ol>
    <p>2. Attack SQL Injection ( Insecure )</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/search/insecure?username=' OR '1'='1</li>
        <li>Expected Response: Status 200 OK</li>
        <ul>
            <li> {"id": 1, "username": "alice", "email": "alice@example.com"},</li>
            <li> {"id": 2, "username": "bob", "email": "bob@example.com"},</li>
            <li> {"id": 3, "username": "charlie", "email": "charlie@example.com"}</li>
        </ul>
    </ol>
        <li>Vulnerability: The attacker injects ' OR '1'='1 into the query.</li>
        <li>SELECT * FROM users WHERE username = '' OR '1'='1'</li>
        <li>This causes the query to always return TRUE, exposing all the data.</li>
    <p>3. Try to attack SQL Injection ( secure )</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/search/secure?username=' OR '1'='1</li>
        <li>Expected Response: {"message": "No users found"} - Status 404 Not Found</li>
    </ol>
        <li>Safe: The parameterized query treats the input ' OR '1'='1 as a regular string, not as SQL code : SELECT * FROM users WHERE username = "' OR '1'='1'".</li>
        <li>There is no username that matches this string, so no results are returned.</li>
    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)