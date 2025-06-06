from flask import Flask, request, jsonify, session
import bcrypt
import os
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Mock database (in-memory)
users = [
    {"id": 1, "username": "alice", "password": "password123"},  # Plaintext (không an toàn)
    {"id": 2, "username": "bob", "password": "password456"}     # Plaintext (không an toàn)
]

# Tạo mật khẩu đã mã hóa bằng bcrypt cho phiên bản an toàn
users_secure = [
    {"id": 1, "username": "alice", "password": bcrypt.hashpw("password123".encode(), bcrypt.gensalt())},
    {"id": 2, "username": "bob", "password": bcrypt.hashpw("password456".encode(), bcrypt.gensalt())}
]

# Theo dõi số lần thử đăng nhập (chống brute force)
login_attempts = defaultdict(int)
MAX_ATTEMPTS = 5

# Helper function để tìm người dùng theo username
def get_user_by_username(username, user_list):
    for user in user_list:
        if user["username"] == username:
            return user
    return None

# Đăng nhập - Phiên bản không an toàn (Authentication Failures)
@app.route("/login/insecure", methods=["POST"])
def login_insecure():
    """
    Lỗ hổng: Authentication Failures
    1. Lưu mật khẩu dạng plaintext (không mã hóa).
    2. Không giới hạn số lần thử đăng nhập (dễ bị brute force).
    3. Trả về thông báo lỗi chi tiết, để lộ thông tin (ví dụ: username không tồn tại).
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    user = get_user_by_username(username, users)
    if not user:
        return jsonify({"error": "Username does not exist"}), 401  # Lỗi chi tiết

    if user["password"] != password:
        return jsonify({"error": "Incorrect password"}), 401  # Lỗi chi tiết

    session["user_id"] = user["id"]
    return jsonify({"message": f"Logged in as {username} (insecure)"})

# Đăng nhập - Phiên bản an toàn (Proper Authentication)
@app.route("/login/secure", methods=["POST"])
def login_secure():
    """
    An toàn: Áp dụng các biện pháp bảo mật
    1. Mã hóa mật khẩu bằng bcrypt.
    2. Giới hạn số lần thử đăng nhập (chống brute force).
    3. Trả về thông báo lỗi chung, không để lộ thông tin.
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Invalid credentials"}), 400

    username = data["username"]
    password = data["password"]

    # Kiểm tra số lần thử đăng nhập
    client_ip = request.remote_addr
    login_attempts[client_ip] += 1
    if login_attempts[client_ip] > MAX_ATTEMPTS:
        return jsonify({"error": "Too many login attempts, please try again later"}), 429

    user = get_user_by_username(username, users_secure)
    if not user or not bcrypt.checkpw(password.encode(), user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401  # Thông báo lỗi chung

    # Đặt lại số lần thử nếu đăng nhập thành công
    login_attempts[client_ip] = 0
    session["user_id"] = user["id"]
    return jsonify({"message": f"Logged in as {username} (secure)"})

# Đăng xuất
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return jsonify({"message": "Logged out"})

# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A07:2021 – Identification and Authentication Failures</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>Bcrypt installed : pip install bcrypt</li>
        <li>Test the Demo with Postman</li>
    </ol>

    <p><strong>Postman Setup:</strong></p>
    <p>1. Login ( Insecure - Correct credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/insecure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "password123"}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p>  → Message: Logged in as alice (insecure)</p>
    </ol>

    <p>2. Login (Insecure - Incorrect credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/insecure</li>
        <li>Body: Raw JSON →{"username": "alice", "password": "wrongpassword"}</li>
        <li> Expected Response - Status 401 Unauthorized: </li>
        <p>  → Message: "error": "Incorrect password"</p>
        <p> → Vulnerability:</p>
            <ul>Detailed error messages (e.g., "Incorrect password") help attackers determine valid usernames, making exploitation easier.</ul>
            <ul>No limit on login attempts, leaving the system prone to brute force attacks.</ul>
            <ul>Passwords stored in plaintext, making them easily exposed if the database is compromised.</ul>
    </ol>

    <p>3. Login (Secure - Correct credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON →{"username": "alice", "password": "password123"}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p>  → Message: "message": "Logged in as alice (secure)"</p>
    </ol>

    <p>4. Login (Secure - Incorrect credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON →{"username": "alice", "password": "wrongpassword"}</li>
        <li> Expected Response - Status 401 Unauthorized: </li>
        <p>  → Message: "error": "Invalid credentials"</p>
        <p> → Secure Practices:</p>
            <ul>Generic error messages (e.g., "Invalid credentials") that do not disclose whether the username exists.</ul>
            <ul>Passwords hashed using bcrypt, ensuring security even if the database is compromised.</ul>
    </ol>

    <p>5. Brute force attack attempt (Secure):</p>
    <ol>
        <li>Send 6 consecutive requests with incorrect credentials to /login/secure.</li>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON →{"username": "alice", "password": "wrongpassword"}</li>
        <li> Expected Response (6 consecutive requests) - Status 429 Too Many Requests: </li>
        <p>  → Message: "error": "Too many login attempts, please try again later" </p>
    </ol>
    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)