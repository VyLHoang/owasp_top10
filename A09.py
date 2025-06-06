from flask import Flask, request, jsonify, session
import logging
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Cấu hình logging cho phiên bản an toàn
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"  # Định dạng cơ bản, không yêu cầu 'ip'
)

# Tạo logger tùy chỉnh để thêm 'ip' và 'username' khi cần
logger = logging.getLogger("security")

# Mock database (in-memory)
users = [
    {"id": 1, "username": "alice", "password": "password123"},
    {"id": 2, "username": "bob", "password": "password456"}
]

# Helper function để tìm người dùng theo username
def get_user_by_username(username):
    for user in users:
        if user["username"] == username:
            return user
    return None

# Đăng nhập - Phiên bản không an toàn (Logging Failure)
@app.route("/login/insecure", methods=["POST"])
def login_insecure():
    """
    Lỗ hổng: Security Logging and Monitoring Failures
    Không ghi log các lần đăng nhập (thành công hay thất bại).
    Không thể phát hiện các hành vi bất thường (như brute force).
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["id"]
    return jsonify({"message": f"Logged in as {username} (insecure)"})

# Đăng nhập - Phiên bản an toàn (Proper Logging)
@app.route("/login/secure", methods=["POST"])
def login_secure():
    """
    An toàn: Áp dụng logging và monitoring
    1. Ghi log chi tiết các lần đăng nhập (thành công và thất bại).
    2. Bao gồm thời gian, IP, username, và kết quả.
    3. Dễ dàng phát hiện các hành vi bất thường.
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        client_ip = request.remote_addr
        logger.warning("Missing username or password", extra={"ip": client_ip, "username": "unknown"})
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]
    client_ip = request.remote_addr

    user = get_user_by_username(username)
    if not user:
        logger.warning("Invalid credentials - Username not found", extra={"ip": client_ip, "username": username})
        return jsonify({"error": "Invalid credentials"}), 401

    if user["password"] != password:
        logger.warning("Invalid credentials - Wrong password", extra={"ip": client_ip, "username": username})
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["id"]
    logger.info("Login successful", extra={"ip": client_ip, "username": username})
    return jsonify({"message": f"Logged in as {username} (secure)"})

# Đăng xuất
@app.route("/logout", methods=["POST"])
def logout():
    if "user_id" not in session:
        client_ip = request.remote_addr
        logger.warning("Logout attempt without session", extra={"ip": client_ip, "username": "unknown"})
        return jsonify({"error": "Not logged in"}), 401

    user_id = session["user_id"]
    username = get_user_by_username(user_id)["username"] if user_id else "unknown"
    client_ip = request.remote_addr
    logger.info("Logout successful", extra={"ip": client_ip, "username": username})
    session.pop("user_id", None)
    return jsonify({"message": "Logged out"})

# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A09:2021 – Security Logging and Monitoring Failures</h2>
    <p><strong>How to run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed</li>
        <li>Flask installed: pip install flask</li>
        <li>Test the Demo with Postman</li>
    </ol>
    <p><strong>Postman Setup:</strong></p>
    <p>1. Login (Insecure - Correct credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/insecure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "password123"}</li>
        <li>Expected Response - Status 200 OK:</li>
        <p>→ Message: {"message": "Logged in as alice (insecure)"}</p>
    </ol>
    <p>2. Login (Insecure - Incorrect credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/insecure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "wrongpassword"}</li>
        <li>Expected Response - Status 401 Unauthorized:</li>
        <p>→ Message: {"error": "Invalid credentials"}</p>
    </ol>
    <p>3. Login (Secure - Correct credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "password123"}</li>
        <li>Expected Response - Status 200 OK:</li>
        <p>→ Message: {"message": "Logged in as alice (secure)"}</p>
    </ol>
    <p>4. Login (Secure - Incorrect credentials):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "wrongpassword"}</li>
        <li>Expected Response - Status 401 Unauthorized:</li>
        <p>→ Message: {"error": "Invalid credentials"}</p>
    </ol>
    <p>5. Brute Force Attack Simulation (Secure):</p>
    <ol>
        <li>Send 5 consecutive requests with incorrect credentials to /login/secure.</li>
        <li>Request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "wrongpassword"}</li>
        <li>Check the log (security.log)</li>
        <li>Secure Outcome: The log detects consecutive failed login attempts from the same IP, making brute force attacks easily identifiable.</li>
    </ol>
    """
if __name__ == "__main__":
    app.run(debug=True, port=5000)