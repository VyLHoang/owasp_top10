from flask import Flask, request, jsonify, session, make_response
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Mock database (in-memory)
users = [
    {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": False},
    {"id": 2, "username": "bob", "email": "bob@example.com", "is_admin": False},
    {"id": 3, "username": "admin", "email": "admin@example.com", "is_admin": True}
]

# Helper function để tìm người dùng theo ID
def get_user_by_id(user_id):
    for user in users:
        if user["id"] == user_id:
            return user
    return None

# Đăng nhập
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Missing username"}), 400

    username = data["username"]
    for user in users:
        if user["username"] == username:
            session["user_id"] = user["id"]
            session["is_admin"] = user["is_admin"]
            return jsonify({"message": f"Logged in as {username}"})
    return jsonify({"error": "Invalid username"}), 401

# Đăng xuất
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    session.pop("is_admin", None)
    return jsonify({"message": "Logged out"})

# Lấy thông tin người dùng - Phiên bản không an toàn (Security Misconfiguration)
@app.route("/user/insecure/<user_id>", methods=["GET"])
def user_insecure(user_id):
    """
    Lỗ hổng: Security Misconfiguration
    1. Chế độ debug bật, để lộ stack trace khi xảy ra lỗi.
    2. Không có header bảo mật, dễ bị tấn công như clickjacking hoặc MIME sniffing.
    3. Trả về thông tin nhạy cảm trong thông báo lỗi.
    """
    if "user_id" not in session:
        return jsonify({"error": "Please log in"}), 401

    current_user_id = session["user_id"]
    is_admin = session.get("is_admin", False)

    # Gây lỗi cố ý nếu user_id không phải số (để lộ stack trace)
    try:
        user_id = int(user_id)
    except ValueError as e:
        # Ở chế độ debug, Flask sẽ trả về stack trace chi tiết
        return jsonify({"error": f"Invalid user_id: {str(e)}", "debug_info": "Stack trace would be exposed in debug mode"}), 400

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": f"User {user_id} not found", "debug_info": "Database query failed"}), 404

    # Kiểm tra quyền
    if current_user_id != user_id and not is_admin:
        return jsonify({"error": "Unauthorized access", "debug_info": "User lacks permission"}), 403

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "is_admin": user["is_admin"]
    })

# Lấy thông tin người dùng - Phiên bản an toàn (Proper Configuration)
@app.route("/user/secure/<user_id>", methods=["GET"])
def user_secure(user_id):
    """
    An toàn: Cấu hình bảo mật đúng cách
    1. Tắt chế độ debug, không để lộ stack trace.
    2. Thêm các header bảo mật (X-Content-Type-Options, X-Frame-Options, CSP).
    3. Xử lý lỗi mà không để lộ thông tin nhạy cảm.
    """
    if "user_id" not in session:
        response = make_response(jsonify({"error": "Please log in"}), 401)
        response = add_security_headers(response)
        return response

    current_user_id = session["user_id"]
    is_admin = session.get("is_admin", False)

    # Xử lý lỗi mà không để lộ thông tin nhạy cảm
    try:
        user_id = int(user_id)
    except ValueError:
        response = make_response(jsonify({"error": "Invalid user_id"}), 400)
        response = add_security_headers(response)
        return response

    user = get_user_by_id(user_id)
    if not user:
        response = make_response(jsonify({"error": "User not found"}), 404)
        response = add_security_headers(response)
        return response

    # Kiểm tra quyền
    if current_user_id != user_id and not is_admin:
        response = make_response(jsonify({"error": "Unauthorized access"}), 403)
        response = add_security_headers(response)
        return response

    response = make_response(jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "is_admin": user["is_admin"]
    }))
    response = add_security_headers(response)
    return response

# Helper function để thêm các header bảo mật
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Trang hướng dẫn
@app.route("/")
def index():
    return """
            <h2>OWASP A05:2021 - Security Misconfiguration</h2>
            <p><strong>How to run the Demo:</strong></p>
            <ol>
                <li>Python 3.x installed </li>
                <li>Flask installed : pip install flask </li>
                <li>Test the Demo with Postman</li>
            </ol>
            <p><strong>Postman Setup:</strong></p>
            <p>Log In as Alice:</p>
            <ol>
                <li>Create a new request: POST http://127.0.0.1:5000/login</li>
                <li>Body: Raw JSON → {"username": "alice"}</li>
                <li>Expected Response: {"message": "Logged in as alice"} - Status 200 OK</li>
                <li>Note: Record the session cookie from Postman to use for subsequent requests.</li>
            </ol>
            
            <p>1. Induce errors (Insecure - Exposes sensitive information):</p>
            <ol>
                <li>Create a new request: GET http://127.0.0.1:5000/user/insecure/invalid</li>
                <li>Headers: Make sure to send the session cookie from the login step.</li>
                <li>Expected Response: {"error": "Invalid user_id: invalid literal for int() with base 10: 'invalid'", "debug_info": "Stack trace would be exposed in debug mode"} - Status 400 Bad Request</li>
                <p> → Because debug=True, Flask will return an HTML page containing a detailed stack trace (instead of JSON).</li>
            </ol>
            <ul>
                <p>Check Headers (in Postman → Headers tab):</p>
                <li>No security headers are present (e.g., X-Content-Type-Options, X-Frame-Options, etc.).</li>
                <p>Vulnerabilities:</p>
                    <ol>
                        <li>Exposed stack trace (sensitive information) due to debug mode being enabled.</li>
                        <li>Missing security headers, making the application vulnerable to attacks such as:</li>
                        <ul>
                            <li>Clickjacking (X-Frame-Options header missing).</li>
                            <li>MIME sniffing (X-Content-Type-Options header missing).</li>
                        </ul>
                    </ol>
            </ul>    
            
            <p>2. Induce errors (Secure - Proper error handling):</p>
            <ol>
                <li>Create a new request: GET http://127.0.0.1:5000/user/secure/invalid</li>
                <li>Headers: Make sure to send the session cookie from the login step.</li>
                <li>Expected Response: {"error": "Invalid user_id"} - Status 400  Bad Request</li>
                <li>Note: Record the session cookie from Postman to use for subsequent requests.</li>
            </ol>
            <ul>
                <p>Check Headers (in Postman → Headers tab):</p>
                <p>Security headers are present:</p>
                <li>X-Content-Type-Options: nosniff</li>
                <li>X-Frame-Options: DENY</li>
                <li>Content-Security-Policy: default-src 'self'</li>
                <p>Security:</p>
                    <ul>
                        <li>No exposed stack trace (sensitive information) because debug mode is disabled.</li>
                        <li>Security headers are present, reducing the risk of attacks.</li>
                    </ul>
            </ul>

            <p>3. Retrieve user information (Insecure):</p>
            <ol>
                <li>Create a new request: GET http://127.0.0.1:5000/user/insecure/1</li>
                <li>Headers: Make sure to send the session cookie from the login step.</li>
                <li>Expected Response: {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": false} - Status 200 OK</li>
                <p> → Vulnerability: Despite functioning correctly, this endpoint remains vulnerable to attacks due to missing security headers.</p>
            </ol>

            <p>4. Retrieve user information (Secure):</p>
            <ol>
                <li>Create a new request: GET http://127.0.0.1:5000/user/secure/1</li>
                <li>Headers: Make sure to send the session cookie from the login step.</li>
                <li>Expected Response: {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": false} - Status 200 OK</li>
                <p> → This endpoint is secure and includes security headers.</p>
            </ol>
            """

if __name__ == "__main__":
    # Chế độ debug được bật để mô phỏng cấu hình sai (cho /user/insecure)
    app.run(debug=True, port=5000)



