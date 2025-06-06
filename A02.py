from flask import Flask, request, jsonify, session
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Mock database (in-memory)
insecure_users = []  # Lưu trữ không an toàn (plain text passwords)
secure_users = []    # Lưu trữ an toàn (hashed passwords)

# Đăng ký người dùng - Phiên bản không an toàn
@app.route("/register/insecure", methods=["POST"])
def register_insecure():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    # Kiểm tra xem username đã tồn tại chưa
    for user in insecure_users:
        if user["username"] == username:
            return jsonify({"error": "Username already exists"}), 409

    # Lưu mật khẩu dưới dạng plain text (lỗ hổng)
    insecure_users.append({
        "username": username,
        "password": password  # Plain text!
    })
    return jsonify({"message": f"User {username} registered (insecure)"})

# Đăng ký người dùng - Phiên bản an toàn
@app.route("/register/secure", methods=["POST"])
def register_secure():
    """
    An toàn: Sử dụng bcrypt để băm mật khẩu trước khi lưu.
    """
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    # Kiểm tra xem username đã tồn tại chưa
    for user in secure_users:
        if user["username"] == username:
            return jsonify({"error": "Username already exists"}), 409

    # Băm mật khẩu bằng bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    secure_users.append({
        "username": username,
        "password": hashed_password  # Hashed password
    })
    return jsonify({"message": f"User {username} registered (secure)"})

# Đăng nhập - Phiên bản không an toàn
@app.route("/login/insecure", methods=["POST"])
def login_insecure():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    for user in insecure_users:
        if user["username"] == username and user["password"] == password:
            session["username"] = username
            return jsonify({"message": f"Logged in as {username} (insecure)"})
    return jsonify({"error": "Invalid credentials"}), 401

# Đăng nhập - Phiên bản an toàn
@app.route("/login/secure", methods=["POST"])
def login_secure():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"]
    password = data["password"]

    for user in secure_users:
        if user["username"] == username:
            # So sánh mật khẩu với bản băm
            if bcrypt.checkpw(password.encode('utf-8'), user["password"]):
                session["username"] = username
                return jsonify({"message": f"Logged in as {username} (secure)"})
    return jsonify({"error": "Invalid credentials"}), 401

# Xem danh sách người dùng - Phiên bản không an toàn (mô phỏng hacker truy cập database)
@app.route("/users/insecure", methods=["GET"])
def get_users_insecure():
    """
    Lỗ hổng: Hacker có thể thấy mật khẩu plain text.
    """
    return jsonify(insecure_users)

# Xem danh sách người dùng - Phiên bản an toàn
@app.route("/users/secure", methods=["GET"])
def get_users_secure():
    """
    An toàn: Chỉ thấy mật khẩu đã được băm, không thể đọc trực tiếp.
    """
    # Chuyển bytes (hashed password) thành string để hiển thị JSON
    display_users = []
    for user in secure_users:
        display_users.append({
            "username": user["username"],
            "password": user["password"].decode('utf-8')  # Hiển thị hash dưới dạng string
        })
    return jsonify(display_users)

# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A02:2021 - Cryptographic Failures Demo</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>bcrypt installed : pip install bcrypt </li>
        <li>Test the Demo with Postman</li>
    </ol>
    <p><strong>Postman Setup:</strong></p>
    <p>1. Sign up as user ( insecure )</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/register/insecure</li>
        <li>Go to the Body tab, select raw, and choose JSON from the dropdown.</li>
        <li>Enter body: Raw JSON → {"username": "alice", "password": "123456"}</li>
        <li>Expected Response: {"message": "User alice registered (insecure)"} - Status 200 OK</li>
    </ol>
    <p>2. ASign up as user ( secure )</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/register/secure</li>
        <li>Go to the Body tab, select raw, and choose JSON from the dropdown.</li>
        <li>Enter body: Raw JSON → {"username": "bob", "password": "abcdef"}</li>
        <li>Expected Response: {"message": "User bob registered (secure)"} - Status 200 OK</li>
    </ol>
    <p>3. Sign In ( insecure )</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/login/insecure</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request.</li>
        <li>Body: Raw JSON → {"username": "alice", "password": "123456"}</li>
        <li>Expected Response: {"message": "Logged in as alice (insecure)"} - Status 200 OK</li>
    </ol>
    <p>4. Sign In ( secure )</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/login/secure</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request.</li>
        <li>Body: Raw JSON → {"username": "bob", "password": "abcdef"}</li>
        <li>Expected Response: {"message": "Logged in as bob (secure)"} - Status 200 OK</li>
    </ol>
    <p>5. View list of insecure user</p>
    <ol>
        <li>Create a new request:GET http://127.0.0.1:5000/users/insecure</li>
        <li>Expected Response:[{"username": "alice", "password": "123456"}] - Status 200 OK</li>
        <li>User password is been stored as plaintext, make it easy for hacker to read if they could access the database.</li> 
    </ol>
    <p>6. View list of secure user</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/users/secure</li>
        <li>Expected Response:[{"username": "bob", "password": "$2b$12$..."}] - Status 200 OK</li>
        <li>The password value will be a bcrypt hash string and cannot be read directly.</li> 
        <li>Security: The password is hashed, so hackers cannot determine the original password.</li>
    </ol>
    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)