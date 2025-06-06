from flask import Flask, request, jsonify, session
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

# Xóa tài khoản - Phiên bản không an toàn (Insecure Design)
@app.route("/delete/insecure/<int:user_id>", methods=["DELETE"])
def delete_insecure(user_id):
    """
    Lỗ hổng: Thiết kế không an toàn, không kiểm tra quyền hoặc xác nhận hành động.
    Bất kỳ ai đã đăng nhập đều có thể xóa tài khoản của người khác.
    """
    if "user_id" not in session:
        return jsonify({"error": "Please log in"}), 401

    user_to_delete = get_user_by_id(user_id)
    if not user_to_delete:
        return jsonify({"error": "User not found"}), 404

    # Xóa người dùng mà không kiểm tra quyền hoặc xác nhận
    users.remove(user_to_delete)
    return jsonify({"message": f"User {user_id} deleted (insecure)"})

# Xóa tài khoản - Phiên bản an toàn (Secure Design)
@app.route("/delete/secure/<int:user_id>", methods=["DELETE"])
def delete_secure(user_id):
    """
    An toàn: Áp dụng thiết kế bảo mật:
    1. Kiểm tra quyền (chỉ người dùng đó hoặc admin mới được xóa).
    2. Yêu cầu xác nhận hành động qua tham số 'confirm'.
    """
    if "user_id" not in session:
        return jsonify({"error": "Please log in"}), 401

    current_user_id = session["user_id"]
    is_admin = session.get("is_admin", False)

    # Kiểm tra quyền
    if current_user_id != user_id and not is_admin:
        return jsonify({"error": "Unauthorized: You can only delete your own account or must be an admin"}), 403

    user_to_delete = get_user_by_id(user_id)
    if not user_to_delete:
        return jsonify({"error": "User not found"}), 404

    # Yêu cầu xác nhận hành động
    confirm = request.args.get("confirm", "").lower()
    if confirm != "yes":
        return jsonify({"error": "Confirmation required: Add ?confirm=yes to the request"}), 400

    # Xóa người dùng
    users.remove(user_to_delete)
    return jsonify({"message": f"User {user_id} deleted (secure)"})

# Trang hướng dẫn
@app.route("/")
def index():
    return """
        <h2>OWASP A04:2021 - Insecure Design</h2>
        <p><strong>How ro run the Demo:</strong></p>
        <ol>
            <li>Python 3.x installed </li>
            <li>Flask installed : pip install flask </li>
            <li>Test the Demo with Postman</li>
        </ol>
        <p><strong>Postman Setup:</strong></p>
        <p>1. Log In as Alice:</p>
        <ol>
            <li>Create a new request: POST http://127.0.0.1:5000/login</li>
            <li>Body: Raw JSON → {"username": "alice"}</li>
            <li>Expected Response: {"message": "Logged in as alice"} - Status 200 OK</li>
            <li>Note: Record the session cookie from Postman to use for subsequent requests.</li>
        </ol>
        <p>2. Delete account (Insecure – Alice deletes Bob's account):</p>
        <ol>
            <li>Create a new request: DELETE http://127.0.0.1:5000/delete/insecure/2</li>
            <li>Headers: Make sure to send the session cookie from the login step.</li>
            <li>Expected Response: {"message": "User 2 deleted (insecure)"} - Status 200 OK</li>
            <p> →Vulnerability: Alice (ID 1) can delete Bob's account (ID 2) without permission or confirmation, due to insecure design.</li>
        </ol>
        <p>3. Log in as Alice again</p>
            <li>Repeat step 1 to restore the session (because the user list has changed after deletion).</li>
        <p>4. Delete account (Secure - Alice attempts to delete Bob's account):</p>
        <ol>
            <li>Create a new request: DELETE http://127.0.0.1:5000/delete/secure/2</li>
            <li>Headers: make sure send session cookie.</li>
            <li>Expected Response: {"error": "Unauthorized: You can only delete your own account or must be an admin"} - Status 403 Forbidden</li>
             <p> → Secure: Alice is not authorized to delete Bob's account. </p>
        </ol>
        <p>5. Delete account (Secure - Alice attempts to delete her own account, but lacks confirmation):</p>
        <ol>
            <li>Create a new request: DELETE http://127.0.0.1:5000/delete/secure/1</li>
            <li>Headers: make sure send session cookie.</li>
            <li>Expected Response: {"error": "Confirmation required: Add ?confirm=yes to the request"} - Status 400 Bad Request</li>
             <p> → Secure: The design requires an action confirmation step. </p>
        </ol>
        <p>6. Delete account (Secure - Alice attempts to delete her own account, but have the confirmation):</p>
        <ol>
            <li>Create a new request: DELETE http://127.0.0.1:5000/delete/secure/1?confirm=yes</li>
            <li>Headers: make sure send session cookie.</li>
            <li>Expected Response: {"message": "User 1 deleted (secure)"} - Status 200 OK</li>
             <p> → Secure: The action is executed after the confirmation step. </p>
        </ol>
        <p>7. Log in as Admin and delete account (Secure):</p>
        <ol>
            <li>Login: POST http://127.0.0.1:5000/login với {"username": "admin"}.</li>
            <li>Create a new request: DELETE http://127.0.0.1:5000/delete/secure/2?confirm=yes/li>
            <li>Expected Response: {"message": "User 2 deleted (secure)"} - Status 200 OK</li>
             <p> → Secure: Admins are authorized to delete others' accounts, but confirmation is still required. </p>
        </ol>
        """


if __name__ == "__main__":
    app.run(debug=True, port=5000)