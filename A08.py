from flask import Flask, request, jsonify, session
import os
import hmac
import hashlib
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Khóa bí mật để tạo HMAC (trong thực tế, nên lưu trữ an toàn)
SECRET_KEY = "my-secret-key".encode()

# Mock database (in-memory)
accounts = [
    {"id": 1, "username": "alice", "balance": 1000},
    {"id": 2, "username": "bob", "balance": 500}
]

# Helper function để tìm tài khoản theo ID
def get_account_by_id(account_id):
    for account in accounts:
        if account["id"] == account_id:
            return account
    return None

# Đăng nhập
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Missing username"}), 400

    username = data["username"]
    account = get_account_by_username(username)
    if not account:
        return jsonify({"error": "Invalid username"}), 401

    session["account_id"] = account["id"]
    return jsonify({"message": f"Logged in as {username}"})

# Helper function để tìm tài khoản theo username
def get_account_by_username(username):
    for account in accounts:
        if account["username"] == username:
            return account
    return None

# Cập nhật số dư - Phiên bản không an toàn (Data Integrity Failure)
@app.route("/update-balance/insecure", methods=["POST"])
def update_balance_insecure():
    """
    Lỗ hổng: Data Integrity Failure
    Không kiểm tra tính toàn vẹn của dữ liệu.
    Kẻ tấn công có thể thay đổi số dư trên đường truyền (tamper data).
    """
    if "account_id" not in session:
        return jsonify({"error": "Please log in"}), 401

    current_account_id = session["account_id"]
    data = request.get_json()
    if not data or "account_id" not in data or "balance" not in data:
        return jsonify({"error": "Missing account_id or balance"}), 400

    account_id = data["account_id"]
    new_balance = data["balance"]

    # Kiểm tra quyền
    if current_account_id != account_id:
        return jsonify({"error": "Unauthorized: You can only update your own balance"}), 403

    account = get_account_by_id(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404

    # Cập nhật số dư mà không kiểm tra tính toàn vẹn
    account["balance"] = new_balance
    return jsonify({
        "message": "Balance updated (insecure)",
        "account": account
    })

# Cập nhật số dư - Phiên bản an toàn (Integrity Check)
@app.route("/update-balance/secure", methods=["POST"])
def update_balance_secure():
    """
    An toàn: Đảm bảo tính toàn vẹn dữ liệu
    1. Sử dụng HMAC để kiểm tra tính toàn vẹn của dữ liệu.
    2. Từ chối nếu dữ liệu bị thay đổi trái phép.
    """
    if "account_id" not in session:
        return jsonify({"error": "Please log in"}), 401

    current_account_id = session["account_id"]
    data = request.get_json()
    if not data or "account_id" not in data or "balance" not in data or "signature" not in data:
        return jsonify({"error": "Missing account_id, balance, or signature"}), 400

    account_id = data["account_id"]
    new_balance = data["balance"]
    received_signature = data["signature"]

    # Kiểm tra quyền
    if current_account_id != account_id:
        return jsonify({"error": "Unauthorized: You can only update your own balance"}), 403

    account = get_account_by_id(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404

    # Tạo HMAC để kiểm tra tính toàn vẹn
    data_to_sign = json.dumps({"account_id": account_id, "balance": new_balance}).encode()
    expected_signature = hmac.new(SECRET_KEY, data_to_sign, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, received_signature):
        return jsonify({"error": "Data integrity check failed: Invalid signature"}), 400

    # Cập nhật số dư
    account["balance"] = new_balance
    return jsonify({
        "message": "Balance updated (secure)",
        "account": account
    })

# Helper function để tạo chữ ký HMAC (dùng trong Postman hoặc client)
@app.route("/generate-signature", methods=["POST"])
def generate_signature():
    """
    Helper endpoint để tạo chữ ký HMAC cho dữ liệu (dùng trong Postman).
    Trong thực tế, client sẽ tự tạo chữ ký này.
    """
    data = request.get_json()
    if not data or "account_id" not in data or "balance" not in data:
        return jsonify({"error": "Missing account_id or balance"}), 400

    data_to_sign = json.dumps({"account_id": data["account_id"], "balance": data["balance"]}).encode()
    signature = hmac.new(SECRET_KEY, data_to_sign, hashlib.sha256).hexdigest()
    return jsonify({"signature": signature})

# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A08:2021 – Software and Data Integrity Failures</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>Test the Demo with Postman</li>
    </ol>

    <p><strong>Postman Setup:</strong></p>
    <p>1. Login (Alice):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/login</li>
        <li>Body: Raw JSON → {"username": "alice"}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p>  → Message: {"message": "Logged in as alice"}</p>
    </ol>

    <p>2. Update Balance (Insecure - Tamperable):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/update-balance/insecure</li>
        <li>Body: Raw JSON → {"account_id": 1, "balance": 2000}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p>  → Message: {
                "message": "Balance updated (insecure)",<br/>
                "account": {"id": 1, "username": "alice", "balance": 2000}
        }</p>
        <p> Simulated Attack:</p>
        <ul>
            <li>Change the balance to 9999 in Postman and resend the request.</li>
            <li> → Message: {"account_id": 1, "balance": 9999} </li>
            <li> → Expected Response: {
                "message": "Balance updated (insecure)", <br/>
                "account": {"id": 1, "username": "alice", "balance": 9999}
            } </li>
            <li> → Vulnerability: Data integrity is not validated, allowing attackers to manipulate balances illegitimately.</li>
        </ul>

    </ol>

    <p>3. Generate HMAC Signature:</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/generate-signature</li>
        <li>Body: Raw JSON → {"account_id": 1, "balance": 2000} </li>
        <li> Expected Response: </li>
        <p>  → Message: {"signature": "some_hmac_signature"}</p>
        <p> Save the signature for use in the next step.</p>
    </ol>

    <p>4. Update Balance (Secure - Integrity Checked):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/update-balance/secure</li>
        <li>Body: Raw JSON → {"account_id": 1, "balance": 2000, "signature": "some_hmac_signature"} </li>
        <li> Expected Response - Status 200 OK: </li>
        <p>  → Message: {
                "message": "Balance updated (secure)",<br/>
                "account": {"id": 1, "username": "alice", "balance": 2000}
        }</p>
    </ol>

    <p>5. Simulated Attack (Secure - Data Tampering):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/update-balance/secure</li>
        <li>Body: Raw JSON → {"account_id": 1, "balance": 9999, "signature": "some_hmac_signature"} <br/>
        Modify the balance but keep the signature unchanged. </li>
        <li> Expected Response - Status 400 Bad Request: </li>
        <p>  → Message:{"error": "Data integrity check failed: Invalid signature"} </p>
        <p> Secure Outcome:</p>
        <ul>
            <li>Unauthorized data modification (balance changed from 2000 to 9999), but the HMAC does not match, so the request is rejected.</li>
        </ul>
    </ol>
    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)