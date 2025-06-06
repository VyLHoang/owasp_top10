from flask import Flask, request, session, jsonify, abort
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Mock user database
users = [
    {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": False},
    {"id": 2, "username": "bob", "email": "bob@example.com", "is_admin": False},
    {"id": 3, "username": "admin", "email": "admin@example.com", "is_admin": True}
]

# Hàm tìm User theo ID
def get_user_by_id(user_id):
    for user in users:
        if user["id"] == user_id:
            return user
    return None

# Login route
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Missing username in JSON body"}), 400
    username = data.get("username")
    for user in users:
        if user["username"] == username:
            session["user_id"] = user["id"]
            session["is_admin"] = user["is_admin"]
            return jsonify({"message": f"Logged in as {username}"})
    return jsonify({"error": "Invalid username"}), 401

# Logout route
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    session.pop("is_admin", None)
    return jsonify({"message": "Logged out"})

@app.route("/profile/insecure/<int:user_id>", methods=["GET"])
def get_profile_insecure(user_id):
    if "user_id" not in session:
        return jsonify({"error": "Please log in"}), 401
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "is_admin": user["is_admin"]
    })

@app.route("/profile/secure/<int:user_id>", methods=["GET"])
def get_profile_secure(user_id):
    if "user_id" not in session:
        return jsonify({"error": "Please log in"}), 401
    current_user_id = session["user_id"]
    is_admin = session.get("is_admin", False)
    if current_user_id != user_id and not is_admin:
        return jsonify({"error": "Unauthorized access"}), 403
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "is_admin": user["is_admin"]
    })

@app.route("/")
def index():
    return """
    <h2>OWASP A01:2021 - Broken Access Control Demo</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed </li>
        <li>Test the Demo with Postman</li>
    </ol>
    <p><strong>Postman Setup:</strong></p>
    <p>1. Log In as Alice</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/login.</li>
        <li>Go to the Body tab, select raw, and choose JSON from the dropdown.</li>
        <li>Enter body: {"username": "alice"}. </li>
        <li>Expected Response: {"message": "Logged in as alice"} - Status 200 OK</li>
    </ol>
    <p>2. Access Alice’s Profile (Insecure Route).</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/profile/insecure/1.</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request.</li>
        <li>Expected Response:{"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": false} - Status 200 OK</li>
    </ol>
    <p>3. Test the Secure Route (Access Bob’s Profile as Alice)</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/profile/secure/2.</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request.</li>
        <li>Expected Response:{"error": "Unauthorized access"} - Status 403 Forbidden</li>
        <li>Result: Alice is denied access to Bob’s profile, showing proper access control.</li>
    </ol>
    <p>4. Test the Secure Route (Access Alice’s Own Profile)</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/profile/secure/1.</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request</li>
        <li>Expected Response:{"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": false} - Status OK</li>
    </ol>
    <p>5. Log Out</p>
    <ol>
        <li>Create a new request: POST http://127.0.0.1:5000/logout</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request</li>
        <li>Expected Response:{"message": "Logged out"} - Status 200 OK</li>
    </ol>
    <p>6. Verify No Access After Logout</p>
    <ol>
        <li>Create a new request: GET http://127.0.0.1:5000/profile/insecure/1</li>
        <li>Ensure the session cookie is sent (Postman should include it automatically if the login succeeded). - Send the request</li>
        <li>Expected Response:{"error": "Please log in"} - Status 401 Unauthorized</li>
    </ol>
  
    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)