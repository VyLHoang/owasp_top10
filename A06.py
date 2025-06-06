from flask import Flask, request, jsonify
import html
import os

app = Flask(__name__)

# Mock database (in-memory)
comments = []


# Giả lập thư viện xử lý đầu vào (phiên bản cũ - không an toàn)
class InputProcessorV1:
    @staticmethod
    def process_input(data):
        """
        Phiên bản cũ của thư viện (có lỗ hổng).
        Không lọc đầu vào, cho phép chèn mã độc (mô phỏng XSS hoặc command injection).
        """
        return data  # Trả về dữ liệu thô, không xử lý


# Giả lập thư viện xử lý đầu vào (phiên bản mới - an toàn)
class InputProcessorV2:
    @staticmethod
    def process_input(data):
        """
        Phiên bản mới của thư viện (đã vá lỗi).
        Lọc và mã hóa đầu vào để ngăn chặn khai thác.
        """
        # Mã hóa HTML để ngăn XSS
        return html.escape(data)


# Thêm bình luận - Phiên bản không an toàn (Vulnerable Component)
@app.route("/comment/insecure", methods=["POST"])
def comment_insecure():
    """
    Lỗ hổng: Sử dụng phiên bản cũ của thư viện (InputProcessorV1),
    không lọc đầu vào, cho phép chèn mã độc (mô phỏng XSS hoặc command injection).
    """
    data = request.get_json()
    if not data or "comment" not in data:
        return jsonify({"error": "Missing comment"}), 400

    comment = data["comment"]

    # Sử dụng phiên bản cũ (có lỗ hổng)
    processor = InputProcessorV1()
    processed_comment = processor.process_input(comment)

    comments.append(processed_comment)
    return jsonify({
        "message": "Comment added (insecure)",
        "comment": processed_comment,
        "warning": "This comment may contain malicious code (e.g., XSS or command injection)"
    })


# Thêm bình luận - Phiên bản an toàn (Updated Component)
@app.route("/comment/secure", methods=["POST"])
def comment_secure():
    """
    An toàn: Sử dụng phiên bản mới của thư viện (InputProcessorV2),
    lọc và mã hóa đầu vào để ngăn chặn khai thác.
    """
    data = request.get_json()
    if not data or "comment" not in data:
        return jsonify({"error": "Missing comment"}), 400

    comment = data["comment"]

    # Sử dụng phiên bản mới (đã vá lỗi)
    processor = InputProcessorV2()
    processed_comment = processor.process_input(comment)

    comments.append(processed_comment)
    return jsonify({
        "message": "Comment added (secure)",
        "comment": processed_comment
    })


# Xem tất cả bình luận
@app.route("/comments", methods=["GET"])
def get_comments():
    return jsonify({"comments": comments})


# Trang hướng dẫn
@app.route("/")
def index():
    return """
    <h2>OWASP A06:2021 – Vulnerable and Outdated Components</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>Test the Demo with Postman</li>
    </ol>

    <p><strong>Postman Setup:</strong></p>
    <p>1. Add comment (Insecure - Contains malicious code):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/comment/insecure</li>
        <li>Body: Raw JSON → {"comment": "<script>alert('XSS')</script>"}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p> {<br>"message": "Comment added (insecure)",<br> "comment": "<script>alert('XSS')</script>",<br> "warning": "This comment may contain malicious code (e.g., XSS or command injection)"<br>} </p>
        <p>  → Vulnerability: The comment contains malicious JavaScript code (<script>alert('XSS')</script>), which is not sanitized, potentially causing XSS if rendered on the web interface.</p>
    </ol>

    <p>2. Add comment (Secure - No malicious code):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/comment/secure </li>
        <li>Body: Raw JSON → {"comment": "<script>alert('XSS')</script>"}</li>
        <li> Expected Response - Status 200 OK: </li>
        <p> {<br>"message": "Comment added (secure)",<br> "comment": "&lt;script&gt;alert('XSS')&lt;/script&gt;"<br>} </p> 
        <p>  → Secure: The comment is sanitized, and the malicious code is encoded as HTML entities (&lt;script&gt;alert('XSS')&lt;/script&gt;), preventing XSS.</p>
    </ol>

    <p>3. View all comments:</p>
    <ol>
        <li>Request: GET http://127.0.0.1:5000/comments</li>
        <li>Expected Response - Status 200 OK: </li>
        <p> {<br>"comments": ["<script>alert('XSS')</script>",<br>"&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"<br>]<br>} </p> 
        <p>  → Vulnerability: The comment contains malicious JavaScript code (<script>alert('XSS')</script>), which is not sanitized, potentially causing XSS if rendered on the web interface.</p>
    </ol>

   """


if __name__ == "__main__":
    app.run(debug=True, port=5000)