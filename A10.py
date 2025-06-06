from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Whitelist các domain được phép truy cập (phiên bản an toàn)
ALLOWED_DOMAINS = ["example.com", "api.example.com"]

# Đọc nội dung từ URL - Phiên bản không an toàn (SSRF Vulnerable)
@app.route("/fetch/insecure", methods=["POST"])
def fetch_insecure():
    """
    Lỗ hổng: Server-Side Request Forgery (SSRF)
    Không kiểm tra URL, cho phép truy cập bất kỳ địa chỉ nào (bao gồm localhost, nội bộ).
    Kẻ tấn công có thể yêu cầu server truy cập tài nguyên không mong muốn.
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = data["url"]

    try:
        # Server gửi yêu cầu đến URL mà người dùng cung cấp
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return jsonify({
            "message": "Content fetched (insecure)",
            "url": url,
            "content": response.text[:200]  # Giới hạn nội dung trả về để dễ đọc
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch URL: {str(e)}"}), 400

# Đọc nội dung từ URL - Phiên bản an toàn (SSRF Mitigated)
@app.route("/fetch/secure", methods=["POST"])
def fetch_secure():
    """
    An toàn: Ngăn chặn SSRF
    1. Kiểm tra scheme (chỉ cho phép http/https).
    2. Kiểm tra domain (chỉ cho phép các domain trong whitelist).
    3. Chặn truy cập localhost hoặc địa chỉ nội bộ.
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = data["url"]

    # Phân tích URL
    parsed_url = urlparse(url)

    # 1. Kiểm tra scheme (chỉ cho phép http hoặc https)
    if parsed_url.scheme not in ["http", "https"]:
        return jsonify({"error": "Only http and https schemes are allowed"}), 400

    # 2. Kiểm tra hostname
    hostname = parsed_url.hostname
    if not hostname:
        return jsonify({"error": "Invalid URL: No hostname found"}), 400

    # 3. Chặn truy cập localhost hoặc địa chỉ nội bộ
    if hostname in ["localhost", "127.0.0.1", "::1"] or re.match(r"^(10|172|192)\.", hostname):
        return jsonify({"error": "Access to internal resources is not allowed"}), 403

    # 4. Kiểm tra domain trong whitelist
    if not any(hostname == allowed or hostname.endswith("." + allowed) for allowed in ALLOWED_DOMAINS):
        return jsonify({"error": f"Domain {hostname} is not in the allowed list"}), 403

    try:
        # Server gửi yêu cầu đến URL
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return jsonify({
            "message": "Content fetched (secure)",
            "url": url,
            "content": response.text[:200]  # Giới hạn nội dung trả về để dễ đọc
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch URL: {str(e)}"}), 400


@app.route("/")
def index():
    return """
    <h2>OWASP A10:2021 – Server-Side Request Forgery (SSRF)</h2>
    <p><strong>How ro run the Demo:</strong></p>
    <ol>
        <li>Python 3.x installed </li>
        <li>Flask installed : pip install flask </li>
        <li>Resquests installed : pip install requests </li>
        <li>Test the Demo with Postman</li>
    </ol>

    <p><strong>Postman Setup:</strong></p>
    <p>1. Download Content (Insecure - Valid URL):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/fetch/insecure </li>
        <li> Status: 200 OK </li>
        <li>Body: Raw JSON → {"url": "http://example.com"}</li>
    </ol>

    <p>2. Download Content (Insecure - SSRF: Access localhost):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/fetch/insecure </li>
        <li> Status: 200 OK </li>
        <li>Body: Raw JSON → {"url": "http://localhost:5000"} </li>
    </ol>

    <p>3. Download Content (Secure - Valid URL):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/fetch/secure </li>
        <li> Status: 200 OK </li>
        <li>Body: Raw JSON → {"url": "http://example.com"} </li>
    </ol>

    <p>4. Download Content (Secure - SSRF: Access localhost):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/fetch/secure </li>
        <li> Status: 403 Forbidden </li>
        <li>Body: Raw JSON → {"url": "http://localhost:5000"} </li>
    </ol>

    <p>5. Download Content (Secure - URL Not in Allowlist):</p>
    <ol>
        <li>Request: POST http://127.0.0.1:5000/fetch/secure </li>
         <li> Status: 403 Forbidden </li>
        <li>Body: Raw JSON → {"url": "http://malicious.com"} </li>
    </ol>

    """

if __name__ == "__main__":
    app.run(debug=True, port=5000)