import os 
import subprocess
import pickle
import jwt
import hashlib
import base64
import requests
import json
import yaml
import flask
from flask import Flask, request, render_template_string
import sqlite3
import socket
import tempfile
import random
import string
import shutil
import xml.etree.ElementTree as ET

app = Flask(__name__)

# 1. Hardcoded credentials
API_KEY = "1234567890abcdef"
SECRET_KEY = "supersecret"

# 2. SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)  # Vulnerable to SQL Injection
    user = cursor.fetchone()
    conn.close()
    return "Login successful" if user else "Login failed"

# 3. Command Injection
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    response = os.popen(f"ping -c 4 {ip}").read()  # Vulnerable to Command Injection
    return response

# 4. Insecure Deserialization
@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data
    obj = pickle.loads(data)  # Arbitrary code execution risk
    return "Deserialized successfully"

# 5. Insecure JWT token handling
@app.route("/jwt-decode")
def decode_jwt():
    token = request.args.get("token")
    decoded = jwt.decode(token, options={"verify_signature": False})  # No signature verification
    return json.dumps(decoded)

# 6. Use of MD5 for hashing
@app.route("/hash-md5")
def hash_md5():
    password = request.args.get("password")
    hashed_password = hashlib.md5(password.encode()).hexdigest()  # Weak hashing algorithm
    return hashed_password

# 7. XSS (Cross-Site Scripting)
@app.route("/search")
def search():
    query = request.args.get("query")
    return render_template_string("<h1>Results for: {} </h1>".format(query))  # XSS vulnerability

# 8. Insecure Random Number Generation
@app.route("/generate-password")
def generate_password():
    password = ''.join(random.choice(string.ascii_letters) for _ in range(8))  # Predictable random values
    return password

# 9. Untrusted XML Parsing
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    data = request.data
    root = ET.fromstring(data)  # Vulnerable to XML External Entity (XXE) attacks
    return root.tag

# 10. SSRF (Server-Side Request Forgery)
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)  # Vulnerable to SSRF
    return response.text

# 11. Insecure File Upload
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files['file']
    file.save("uploads/" + file.filename)  # No validation, could lead to RCE
    return "File uploaded"

# 12. Directory Traversal
@app.route("/read-file")
def read_file():
    filename = request.args.get("filename")
    with open(f"/var/www/{filename}", "r") as file:  # Potential directory traversal
        return file.read()

# 13. Unrestricted File Write
@app.route("/write-file", methods=["POST"])
def write_file():
    filename = request.args.get("filename")
    content = request.data.decode()
    with open(filename, "w") as file:  # Can overwrite critical files
        file.write(content)
    return "File written"

# 14. Exposing sensitive data in logs
@app.route("/debug")
def debug():
    user_input = request.args.get("input")
    app.logger.info(f"User input: {user_input}")  # Logging sensitive data
    return "Logged successfully"

# 15. Use of insecure temp files
@app.route("/temp-file")
def temp_file():
    tmp = tempfile.NamedTemporaryFile(delete=False)  # File not deleted after use
    return tmp.name

# 16. Unencrypted communication
@app.route("/send-password")
def send_password():
    password = request.args.get("password")
    return f"Your password is {password}"  # Sent over HTTP, should be HTTPS

# 17. Unrestricted Network Access
@app.route("/socket-connect")
def socket_connect():
    host = request.args.get("host")
    port = int(request.args.get("port"))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))  # Open network connection without restriction
    return "Connected"

# 18. Using eval() on user input
@app.route("/eval")
def eval_code():
    code = request.args.get("code")
    result = eval(code)  # Remote Code Execution vulnerability
    return str(result)

# 19. YAML deserialization
@app.route("/yaml-load", methods=["POST"])
def yaml_load():
    data = request.data.decode()
    obj = yaml.load(data, Loader=yaml.FullLoader)  # Unsafe deserialization
    return json.dumps(obj)

# 20. Information Disclosure via Stack Trace
@app.route("/error")
def error():
    return 1 / 0  # Will cause division by zero exception, exposing stack trace

if __name__ == "__main__":
    app.run(debug=True)  # Debug mode enabled, sensitive data may leak
