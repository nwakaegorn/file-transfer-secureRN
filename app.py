import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, send_file, url_for, jsonify
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from models import db, User, FileLog
from config import Config
from sqlalchemy import inspect

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# -----------------------------
# Sensitive File Policy
# -----------------------------
SENSITIVE_KEYWORDS = [
    "confidential",
    "secret",
    "restricted",
    "finance"
]

# -----------------------------
# Encryption Key Setup
# -----------------------------
if not os.path.exists("secret.key"):
    key = Fernet.generate_key()

    with open("secret.key", "wb") as key_file:
        key_file.write(key)

with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

# -----------------------------
# Create Required Folders
# -----------------------------
os.makedirs(
    app.config['UPLOAD_FOLDER'],
    exist_ok=True
)

os.makedirs(
    app.config['ENCRYPTED_FOLDER'],
    exist_ok=True
)

# -----------------------------
# Database Initialization
# -----------------------------
with app.app_context():

    inspector = inspect(db.engine)

    if "file_log" not in inspector.get_table_names():
        db.create_all()

    # Create default admin
    if not User.query.filter_by(username="admin").first():

        admin = User(
            username="admin",
            password=generate_password_hash("admin123")
        )

        db.session.add(admin)
        db.session.commit()

# -----------------------------
# Utility Functions
# -----------------------------
def generate_hashes(data):

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    return sha256, md5


def is_sensitive(filename):

    return any(
        keyword.lower() in filename.lower()
        for keyword in SENSITIVE_KEYWORDS
    )


def log_event(
    filename,
    username,
    action,
    status,
    sha256=None,
    md5=None,
    alert=False,
    message=""
):

    log = FileLog(
        filename=filename,
        username=username,
        action=action,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow(),
        status=status,
        sha256=sha256,
        md5=md5,
        alert=alert,
        message=message
    )

    db.session.add(log)
    db.session.commit()

# -----------------------------
# Home Route
# -----------------------------
@app.route('/')
def home():

    return redirect(url_for('dashboard'))

# -----------------------------
# Upload Route
# -----------------------------
@app.route('/upload', methods=['POST'])
def upload():

    file = request.files.get('file')
    username = "admin"

    if not file:
        return "No file selected"

    try:

        file_data = file.read()

        sha256, md5 = generate_hashes(file_data)

        alert_flag = False
        message = "File uploaded successfully"

        # Detect sensitive filenames
        if is_sensitive(file.filename):

            alert_flag = True
            message = "ALERT: Sensitive file upload detected"

        # Encrypt file
        encrypted_data = cipher.encrypt(file_data)

        encrypted_path = os.path.join(
            app.config['ENCRYPTED_FOLDER'],
            file.filename + ".enc"
        )

        with open(encrypted_path, "wb") as f:
            f.write(encrypted_data)

        # Log event
        log_event(
            file.filename,
            username,
            "upload",
            "success",
            sha256,
            md5,
            alert_flag,
            message
        )

        return redirect(url_for('dashboard'))

    except Exception as e:

        log_event(
            file.filename,
            username,
            "upload",
            "failure",
            alert=True,
            message=str(e)
        )

        return f"Upload Failed: {str(e)}"

# -----------------------------
# Download Route
# -----------------------------
@app.route('/download/<filename>')
def download(filename):

    username = "admin"

    encrypted_path = os.path.join(
        app.config['ENCRYPTED_FOLDER'],
        filename + ".enc"
    )

    if not os.path.exists(encrypted_path):

        log_event(
            filename,
            username,
            "download",
            "failure",
            alert=True,
            message="File not found"
        )

        return "File Not Found"

    try:

        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        sha256, md5 = generate_hashes(decrypted_data)

        alert_flag = False
        message = "File downloaded successfully"

        # Detect sensitive downloads
        if is_sensitive(filename):

            alert_flag = True
            message = "ALERT: Sensitive file download detected"

        # Log event
        log_event(
            filename,
            username,
            "download",
            "success",
            sha256,
            md5,
            alert_flag,
            message
        )

        # Temporary file for sending
        temp_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            filename
        )

        with open(temp_path, "wb") as f:
            f.write(decrypted_data)

        return send_file(
            temp_path,
            as_attachment=True
        )

    except Exception as e:

        log_event(
            filename,
            username,
            "download",
            "failure",
            alert=True,
            message=str(e)
        )

        return f"Download Failed: {str(e)}"

# -----------------------------
# Dashboard Route
# -----------------------------
@app.route('/dashboard')
def dashboard():

    logs = FileLog.query.order_by(
        FileLog.timestamp.desc()
    ).all()

    return render_template(
        'dashboard.html',
        logs=logs
    )

# -----------------------------
# Security Report API
# -----------------------------
@app.route('/security-report')
def security_report():

    total_transfers = FileLog.query.count()

    violations = FileLog.query.filter_by(
        alert=True
    ).count()

    failed = FileLog.query.filter_by(
        status="failure"
    ).count()

    sensitive_transfers = FileLog.query.filter(
        FileLog.message.contains("Sensitive")
    ).count()

    report = {
        "Total Transfers": total_transfers,
        "Policy Violations": violations,
        "Failed Transfers": failed,
        "Sensitive File Movements": sensitive_transfers,
        "Generated At": datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    }

    return jsonify(report)

# -----------------------------
# Run Application
# -----------------------------
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
