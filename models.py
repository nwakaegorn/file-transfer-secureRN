from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class FileLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    username = db.Column(db.String(100))
    action = db.Column(db.String(50))
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))
    sha256 = db.Column(db.String(128))
    md5 = db.Column(db.String(64))
    alert = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(300))
