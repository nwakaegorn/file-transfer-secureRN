import os

class Config:
    SECRET_KEY = 'supersecretkey'
    JWT_SECRET_KEY = 'jwt-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secure_transfer.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'
