from .db import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')

class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False) # BLOB
    encrypted_file_data = db.Column(db.LargeBinary, nullable=False) # BLOB
    key_wrap_scheme = db.Column(db.String(50), default='RSA-OAEP')
    pqc_algorithm = db.Column(db.String(50))
    pqc_kem_ciphertext = db.Column(db.LargeBinary)
    pqc_wrap_nonce = db.Column(db.LargeBinary)
    pqc_wrapped_aes_key = db.Column(db.LargeBinary)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), index=True)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))

