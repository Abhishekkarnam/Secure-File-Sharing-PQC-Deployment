import os
from datetime import datetime
from werkzeug.utils import secure_filename
from crypto.aes_utils import encrypt_file_data, decrypt_file_data
from crypto.pqc_utils import unwrap_aes_key_with_pqc, wrap_aes_key_with_pqc
from crypto.rsa_utils import (
    decrypt_aes_key_with_rsa,
    encrypt_aes_key_with_rsa,
    load_private_key,
    load_public_key,
)
from database.models import FileMetadata, User, db
from flask import current_app


def _crypto_key_path(filename):
    return os.path.join(current_app.root_path, 'crypto', filename)


def _crypto_key_dir():
    return os.path.join(current_app.root_path, 'crypto')


def _resolve_stored_aes_key(file_record):
    if (
        file_record.pqc_kem_ciphertext
        and file_record.pqc_wrap_nonce
        and file_record.pqc_wrapped_aes_key
    ):
        return unwrap_aes_key_with_pqc(
            file_record.pqc_kem_ciphertext,
            file_record.pqc_wrap_nonce,
            file_record.pqc_wrapped_aes_key,
            _crypto_key_dir(),
        )

    stored_key = file_record.encrypted_aes_key
    # Backward compatibility: older uploads stored the raw 32-byte AES key directly.
    if len(stored_key) == 32:
        return stored_key

    private_key = load_private_key(_crypto_key_path('private.pem'))
    return decrypt_aes_key_with_rsa(stored_key, private_key)


# --- UPLOAD LOGIC ---
def save_secure_file(file, username):
    filename = secure_filename(file.filename)
    file_data = file.read()
    user = User.query.filter_by(username=username).first()
    if not user:
        return {"msg": "User not found"}

    # 1. Encrypt File Data (AES)
    aes_key, encrypted_data = encrypt_file_data(file_data)

    # 2. Keep RSA wrapping for compatibility with older records.
    public_key = load_public_key(_crypto_key_path('public.pem'))
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

    # 3. Add post-quantum ML-KEM/Kyber wrapping for the AES key.
    pqc_key_wrap = wrap_aes_key_with_pqc(aes_key, _crypto_key_dir())

    # 4. Store metadata, AES key wraps, and encrypted bytes in PostgreSQL.
    existing_file = FileMetadata.query.filter_by(
        filename=filename,
        owner_id=user.id
    ).order_by(FileMetadata.id.desc()).first()

    if existing_file:
        existing_file.encrypted_aes_key = encrypted_aes_key
        existing_file.encrypted_file_data = encrypted_data
        existing_file.key_wrap_scheme = 'RSA-OAEP+ML-KEM'
        existing_file.pqc_algorithm = pqc_key_wrap['algorithm']
        existing_file.pqc_kem_ciphertext = pqc_key_wrap['kem_ciphertext']
        existing_file.pqc_wrap_nonce = pqc_key_wrap['wrap_nonce']
        existing_file.pqc_wrapped_aes_key = pqc_key_wrap['wrapped_aes_key']
        existing_file.upload_date = datetime.utcnow()
    else:
        new_file = FileMetadata(
            filename=filename,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_file_data=encrypted_data,
            key_wrap_scheme='RSA-OAEP+ML-KEM',
            pqc_algorithm=pqc_key_wrap['algorithm'],
            pqc_kem_ciphertext=pqc_key_wrap['kem_ciphertext'],
            pqc_wrap_nonce=pqc_key_wrap['wrap_nonce'],
            pqc_wrapped_aes_key=pqc_key_wrap['wrapped_aes_key'],
            owner_id=user.id
        )
        db.session.add(new_file)

    db.session.commit()

    return {
        "msg": "File encrypted and saved successfully with RSA and PQC key wrapping",
        "filename": filename,
        "key_wrap_scheme": "RSA-OAEP+ML-KEM",
        "pqc_algorithm": pqc_key_wrap['algorithm'],
    }


# --- DOWNLOAD/DECRYPT LOGIC ---
def get_secure_file(filename):
    # 1. Get metadata from DB
    file_record = FileMetadata.query.filter_by(filename=filename).order_by(FileMetadata.id.desc()).first()
    if not file_record:
        return None

    # 2. Read the encrypted file bytes from PostgreSQL first.
    encrypted_data = file_record.encrypted_file_data
    if not encrypted_data:
        # Backward compatibility for older local uploads.
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return None

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

    # 3. Prefer PQC unwrapping when present; fall back to RSA for older files.
    aes_key = _resolve_stored_aes_key(file_record)
    decrypted_data = decrypt_file_data(aes_key, encrypted_data)

    return decrypted_data