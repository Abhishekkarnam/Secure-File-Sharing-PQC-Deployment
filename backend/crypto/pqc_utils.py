import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PQC_ALGORITHM = "ML-KEM-768"
PUBLIC_KEY_FILE = "pqc_public.bin"
PRIVATE_KEY_FILE = "pqc_private.bin"


def _load_kem_module():
    try:
        from pqcrypto.kem import ml_kem_768
        return ml_kem_768
    except ImportError:
        try:
            from pqcrypto.kem import kyber768
            return kyber768
        except ImportError as exc:
            raise RuntimeError(
                "PQC support requires the pqcrypto package. Install it with: pip install pqcrypto"
            ) from exc


def _pqc_key_path(key_dir, filename):
    return os.path.join(key_dir, filename)


def ensure_pqc_keypair(key_dir):
    public_key_path = _pqc_key_path(key_dir, PUBLIC_KEY_FILE)
    private_key_path = _pqc_key_path(key_dir, PRIVATE_KEY_FILE)

    if os.path.exists(public_key_path) and os.path.exists(private_key_path):
        with open(public_key_path, "rb") as public_file:
            public_key = public_file.read()
        with open(private_key_path, "rb") as private_file:
            private_key = private_file.read()
        return public_key, private_key

    kem = _load_kem_module()
    public_key, private_key = kem.generate_keypair()

    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key)
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key)

    return public_key, private_key


def _derive_wrapping_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-file-sharing-pqc-aes-key-wrap-v1",
    ).derive(shared_secret)


def wrap_aes_key_with_pqc(aes_key, key_dir):
    public_key, _ = ensure_pqc_keypair(key_dir)
    kem = _load_kem_module()

    kem_ciphertext, shared_secret = kem.encrypt(public_key)
    wrapping_key = _derive_wrapping_key(shared_secret)

    nonce = os.urandom(12)
    wrapped_aes_key = AESGCM(wrapping_key).encrypt(nonce, aes_key, None)

    return {
        "algorithm": PQC_ALGORITHM,
        "kem_ciphertext": kem_ciphertext,
        "wrap_nonce": nonce,
        "wrapped_aes_key": wrapped_aes_key,
    }


def unwrap_aes_key_with_pqc(kem_ciphertext, wrap_nonce, wrapped_aes_key, key_dir):
    _, private_key = ensure_pqc_keypair(key_dir)
    kem = _load_kem_module()

    shared_secret = kem.decrypt(private_key, kem_ciphertext)
    wrapping_key = _derive_wrapping_key(shared_secret)

    return AESGCM(wrapping_key).decrypt(wrap_nonce, wrapped_aes_key, None)