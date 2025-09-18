# simple_kms.py
import os, base64, json
from typing import Any, Dict, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_keys() -> bytes:
    try:
        with open('keys.json') as f:
            keys = json.load(f)
        kms_key =  keys.get("kms_key")
    except Exception:
        print('Unable to load keys.json — file missing or corrupted.')
        return
    return base64.b64decode(kms_key)

KEY = load_keys()

def encrypt_bytes(plaintext: bytes, aad: Optional[bytes] = None) -> str:
    """
    AES-GCM avec nonce aléatoire (12 bytes). Return base64(nonce || ciphertext).
    """
    aes = AESGCM(KEY)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    blob = nonce + ct
    return base64.b64encode(blob).decode()

def decrypt_bytes(blob_b64: str, aad: Optional[bytes] = None) -> bytes:
    """
    blob = base64(nonce||ciphertext)
    """
    blob = base64.b64decode(blob_b64)
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(KEY).decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Déchiffrement impossible (clé invalide ?)")

# Helpers JSON pratiques
def encrypt_json(data: Dict[str, Any]) -> str:
    if not data:
        return
    return encrypt_bytes(json.dumps(data, separators=(",", ":")).encode())

def decrypt_json(blob_b64: str) -> Dict[str, Any]:
    if not blob_b64:
        return
    return json.loads(decrypt_bytes(blob_b64).decode())
