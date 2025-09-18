# signer_auto.py
import json, time, base64
from typing import Dict, Any, Optional
from jwcrypto import jwk, jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from utils.kms import decrypt_json


# ---- helpers ----
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def build_signing_input(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    protected = b64url(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode())
    body      = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    return f"{protected}.{body}"

def normalize_b64_to_b64url(s: str) -> str:
    if any(c in s for c in "+/="):
        return b64url(base64.b64decode(s))
    return s

# ---- main function ----
def sign_jwt(credential_row, header, payload):
    #credential = Credential.query.filter(Credential.credential_id == credential_id).first()
    #if not credential:
    #    return None
    if credential_row.credential_type == "sandbox":
        private_key = decrypt_json(credential_row.key)
        priv = jwk.JWK(**private_key)
        tok = jwt.JWT(header=header, claims=payload)
        tok.make_signed_token(priv)
        return tok.serialize()
    else:
        pass


def verify_jwt_auto(token, public_key) -> Dict[str, Any]:
    verified = jwt.JWT(key=public_key, jwt=token)
    return json.loads(verified.claims)


def get_list(account):
    signer = TrustedAppSigner(account)
    data = signer.get_list()
    return data


def get_credential_certificate(account, credential_id):
    signer = TrustedAppSigner(account)
    info = signer.get_credential_info(credential_id)
    return info["cert"]["certificates"][0]