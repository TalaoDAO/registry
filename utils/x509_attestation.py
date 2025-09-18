from datetime import datetime, timedelta, timezone
import json
import base64
from typing import Tuple, List, Union, Dict, Optional

from jwcrypto import jwk, jwt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature

# ──────────────────────────────────────────────────────────────────────────────
# Load keys from a JSON file
# ──────────────────────────────────────────────────────────────────────────────
with open('keys.json') as f:
    keys = json.load(f)
TRUST_ANCHOR_KEY: Dict = keys['RSA_key']  # Root CA (private key JWK)
#TRUST_ANCHOR_KEY: Dict = keys["credentials"][0]["request_key"]  # Root CA (private key JWK)

#SIGNER_KEY: Dict = keys["credentials"][0]["request_key"]  # Leaf private key JWK
SIGNER_KEY: Dict = keys['RSA_key']  # Leaf private key JWK

DID = keys["credentials"][0]["did"]
X5C = keys["credentials"][0]["x5c"]

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def alg(key: Union[str, Dict]) -> str:
    key = json.loads(key) if isinstance(key, str) else key
    kty = key.get('kty')
    crv = key.get('crv', '')
    if kty == 'EC':
        return {'secp256k1':'ES256K','P-256':'ES256','P-384':'ES384','P-521':'ES512'}[crv]
    if kty == 'RSA':
        return 'RS256'
    if kty == 'OKP':
        return 'EdDSA'
    raise ValueError("Unsupported key type/curve")

def jwk_to_private_key(key_jwk: Dict):
    """Return a cryptography private key object from a JWK."""
    pem = jwk.JWK(**key_jwk).export_to_pem(private_key=True, password=None)
    return serialization.load_pem_private_key(pem, password=None)

def verify_trust_chain(base64_chain: List[str]) -> None:
    certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in base64_chain]
    leaf_cert, issuer_cert = certs[0], certs[1]
    issuer_public_key = issuer_cert.public_key()
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                ec.ECDSA(leaf_cert.signature_hash_algorithm),
            )
        print("✅ Leaf certificate is correctly signed by the issuer.")
    except InvalidSignature:
        print("❌ Invalid signature: the chain is broken.")
    except Exception as e:
        print(f"⚠️ Verification failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# Cert generation with stronger profile + small clock skew tolerance
# ──────────────────────────────────────────────────────────────────────────────
def generate_certificates(signer_key: Dict, trust_anchor_key: Dict) -> Tuple[x509.Certificate, x509.Certificate, object]:
    """
    Generate X.509 certificates for the trust anchor (self-signed) and signer (leaf).
    Returns:
        (leaf_cert, ca_cert, leaf_private_key)
    """
    ca_priv = jwk_to_private_key(trust_anchor_key)
    leaf_priv = jwk_to_private_key(signer_key)
    now = datetime.now(timezone.utc)
    skew = timedelta(minutes=5)

    # ---- CA (self-signed) ----
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet Trust Anchor"),
        x509.NameAttribute(NameOID.COMMON_NAME, "talao.io"),
    ])
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - skew)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_priv.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_priv.public_key()), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("talao.io")]),
            critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    ca_cert = ca_builder.sign(private_key=ca_priv, algorithm=hashes.SHA256())

    # ---- Leaf (issued by CA) ----
    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Web3 Digital Wallet"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Talao"),
    ])
    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_subject)
        .public_key(leaf_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - skew)
        .not_valid_after(now + timedelta(days=825))  # ~27 months typical max for TLS leaf
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_priv.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_priv.public_key()), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("talao.io"),
                x509.UniformResourceIdentifier("https://talao.io")
            ]),
            critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,       # enable if using RSA/TLS
                content_commitment=False,
                data_encipherment=False,
                key_agreement=isinstance(leaf_priv, ec.EllipticCurvePrivateKey),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
    )
    leaf_cert = leaf_builder.sign(private_key=ca_priv, algorithm=hashes.SHA256())

    return leaf_cert, ca_cert, leaf_priv

# ──────────────────────────────────────────────────────────────────────────────
# PKCS#12 (.p12/.pfx) export
# ──────────────────────────────────────────────────────────────────────────────
def create_pkcs12(
    leaf_private_key,
    leaf_cert: x509.Certificate,
    chain: Optional[List[x509.Certificate]] = None,
    password: Optional[str] = None,
    friendly_name: str = "issuer.talao.co",
) -> bytes:
    """
    Build a PKCS#12 blob containing:
      - the LEAF private key
      - the LEAF certificate
      - the (optional) CA chain
    """
    if password is None or password == "":
        # Strongly recommended to set a password; some clients reject unprotected P12
        encryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password.encode())

    pfx = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode(),
        key=leaf_private_key,
        cert=leaf_cert,
        cas=chain or None,
        encryption_algorithm=encryption,
    )
    return pfx

# ──────────────────────────────────────────────────────────────────────────────
# Existing helpers (unchanged): x5c generation & verifier attestation
# ──────────────────────────────────────────────────────────────────────────────
def generate_x509_san_dns_base64_chain() -> List[str]:
    """Return base64 DER chain (leaf first) for x5c headers."""
    leaf, ca, _ = generate_certificates(SIGNER_KEY, TRUST_ANCHOR_KEY)
    return [
        base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode(),
        base64.b64encode(ca.public_bytes(serialization.Encoding.DER)).decode(),
    ]

def build_x509_san_dns():
    """this function is called by oidc4vc.py"""
    return X5C

def build_verifier_attestation(sub: str) -> str:
    rsa_key = jwk.JWK(**SIGNER_KEY)
    public_key = rsa_key.export(private_key=False, as_dict=True)
    public_key.pop('kid', None)
    header = {'typ': "verifier-attestation+jwt", 'alg': alg(SIGNER_KEY)}
    payload = {'iss': DID, 'sub': sub, 'cnf': {"jwk": public_key}, 'exp': datetime.now(tz=timezone.utc).timestamp() + 1000}
    token = jwt.JWT(header=header, claims=payload, algs=[alg(SIGNER_KEY)])
    token.make_signed_token(rsa_key)
    return token.serialize()

# ──────────────────────────────────────────────────────────────────────────────
# CLI demo: generate certs, verify chain, and write a leaf.p12
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # 1) Generate (leaf, ca, key)
    leaf_cert, ca_cert, leaf_key = generate_certificates(SIGNER_KEY, TRUST_ANCHOR_KEY)

    # 2) Verify via base64 x5c chain (leaf, ca)
    chain_b64 = [
        base64.b64encode(leaf_cert.public_bytes(serialization.Encoding.DER)).decode(),
        base64.b64encode(ca_cert.public_bytes(serialization.Encoding.DER)).decode(),
    ]
    verify_trust_chain(chain_b64)

    # 3) Export PKCS#12
    p12_password = "suc2cane"
    pfx_bytes = create_pkcs12(
        leaf_private_key=leaf_key,
        leaf_cert=leaf_cert,
        #chain=[ca_cert],                # include CA cert(s) so clients build the chain
        chain= None,
        password=p12_password,
        friendly_name="talao.io"
    )
    with open("leaf_talao_io.p12", "wb") as f:
        f.write(pfx_bytes)
    print("📦 Wrote PKCS#12 to leaf.p12")
