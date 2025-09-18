import requests
from jwcrypto import jwk, jwt, jws
import base58  # type: ignore
import json
from datetime import datetime, timezone
import logging
import math
import hashlib
from random import randbytes
from utils import x509_attestation
import copy
logging.basicConfig(level=logging.INFO)
import base64
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.x509.oid import ExtensionOID
from utils import signer

"""
https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
VC/VP https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations
DIDS method https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
supported signature: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/E-signing+and+e-sealing+Verifiable+Credentials+and+Verifiable+Presentations

"""


RESOLVER_LIST = [
    'https://unires:test@unires.talao.co/1.0/identifiers/',
    'https://dev.uniresolver.io/1.0/identifiers/',
    'https://resolver.cheqd.net/1.0/identifiers/'
]

def generate_key(curve):
    """
alg value https://www.rfc-editor.org/rfc/rfc7518#page-6

+--------------+-------------------------------+--------------------+
| "alg" Param  | Digital Signature or MAC      | Implementation     |
| Value        | Algorithm                     | Requirements       |
+--------------+-------------------------------+--------------------+
| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
|              | SHA-256                       |                    |
| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-384                       |                    |
| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-512                       |                    |
| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
+--------------+-------------------------------+--------------------+
    """

    if curve in ['P-256', 'P-384', 'P-521', 'secp256k1']:
        key = jwk.JWK.generate(kty='EC', crv=curve)
    elif curve == 'RSA':
        key = jwk.JWK.generate(kty='RSA', size=2048)
    else:
        raise Exception("Curve not supported")
    return json.loads(key.export(private_key=True))


def alg(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key['kty'] == 'EC':
        if key['crv'] in ['secp256k1', 'P-256K']:
            key['crv'] = 'secp256k1'
            return 'ES256K'
        elif key['crv'] == 'P-256':
            return 'ES256'
        elif key['crv'] == 'P-384':
            return 'ES384'
        elif key['crv'] == 'P-521':
            return 'ES512'
        else:
            raise Exception("Curve not supported")
    elif key['kty'] == 'RSA':
        return 'RS256'
    elif key['kty'] == 'OKP':
        return 'EdDSA'
    else:
        raise Exception("Key type not supported")



def extract_first_san_dns_from_der_b64(cert_b64: str) -> str:
    """
    Takes a base64-encoded DER X.509 certificate and returns the first DNS name
    in its Subject Alternative Name extension, or None if not found.
    """
    if not cert_b64:
        return 
    cert_b64 += "=" * (-len(cert_b64) % 4)
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        return dns_names[0] if dns_names else None
    except x509.ExtensionNotFound:
        return None
    

def extract_first_san_uri_from_der_b64(cert_b64: str) -> str:
    """
    Returns the first URI (uniformResourceIdentifier) from the SAN extension,
    or None if not present.
    """
    if not cert_b64:
        return 
    cert_b64 += "=" * (-len(cert_b64) % 4)
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        return uris[0] if uris else None
    except x509.ExtensionNotFound:
        return None


def extract_expiration(cert_b64: str):
    if not cert_b64:
        return 
    cert_b64 += "=" * (-len(cert_b64) % 4)
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before_utc)
    not_after = getattr(cert, "not_valid_after_utc" , cert.not_valid_after_utc)
    print("not after =", not_after)
    return not_after


def pub_key(key):
    key = json.loads(key) if isinstance(key, str) else key
    Key = jwk.JWK(**key) 
    return Key.export_public(as_dict=True)


def salt():
    return base64.urlsafe_b64encode(randbytes(16)).decode().replace("=", "")


def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")


def sd(data):
    unsecured = copy.deepcopy(data)
    payload = {'_sd': []}
    disclosed_claims = ['status', 'status_list', 'idx', 'uri', 'vct', 'iat', 'nbf', 'aud', 'iss', 'exp', '_sd_alg', 'cnf']
    _disclosure = ""
    disclosure_list = unsecured.get("disclosure", [])
    for claim in [attribute for attribute in unsecured.keys()]:
        if claim == "disclosure":
            pass
        # for undisclosed attribute
        elif isinstance(unsecured[claim], (str, bool, int)) or claim in ["status", "status_list"]:
            if claim in disclosure_list or claim in disclosed_claims :
                payload[claim] = unsecured[claim]
            else:
                contents = json.dumps([salt(), claim, unsecured[claim]])
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for nested json
        elif isinstance(unsecured[claim], dict):
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim], disclosure = sd(unsecured[claim])
                if disclosure:
                    _disclosure += "~" + disclosure
            else:
                nested_content, nested_disclosure = sd(unsecured[claim])
                contents = json.dumps([salt(), claim, nested_content])
                if nested_disclosure:
                    _disclosure += "~" + nested_disclosure
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for list
        elif isinstance(unsecured[claim], list):  # list
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                nb = len(unsecured[claim])
                payload.update({claim: []})
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        nested_disclosure_list = unsecured[claim][index].get("disclosure", [])
                        if not nested_disclosure_list:
                            logging.warning("disclosure is missing for %s", claim)
                    else:
                        nested_disclosure_list = []
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        pass  # TODO
                    elif unsecured[claim][index] in nested_disclosure_list:
                        payload[claim].append(unsecured[claim][index])
                    else:
                        contents = json.dumps([salt(), unsecured[claim][index]])
                        nested_disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                        if nested_disclosure:
                            _disclosure += "~" + nested_disclosure
                        payload[claim].append({"...": hash(nested_disclosure)})
        else:
            logging.warning("type not supported")
    if payload.get('_sd'):
        # add 1 fake digest
        contents = json.dumps([salt(), "decoy", "decoy"])
        disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
        payload['_sd'].append(hash(disclosure))
    else:
        payload.pop("_sd", None)
    _disclosure = _disclosure.replace("~~", "~")
    return payload, _disclosure


def sign_sd_jwt(unsecured, credential_row, account, iss, wallet_jwk, wallet_did, draft, wallet_identifier="jwk", duration=365*24*60*60, x5c=False):
    """
    wallet_identifier : jwk | did
    subject_key = wallet pub key
    
    """
    header = {'alg': alg(credential_row.public_key)}
    
    if credential_row.credential_type == "sandbox" and x5c:
        iss = "talao.co"   
        
    public_key = credential_row.public_key or {}  
    public_key = json.loads(public_key) if isinstance(public_key, str) else public_key
    
    wallet_jwk = json.loads(wallet_jwk) if isinstance(wallet_jwk, str) else wallet_jwk
    # clean wallet jwk
    wallet_jwk.pop('use', None)
    wallet_jwk.pop('alg', None)
    payload = {
        'iss': iss,
        'iat': int(datetime.timestamp(datetime.now())),
        'exp': int(datetime.timestamp(datetime.now())) + duration,
        "_sd_alg": "sha-256",
    }
    if wallet_identifier == "jwk":
        payload['cnf'] = {"jwk": wallet_jwk}
    else:
        payload['cnf'] = {"kid": wallet_did}
    
    # Calculate selective disclosure 
    _payload, _disclosure = sd(unsecured)
    
    # update payload with selective disclosure
    payload.update(_payload)
    if not payload.get("_sd"):
        logging.info("no _sd present")
        payload.pop("_sd_alg", None)
    logging.info("sd-jwt payload = %s", json.dumps(payload, indent=4))
        
    # build header
    if int(draft) >= 15:
        header['typ'] = "dc+sd-jwt"
    else:
        header['typ'] = "vc+sd-jwt"
    if x5c:
        logging.info("x509 certificates are added")
        header['x5c'] = x509_attestation.build_x509_san_dns()
    else:
        header['kid'] = public_key.get("kid") or thumbprint(public_key)
    
    if unsecured.get('status'): 
        payload['status'] = unsecured['status']
        
    # sign with signer
    sd_token = signer.sign_jwt(account, credential_row, header, payload)
    sd_token += _disclosure + "~"
    return sd_token


def public_key_multibase_to_jwk(public_key_multibase: str):
    """
    Convert a publicKeyMultibase (Base58 encoded) into JWK format.
    Supports only secp256k1 and Ed25519 keys (Base58-btc encoding).
    """
    if not public_key_multibase.startswith("z"):
        raise ValueError("Only Base58-btc encoding (starting with 'z') is supported.")
    # Decode Base58 (removing "z" prefix)
    decoded_bytes = base58.b58decode(public_key_multibase[1:])
    # Identify the key type based on prefix
    if decoded_bytes[:2] == b'\x04\x88':  # secp256k1 key
        key_data = decoded_bytes[2:]
        curve = "secp256k1"
    elif decoded_bytes[:2] == b'\xed\x01':  # Ed25519 key
        key_data = decoded_bytes[2:]
        curve = "Ed25519"
    else:
        raise ValueError("Unsupported key type.")
    # Convert to JWK format
    if curve == "secp256k1":
        x, y = key_data[:32], key_data[32:]
        jwk = {
            "kty": "EC",
            "crv": "secp256k1",
            "x": base64.urlsafe_b64encode(x).decode().rstrip("="),
            "y": base64.urlsafe_b64encode(y).decode().rstrip("=")
        }
    elif curve == "Ed25519":
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(key_data).decode().rstrip("=")
        }
    return jwk


def base58_to_jwk(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    x_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
    jwk = {
        "kty": "OKP",  # Type de clé pour Ed25519
        "crv": "Ed25519",
        "x": x_b64url
    }
    return jwk


def base58_to_jwk_secp256k1(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    if len(key_bytes) == 33 and key_bytes[0] in (2, 3):  # Format compressé
        raise ValueError("Format compressé non supporté directement, il faut le décompresser.")
    elif len(key_bytes) == 65 and key_bytes[0] == 4:  # Format non compressé
        x_bytes = key_bytes[1:33]
        y_bytes = key_bytes[33:65]
    else:
        raise ValueError("Format de clé non reconnu.")
    x_b64url = base64.urlsafe_b64encode(x_bytes).decode().rstrip("=")
    y_b64url = base64.urlsafe_b64encode(y_bytes).decode().rstrip("=")
    jwk = {
        "kty": "EC",
        "crv": "secp256k1",
        "x": x_b64url,
        "y": y_b64url
    }
    return jwk


def resolve_did(vm) -> dict:
    """Return public key in jwk format from DID"""
    logging.info('vm = %s', vm)
    try:
        if vm[:4] != "did:":
            logging.error("Not a verificationMethod  %s", vm)
            return
        did = vm.split('#')[0]
    except Exception as e:
        logging.error("This verification method is not supported  %s", vm + " " + str(e))
        return 

    if did.split(':')[1] == "jwk":
        key = did.split(':')[2]
        key += "=" * ((4 - len(key) % 4) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(key))
        except Exception:
            logging.warning("did:jwk is not formated correctly")
            return
    else:
        for res in RESOLVER_LIST:
            try:
                r = requests.get(res + did, timeout=10)
                logging.info("resolver used = %s", res)
                break
            except Exception:
                pass
        did_document = r.json()['didDocument']
    try:
        vm_list = did_document['verificationMethod']
    except Exception:
        logging.warning("No DID Document or verification method")
        return
    for verificationMethod in vm_list:
        if verificationMethod['id'] == vm: # or (('#' + vm.split('#')[1]) == verificationMethod['id']) :
            if verificationMethod.get('publicKeyJwk'):
                jwk = verificationMethod['publicKeyJwk']
                break
            elif verificationMethod.get('publicKeyBase58'):
                if verificationMethod["type"] in ["Ed25519VerificationKey2020","Ed25519VerificationKey2018"]:
                    jwk = base58_to_jwk(verificationMethod['publicKeyBase58'])
                    break
                else:
                    jwk = base58_to_jwk_secp256k1(verificationMethod['publicKeyBase58'])
                    break
            elif verificationMethod.get("publicKeyMultibase"):
                jwk = public_key_multibase_to_jwk(verificationMethod["publicKeyMultibase"])
                break
            else:
                logging.warning("Unsupported verification method.")
                return
    return jwk


def verif_token(token: str):
    header = get_header_from_token(token)
    if x5c_list := header.get('x5c'):
        try:
            cert_der = base64.b64decode(x5c_list[0])
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            issuer_key = jwk.JWK.from_pyca(public_key)
        except Exception as e:
            raise ValueError(f"Invalid x5c certificate or public key extraction failed: {e}")

    elif header.get('jwk'):
        try:
            jwk_data = header['jwk']
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)
            issuer_key = jwk.JWK(**jwk_data)
        except Exception as e:
            raise ValueError(f"Invalid 'jwk' in header: {e}")

    elif header.get('kid'):
        dict_key = resolve_did(header['kid'])
        if not dict_key or not isinstance(dict_key, dict):
            raise ValueError(f"Unable to resolve public key from kid: {header['kid']}")
        try:
            issuer_key = jwk.JWK(**dict_key)
        except Exception as e:
            raise ValueError(f"Invalid public key structure from DID: {e}")

    else:
        raise ValueError("Header missing key info: expected 'x5c', 'jwk', or 'kid'")

    try:
        parsed_jwt = jwt.JWT.from_jose_token(token)
        parsed_jwt.validate(issuer_key)
    except Exception as e:
        raise ValueError(f"JWT signature validation failed: {e}")

    return True  # if no exceptions, verification succeeded


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        payload_as_dict = json.loads(base64.urlsafe_b64decode(payload).decode())
        return payload_as_dict
    except Exception as e:
        raise ValueError(f"Invalid token payload: {e}")


def get_header_from_token(token):
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        raise ValueError(f"Invalid token header: {e}")


def thumbprint(key):
    key = json.loads(key) if isinstance(key, str) else key
    if key.get('crv') == 'P-256K':
        key['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key)
    return signer_key.thumbprint()


def verification_method(did, key):  # = kid
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key)
    thumb_print = signer_key.thumbprint()
    return did + '#' + thumb_print



def did_resolve_lp(did):
    """
    for legal person  did:ebsi and did:web
    API v3   Get DID document with EBSI API
    https://api-pilot.ebsi.eu/docs/apis/did-registry/latest#/operations/get-did-registry-v3-identifier
    """
    url = 'https://unires:test@unires.talao.co/1.0/identifiers/' + did
    try:
        r = requests.get(url, timeout=10)
        logging.info('Access to Talao Universal Resolver')
    except Exception:
        logging.error('cannot access to Talao Universal Resolver API')
        url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
        try:
            r = requests.get(url, timeout=5)
            logging.info('Access to Public Universal Resolver')
        except Exception:
            logging.warning('fails to access to both universal resolver')
            return "{'error': 'cannot access to Universal Resolver'}"
    logging.info("DID Document = %s", r.json())
    return r.json().get('didDocument')


def load_cert_from_b64(b64_der):
    der = base64.b64decode(b64_der)
    return x509.load_der_x509_certificate(der)


def verify_signature(cert, issuer_cert):
    pubkey = issuer_cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes
            )
        else:
            return f"Error: Unsupported public key type: {type(pubkey)}"
        return None  # success
    except InvalidSignature:
        return "Error: Signature verification failed."
    except Exception as e:
        return f"Error: Verification failed with exception: {e}"


def verify_x5c_chain(x5c_list):
    """
    Verifies a certificate chain from the x5c header field of a JWT.
    
    Checks:
      1. Each certificate is signed by the next one in the list.
      2. Each certificate is valid at the current time.
    
    Args:
        x5c_list (List[str]): List of base64-encoded DER certificates (leaf to root).
    
    Returns:
        str: Info or error message.
    """
    if not x5c_list or len(x5c_list) < 2:
        return "Error: Insufficient certificate chain."

    try:
        certs = [load_cert_from_b64(b64cert) for b64cert in x5c_list]
    except Exception as e:
        return f"Error loading certificates: {e}"

    now = datetime.now(timezone.utc)

    for i, cert in enumerate(certs):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return (
                f"Error: Certificate {i} is not valid at current time:\n"
                f" - Not before: {cert.not_valid_before_utc}\n"
                f" - Not after : {cert.not_valid_after_utc}"
            )
        else:
            logging.info(f"Certificate {i} is within validity period.")

    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer_cert = certs[i + 1]
        result = verify_signature(cert, issuer_cert)
        if result:
            return f"Error: Certificate {i} verification failed: {result}"
        else:
            logging.info(f"Certificate {i} is signed by certificate {i+1}.")

    return "Info: Certificate chain and validity periods are all OK."
