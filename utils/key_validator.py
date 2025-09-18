from jwcrypto import jwk, jws

class JWKValidationError(Exception):
    pass

def _pick_alg(key: jwk.JWK) -> str:
    # Prefer an explicit alg from the JWK if present
    try:
        meta = key.export(as_dict=True)  # dict with kty/crv/alg/etc.
    except Exception:
        meta = {}
    if "alg" in meta:
        return meta["alg"]

    kty = key.key_type  # "EC", "RSA", "OKP", "oct"
    crv = getattr(key, "key_curve", None)
    if kty == "EC":
        return {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[crv]
    if kty == "RSA":
        return "RS256"  # or "PS256" if you prefer RSASSA-PSS
    if kty == "OKP":
        # Only Ed25519/Ed448 can sign with JWS -> EdDSA.
        if crv in ("Ed25519", "Ed448"):
            return "EdDSA"
        # X25519/X448 are for key exchange; we can't JWS-sign with them
        raise JWKValidationError(f"OKP curve {crv} is not a signing key (cannot run sign/verify test).")
    raise JWKValidationError(f"Unsupported key type: {kty}")


def validate_asymmetric_private_jwk(jwk_text: str) -> None:
    """
    Raises JWKValidationError if invalid. Returns None on success.
    Validation steps:
      1) Parse as JWK.
      2) Ensure asymmetric + contains private material.
      3) Export public part (sanity).
      4) Sign and verify a test payload (for signing-capable keys).
    """
    # 1) Parse
    try:
        key = jwk.JWK.from_json(jwk_text)
    except Exception as e:
        raise JWKValidationError(f"Not a valid JWK JSON: {e}")

    # 2) Must be asymmetric and have private material
    if key.is_symmetric:
        raise JWKValidationError("JWK is symmetric (kty='oct'); not an asymmetric private key.")
    if not key.has_private:
        raise JWKValidationError("JWK has no private material (public-only).")

    # 3) Export/derive public part (ensures parameters are consistent)
    try:
        pub = jwk.JWK.from_json(key.export_public())
    except Exception as e:
        raise JWKValidationError(f"Failed to derive public key from JWK: {e}")

    # 4) Cryptographic health check (when applicable)
    try:
        alg = _pick_alg(key)
        tok = jws.JWS(b"healthcheck")
        tok.add_signature(key, alg=alg, protected={"alg": alg})
        tok.verify(pub)  # raises on failure
    except JWKValidationError:
        # Reachable for OKP X25519/X448 (no JWS). Structural validation has already passed.
        return
    except Exception as e:
        raise JWKValidationError(f"Sign/verify failed with algorithm '{alg}': {e}")
