
# =============================================================================
# OIDC ⇄ OIDC4VP BRIDGE — DEVELOPER OVERVIEW (COMMENT-ONLY)
# =============================================================================
# This module acts as a bridge between:
#   • Relying Party (RP) / Client applications that speak **classic OIDC**
#   • Wallet/Holders that speak **OIDC4VP** (OpenID for Verifiable Presentations)
#
# GOAL
# ----
# Make RPs happy by exposing standard OIDC endpoints (/authorize, /token, /userinfo,
# /.well-known/openid-configuration, /jwks.json, /logout) while we do the VC/VP dance
# with the wallet behind the scenes using OIDC4VP. The RP never needs to understand
# VC formats; it only consumes normal OIDC tokens + an optional `/userinfo` call.
#
# HIGH-LEVEL HAPPY PATH
# ---------------------
# 1) RP → /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid
#               &state=...&nonce=...&code_challenge=...&authorization_details=...
#    - We validate client + redirect_uri, generate an authorization code `code`,
#      store request context in Redis under key `{code}`, and redirect the user to
#      our wallet UI (/verifier/wallet?code=...).
#
# 2) Wallet flow (OIDC4VP) happens:
#    - We request a VP that satisfies the presentation definition (from scope or
#      `authorization_details`), verify it, and store results in Redis as
#      `{code}_wallet_data`.
#
# 3) We finish the OIDC front-channel step:
#    - For response_type=code (recommended): redirect RP back with ?code=...&state=...
#    - (Sandbox only) For response_type=id_token: we return an ID Token directly to
#      redirect_uri (fragment by default unless response_mode=query).
#
# 4) RP → /token (POST) with client authentication and:
#      grant_type=authorization_code, code=..., redirect_uri=..., code_verifier=...
#    - We validate client credentials (Basic or client_secret_post), the code, the
#      redirect_uri binding and PKCE (code_verifier). On success we return:
#        {
#          "id_token": <JWT signed by this bridge (issuer = our OP)>,
#          "access_token": <opaque uuid4>,
#          "token_type": "Bearer",
#          "expires_in": ACCESS_TOKEN_LIFE
#        }
#    - We also store `{access_token}_wallet_data` so `/userinfo` can later return
#      the verified VP to the RP.
#
# 5) RP → /userinfo with Authorization: Bearer <access_token>
#    - On success (200) we return:
#        { "sub": "<subject>", "vp_token": <the verified VP> }
#    - On failure (expired/unknown token) we return 401 with
#        { "error": "invalid_token", "error_description": "..." }
#      and a WWW-Authenticate: Bearer header.



from flask import request, render_template, redirect,current_app
from flask import session, Response, jsonify, flash
import json, base64
import uuid
import logging
from datetime import datetime, timezone, timedelta
import requests
from jwcrypto import jwk, jwt
import pkce
from utils import oidc4vc, signer
import base64
from db_model import Signin, Credential, User, db
from utils.kms import decrypt_json
from flask_login import logout_user
import secrets
from urllib.parse import urlparse, urlencode

logging.basicConfig(level=logging.INFO)

# customer application 
ACCESS_TOKEN_LIFE = 2000
CODE_LIFE = 2000

# wallet
QRCODE_LIFE = 2000

# OpenID key of the OP for customer application
RSA_KEY_DICT = json.load(open("keys.json", "r"))['RSA_key']
rsa_key = jwk.JWK(**RSA_KEY_DICT) 
public_rsa_key = rsa_key.export(private_key=False, as_dict=True)


def init_app(app):
    # endpoints for application authorization flow bridge
    app.add_url_rule('/signin/wallet', view_func=signin_qrcode, methods=['GET', 'POST'])
    
    # openid configuration of walletw
    #app.add_url_rule('/signin/wallet/.well-known/openid-configuration',  view_func=wallet_openid_configuration, methods = ['GET'])
    
    # endpoints for wallet
    app.add_url_rule('/signin/wallet/callback',  view_func=signin_response, methods=['POST']) # redirect_uri for PODST
    app.add_url_rule('/signin/wallet/request_uri/<stream_id>',  view_func=signin_request_uri, methods=['GET'])
    app.add_url_rule('/signin/wallet/followup',  view_func=signin_login_followup, methods=['GET'])
    
    # event
    app.add_url_rule('/signin/wallet/stream',  view_func=signin_login_stream)
    return
    


def build_id_token(client_id, sub, nonce, vp_token):
    mode = current_app.config["MODE"]
    now = int(datetime.now(timezone.utc).timestamp())
    header = {"typ": "JWT", "kid": RSA_KEY_DICT['kid'], "alg": "RS256"}
    payload = {
        "iss": mode.server + "signin/app",
        "aud": client_id,
        "iat": now,
        "nbf": now,
        "exp": now + 1000,
        "sub": sub,
    }
    if nonce:
        payload["nonce"] = nonce
    logging.info("id_token for application = %s", payload)
    token = jwt.JWT(header=header, claims=payload, algs=["RS256"])
    token.make_signed_token(jwk.JWK(**RSA_KEY_DICT))
    return token.serialize()


# Endpoint
def oidc_jwks():
    return {"keys": [public_rsa_key]}


# Endpoint for customer app
def oidc_openid_configuration():
    """
    For the customer application of the saas platform  
    https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-dynamic-self-issued-openid-
    """
    mode = current_app.config["MODE"]
    return {
        "issuer": mode.server + 'signin/app',
        "authorization_endpoint":  mode.server + 'signin/app/authorize',
        "token_endpoint": mode.server + 'signin/app/token',
        "userinfo_endpoint": mode.server + 'signin/app/userinfo',
        "logout_endpoint": mode.server + 'signin/app/logout',
        "jwks_uri": mode.server + 'signin/app/jwks.json',
        "scopes_supported": ["openid", "email", "profile", "over18"],
        "response_types_supported": ["code", "id_token"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
    }


def oidc_authorize():
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    
    def same_origin_as_client(redirect_uri: str, client_base_url: str) -> bool:
        """Simple, registry-free safety: only allow redirect_uri with same scheme+host as client's base URL.
        Allows http only for localhost."""
        try:
            ru, cu = urlparse(redirect_uri), urlparse(client_base_url)
            if not ru.scheme or not ru.netloc:
                return False
            if ru.scheme not in {"https", "http"}:
                return False
            # allow http for localhost development
            if ru.scheme == "http" and ru.hostname != mode.IP:
                return False
            return (ru.scheme, ru.hostname, ru.port or (80 if ru.scheme =="http" else 443)) == \
                (cu.scheme, cu.hostname, cu.port or (80 if cu.scheme =="http" else 443))
        except Exception:
            return False

    def redirect_with(redirect_uri: str, params: dict, use_fragment: bool = False):
        sep = "#" if use_fragment else "?"
        logging.info("sep = %s", sep)
        return redirect(redirect_uri + sep + urlencode({k: v for k, v in params.items() if v is not None}), code=302)

    logging.info("authorization request received: %s", dict(request.args))
    session.setdefault("verified", False)

    # ---- If user already verified and we’re finishing the flow ----
    if session.get("verified") and request.args.get("code"):
        logging.info("session is verifier")
        code = request.args["code"]
        raw = red.get(code)
        if not raw:
            logging.error("code context missing/expired")
            session.clear()
            return {"error": "access_denied"}, 400

        data = json.loads(raw.decode("utf-8"))
        redirect_uri = data["redirect_uri"]
        response_type = data.get("response_type", "code")
        state = data.get("state")
        
        if response_type == "code":
            return redirect_with(redirect_uri, {"code": code, "state": state}, use_fragment=False)

        # Minimal sandbox implicit (id_token) support
        if response_type == "id_token":
            wallet_raw = red.get(f"{code}_wallet_data")
            if not wallet_raw:
                session.clear()
                return redirect_with(redirect_uri, {"error": "access_denied", "state": state}, use_fragment=True)
            wallet = json.loads(wallet_raw.decode("utf-8"))
            vp_fmt = wallet.get("vp_format")
            if vp_fmt == "ldp_vp":
                vp = wallet["vp_token"]
                id_token = build_id_token(data["client_id"], wallet["sub"], data.get("nonce"), vp)
            else:
                id_token = build_id_token(data["client_id"], wallet["sub"], data.get("nonce"), wallet["vp_token"])
            return redirect_with(
                redirect_uri,
                {
                    "id_token": id_token,
                    "state": state,
                },
                use_fragment=(data.get("response_mode") != "query"),
            )

        # Fallback
        session.clear()
        return redirect_with(redirect_uri, {"error": "access_denied", "state": state})

    # ---- Error coming back from the wallet step ----
    if "error" in request.args:
        err = request.args["error"]
        code = request.args.get("code")
        raw = red.get(code) if code else None
        if not raw:
            return {"error": "access_denied"}, 400
        data = json.loads(raw.decode("utf-8"))
        red.delete(code)
        return redirect_with(
            data["redirect_uri"],
            {"error": err, "error_description": request.args.get("error_description"), "state": data.get("state")},
        )

    # ---- New authorization request (user not verified yet) ----
    logging.info("session is not verified")
    # Required params
    try:
        client_id = request.args["client_id"]
        redirect_uri = request.args["redirect_uri"]
        response_type = request.args["response_type"]  # "code" (recommended) or "id_token" (sandbox)
    except KeyError as e:
        return {"error": "invalid_request", "error_description": f"Missing {e.args[0]}"}, 400

    # Minimal client lookup just to obtain its base URL (no redirect URI registry)
    signin = Signin.query.filter_by(application_api_client_id=client_id).first()
    if not signin:
        return {"error": "unauthorized_client"}, 400

    try:
        client_cfg = decrypt_json(signin.application_api)  # expected to include at least {"url": "..."}
        client_base_url = client_cfg["url"]
    except Exception:
        logging.exception("client config missing url")
        return {"error": "server_error"}, 500

    # Simple safety: allow only same-origin redirect to the client's base URL
    #if not same_origin_as_client(redirect_uri, client_base_url):
    #    return {"error": "invalid_request", "error_description": "redirect_uri not allowed for this client"}, 400

    if response_type not in ("code", "id_token"):
        return {"error": "unsupported_response_type"}, 400

    # Optional params
    scope = request.args.get("scope", "")
    scope = scope.split() if scope else []
    
    response_types = []
    # Add vp_token if any of these scopes are requested
    if set(scope) & {"email", "over18", "profile"}:  
        response_types.append("vp_token")
    # Add id_token if openid is requested
    if "openid" in scope:
        response_types.append("id_token")
    wallet_response_type = " ".join(response_types) if response_types else None
    
    data = {
        "client_id": client_id,
        "scope": scope,
        "state": request.args.get("state"),
        "response_type": response_type,
        "wallet_response_type": wallet_response_type,
        "redirect_uri": redirect_uri,
        "nonce": request.args.get("nonce"),
        "code_challenge": request.args.get("code_challenge"),
        "code_challenge_method": request.args.get("code_challenge_method"),
        "response_mode": request.args.get("response_mode"),
        "authorization_details": request.args.get("authorization_details"),
        "signin_id": signin.id,
        "mode": request.args.get("mode"),
        "expires": datetime.timestamp(datetime.now()) + CODE_LIFE,
    }
    
    # Persist short-lived code context and hand off to wallet step
    code = secrets.token_urlsafe(32)
    red.setex(code, CODE_LIFE, json.dumps(data))

    # Stash a couple of things for error fallback (no redirect registry)
    session["verified"] = False
    session["client_id"] = client_id

    return redirect(f"/signin/wallet?code={code}", code=302)



# token endpoint for customer application
def oidc_token():
    red = current_app.config["REDIS"]
    logging.info("token endpoint request")

    # ------- helpers -------
    def manage_error(error, error_description=None, status=400, www_authenticate=None):
        body = {"error": error}
        if error_description:
            body["error_description"] = error_description
        headers = {}
        if www_authenticate:
            headers["WWW-Authenticate"] = www_authenticate
        return body, status, headers

    def parse_basic_auth(auth_header):
        # Expect "Basic base64(client_id:client_secret)"
        try:
            scheme, value = auth_header.split(" ", 1)
            if scheme.lower() != "basic":
                return None, None
            decoded = base64.b64decode(value).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret
        except Exception:
            return None, None

    # ------- client authentication (RFC 6749 §2.3) -------
    client_id = None
    client_secret = None

    auth_header = request.headers.get("Authorization")
    if auth_header:
        cid, csec = parse_basic_auth(auth_header)
        if cid and csec:
            client_id, client_secret = cid, csec
            logging.info("client authentication: client_secret_basic")
        else:
            # Malformed/invalid Basic credentials
            return manage_error(
                "invalid_client",
                "Malformed client authentication.",
                status=401,
                www_authenticate='Basic realm="token"'
            )
    else:
        # Fallback to client_secret_post
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")
        if not client_id or not client_secret:
            return manage_error(
                "invalid_client",
                "Client authentication required.",
                status=401,
                www_authenticate='Basic realm="token"'
            )
        logging.info("client authentication: client_secret_post")

    # ------- required form parameters -------
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    code_signin = request.form.get("code_signin")

    if not grant_type or not code or not redirect_uri:
        return manage_error("invalid_request", "Missing required parameters: grant_type, code, redirect_uri.")

    if grant_type != "authorization_code":
        return manage_error("unsupported_grant_type", "Only authorization_code is supported.")

    # ------- look up client and authorization code -------
    signin = Signin.query.filter_by(application_api_client_id=client_id).first()
    if not signin:
        # unknown client_id
        return manage_error(
            "invalid_client",
            "Unknown client_id.",
            status=401,
            www_authenticate='Basic realm="token"'
        )

    try:
        stored_client_secret = decrypt_json(signin.application_api)["client_secret"]
    except Exception:
        logging.exception("Failed to read client secret from DB")
        return manage_error("server_error", "Server configuration error.", status=500)

    if client_secret != stored_client_secret:
        return manage_error(
            "invalid_client",
            "Invalid client credentials.",
            status=401,
            www_authenticate='Basic realm="token"'
        )

    try:
        data_raw = red.get(code)
        if not data_raw:
            raise KeyError("code not found")
        data = json.loads(data_raw.decode("utf-8"))
    except Exception:
        logging.warning("authorization code not found or expired")
        # RFC 6749: use invalid_grant for expired/revoked/invalid code
        return manage_error("invalid_grant", "Invalid or expired authorization code.")

    # Validate binding of the code to client and redirect_uri
    if client_id != data.get("client_id"):
        return manage_error("invalid_grant", "Authorization code was not issued to this client.")
    if redirect_uri != data.get("redirect_uri"):
        # At the token endpoint this should be invalid_grant (not invalid_redirect_uri)
        return manage_error("invalid_grant", "redirect_uri does not match the authorization request.")

    # ------- PKCE validation (RFC 7636) -------
    code_challenge = data.get("code_challenge")
    if code_challenge:
        if not code_signin:
            return manage_error("invalid_grant", "Missing code_signin.")
        if pkce.get_code_challenge(code_signin) != code_challenge:
            logging.warning("PKCE verification failed")
            return manage_error("invalid_grant", "Invalid code_signin.")
    else:
        logging.info("PKCE not used for this authorization request.")

    # ------- build tokens -------
    try:
        wallet_raw = red.get(f"{code}_wallet_data")
        if not wallet_raw:
            raise KeyError("wallet data missing")
        code_wallet_data = json.loads(wallet_raw.decode("utf-8"))
    except Exception:
        logging.error("Failed to load wallet data for code")
        return manage_error("invalid_grant", "Authorization code context not available.")

    sub = code_wallet_data.get("sub")
    vp_token = code_wallet_data.get("vp_token")
    id_token = code_wallet_data.get("id_token")
    presentation_submission = code_wallet_data.get("presentation_submission")
    
    idt = build_id_token(
        client_id,
        sub,
        data.get("nonce"),
        vp_token if vp_token else None
    )

    # Access token
    access_token = str(uuid.uuid4())  # prefer uuid4 over uuid1

    # Persist access token context for application
    red.setex(
        f"{access_token}_wallet_data",
        ACCESS_TOKEN_LIFE,
        json.dumps({
            "client_id": client_id,
            "sub": sub,
            "vp_token": vp_token,
            "id_token": id_token,
            "presentation_submission": presentation_submission
        })
    )

    # Invalidate single-use artifacts
    try:
        red.delete(code)
        red.delete(f"{code}_wallet_data")
    except Exception:
        # non-fatal; log and continue
        logging.warning("Failed to delete used authorization code/ctx from Redis")

    logging.info("Issued id_token and access_token from token endpoint")

    return {
        "id_token": idt,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFE
    }, 200



# logout endpoint
def oidc_logout():
    if not session.get('verified'):
        return ('Forbidden'), 403
    vals = request.values
    post_logout_redirect_uri = vals.get("post_logout_redirect_uri")
    state = vals.get("state")
    if not post_logout_redirect_uri:
        post_logout_redirect_uri = session.get('redirect_uri')
    # End session (idempotent)
    try:
        logout_user()
    except Exception:
        pass
    session.clear()
    logging.info("logout call received, redirect to %s", post_logout_redirect_uri)
    target = post_logout_redirect_uri
    if state:
        target += "&state=" + state 
    return redirect(target)


# userinfo endpoint
def oidc_userinfo():
    red = current_app.config["REDIS"]
    logging.info("userinfo endpoint request")

    # 1) Extract Bearer token from header or query parameter (fallback)
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
    if not token:
        # Fallback for legacy callers (your code hinted at this)
        token = request.args.get("access_token")

    if not token:
        body = {
            "error": "invalid_request",
            "error_description": "Missing access token (use Authorization: Bearer <token>)."
        }
        headers = {"WWW-Authenticate": 'Bearer error="invalid_request"'}
        return body, 401, headers

    try:
        raw = red.get(f"{token}_wallet_data")
        if not raw:
            # Not found / expired in Redis
            body = {
                "error": "invalid_token",
                "error_description": "The access token is invalid or has expired."
            }
            headers = {"WWW-Authenticate": 'Bearer error="invalid_token", error_description="expired or unknown token"'}
            return body, 401, headers

        wallet_data = json.loads(raw.decode("utf-8"))

        # Validate the essential fields exist
        sub = wallet_data.get("sub")
        vp_token = wallet_data.get("vp_token")
        id_token = wallet_data.get("id_token")
        presentation_submission = wallet_data.get("presentation_submission")
        if not sub or vp_token is None:
            body = {
                "error": "invalid_token",
                "error_description": "Token payload is malformed (missing sub or vp_token)."
            }
            headers = {"WWW-Authenticate": 'Bearer error="invalid_token"'}
            return body, 401, headers

        # 2) Success → 200 with the documented schema
        payload = {
            "sub": sub,
            "vp_token": vp_token,
            "id_token": id_token,
            "presentation_submission": presentation_submission
        }
        return payload, 200

    except Exception as e:
        logging.exception("userinfo lookup failed")
        body = {
            "error": "server_error",
            "error_description": f"Internal error while processing token: {e}"
        }
        headers = {"WWW-Authenticate": 'Bearer error="server_error"'}
        return body, 500, headers

        

    
################################# SIOPV2 + OIDC4VP ###########################################

"""
def wallet_openid_configuration():
    config = json.load(open("ebsiv3_siopv2_openid_configuration.json", "r"))
    return jsonify(config)
"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _json_compact(obj) -> bytes:
    # Canonical-ish JSON (no spaces, stable key order)
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_jwt_request( credential_id, jwt_request, client_id_scheme) -> str:
    credential = Credential.query.filter(Credential.credential_id == credential_id).first()
    if not credential:
        return None

    private_key = decrypt_json(credential.key)

    header = {"typ": "oauth-authz-req+jwt"}  # RFC 9101 / OpenID specs
    if client_id_scheme == "x509_san_dns":
        header["x5c"] = json.loads(credential.x5c)
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
    elif client_id_scheme == "verifier_attestation":
        header["jwt"] = credential.verifier_attestation
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
    elif client_id_scheme == "redirect_uri":
        header["alg"] = "none"
    else:  # DID by default
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
        header["kid"] = credential.verification_method

    payload = {
        "aud": "https://self-issued.me/v2",
        "exp": int(datetime.timestamp(datetime.now() + timedelta(seconds=1000))),
        **jwt_request,
    }

    if header["alg"] == "none":
        # Use the 2-segment unsecured form: <header>.<payload>
        h = _b64url(_json_compact(header))
        p = _b64url(_json_compact(payload))
        return f"{h}.{p}."
    else:
        # Your existing signer for JWS
        return signer.sign_jwt( credential_id, private_key, credential.credential_type, header, payload)


def build_signin_metadata(signin_id) -> dict:
    signin = Signin.query.get_or_404(signin_id)
    if not signin:
        logging.warning("signin does not exist")
        return {}
    signin_metadata = json.loads(signin.signin_metadata or "{}")
    logging.info("signin metadata = %s", signin_metadata)        
    return signin_metadata


def get_report(signin, url):
    mode = current_app.config["MODE"]
    if mode.myenv == "aws":
        api_url = "https://talao.co/api/anlyse-qrcode"
    else:
        api_url = "http://" + mode.IP + ":3000/api/analyze-qrcode"
    
    headers = {
        "Content-Type": "application/json",
        "Api-Key": "your-api-key", #TODO
    }
    payload = {
        "qrcode": base64.b64encode(url.encode()).decode(),
        "oidc4vpDraft":  signin.draft,
        "profile": "connectors",
        "format": "text",
        "model": "flash" # "escalation",
    }
    try:
        resp = requests.post(api_url, json=payload, headers=headers, timeout=300)
        resp.raise_for_status()
        # If the API returns JSON:
    except requests.HTTPError as e:
        logging.warning("HTTP error: %s and %s", e.response.status_code, e.response.text)
    except requests.RequestException as e:
        logging.warning("Request failed: %s", e)    
    return base64.b64decode(resp.json()["report_base64"].encode()).decode()


# build the authorization request                                      
def signin_qrcode():
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    try:
        code_data = json.loads(red.get(request.args['code']).decode())
    except Exception:
        logging.error("session expired in login_qrcode")
        return render_template("signin_oidc/signin_session_problem.html", message='Session expired')
    
    try:
        signin_id = code_data['signin_id']
    except Exception:
        logging.error("client id or nonce missing")
        return render_template("signin_oidc/signin_session_problem.html", message='Server error ')
    
    signin = Signin.query.get_or_404(signin_id)
    nonce = str(uuid.uuid1())
    
    # authorization request
    authorization_request = { 
        "client_id": signin.client_id,
        "iss": signin.client_id, # TODO
        "response_type": code_data["wallet_response_type"],
        "response_uri": mode.server + "signin/wallet/callback",
        "response_mode": signin.response_mode,
        "nonce": nonce
    }
    if code_data.get("state", None):
        authorization_request["state"] = code_data["state"]
        
    authorization_request["client_metadata"] = build_signin_metadata(signin_id)

    # OIDC4VP
    if 'vp_token' in code_data["wallet_response_type"]:
        try:  
            scope = [item for item in code_data["scope"] if item != "openid"][0]
            if scope not in ["profile", "email", "over18"]:
                logging.warning("This scope is not supported %s", scope)
                return jsonify("This scope is not supported %s", scope), 401  
            logging.info("scope = %s", scope)
            
            if signin.presentation_format == "presentation_exchange":
                presentation_request = json.load( open("presentation_exchange/" + scope + '.json', 'r'))
                authorization_request['presentation_definition'] = presentation_request
            else:
                presentation_request = json.load( open("dcql_query/" + scope + '.json', 'r'))
                authorization_request['dcql_query'] = presentation_request
        except Exception:
            presentation_request = {}
        authorization_request['aud'] = 'https://self-issued.me/v2'
        if signin.client_id_scheme:
            authorization_request["client_id_scheme"] = signin.client_id_scheme
    else:
        presentation_request = {}
        
    # SIOPV2
    if 'id_token' in code_data["wallet_response_type"]:
        authorization_request['scope'] = 'openid'

    # store data in redis attached to the nonce to bind with the response
    session_id = str(uuid.uuid1())
    data = { 
        "code": request.args['code'],
        "signin_id": signin_id,
        "session_id": session_id
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))
    
    # signature key of the request object
    credential_id = signin.credential_id
    
    # build the request object build_jwt_request(credential_id, request, client_id_scheme)
    request_as_jwt = build_jwt_request(credential_id, authorization_request, signin.client_id_scheme)
    if not request_as_jwt:
        return jsonify("This signin or key does not exist"), 401
    
    logging.info("request as jwt = %s", request_as_jwt)

    # generate a request uri endpoint
    stream_id = str(uuid.uuid1())
    red.setex(stream_id, QRCODE_LIFE, request_as_jwt)
    
    # QRCode preparation with authorization_request_displayed
    authorization_request_for_qrcode = { 
        "client_id": signin.client_id,
        "request_uri": mode.server + "signin/wallet/request_uri/" + stream_id 
    }
    logging.info(json.dumps(authorization_request_for_qrcode, indent= 4)  )
    
    url = signin.prefix + '?' + urlencode(authorization_request_for_qrcode)
    
    # MOde of the platform. mode is audit or test. if test the session_id is set in signin.test
    if code_data.get("mode") == "audit":
        qrcode_page = "audit.html"
        try:
            report = get_report(signin, url)
        except Exception:
            flash("❌ The audit feature is not available")
            return redirect("/signin/select/" + signin.signin_type)
    elif code_data.get("mode") == "test":
        qrcode_page = "signin/signin_test.html"
        report = None
        # Test is provided with PID as presentation
        signin.test = True
        db.session.commit()
    else:
        qrcode_page = "signin/landing_pages/" + signin.landing_page + ".html"
        report = None
    
    try:
        return render_template(
            qrcode_page,
            url=url,
            report=report,
            session_id=session_id,
            signin_type=signin.signin_type,
            signin_id=signin.id
        )
    except Exception:
        return jsonify("This landing page does not exist"), 401


def signin_request_uri(stream_id):
    red = current_app.config["REDIS"]
    try:
        payload = red.get(stream_id).decode()
    except Exception:
        return jsonify("Request no more available"), 408

    #red.delete(stream_id)
    headers = { 
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(payload, headers=headers)


def get_format(vp, type="vp"):
    if not vp:
        return
    elif isinstance(vp, dict):
        vp = json.dumps(vp)
    if vp[:1] == "{":
        return "ldp_" + type
    elif len(vp.split("~")) > 1:
        return "vc+sd-jwt"

def signin_response():
    red = current_app.config["REDIS"]
    logging.info("Enter wallet response endpoint")
    logging.info("Header = %s", request.headers)
    logging.info("Form = %s", request.form)
    access = True

    # get if error
    if request.form.get('error'):
        response_data = {
            "error":  request.form.get('error'),
            "error_description": request.form.get('error_description')
        }
        logging.warning("wallet response error = %s", json.dumps(response_data, indent=4))
        access = False
    
    # get id_token, vp_token and presentation_submission
    if request.form.get('response'):
        response = oidc4vc.get_payload_from_token(request.form['response'])
        logging.info("direct_post.jwt")
    else:
        logging.info("direct_post")
        response = request.form
    
    vp_token = response.get('vp_token')
    id_token = response.get('id_token')
    presentation_submission = response.get('presentation_submission')
    
    if not vp_token:
        vp_token = ()
    elif vp_token and not presentation_submission:
        logging.error('No presentation submission received')
        access = False
    else:
        logging.info('presentation submission received = %s', presentation_submission)
        if isinstance(presentation_submission, str):
            presentation_submission = json.loads(presentation_submission)
            logging.info("presentation submission is a string")
        else:
            logging.info("presentation submission is a dict /json object")
    
    if id_token:
        logging.info('id token received = %s', id_token)
        id_token_payload = oidc4vc.get_payload_from_token(id_token)
    else:
        logging.info("id_token not received")
    
    vp_format = get_format(vp_token)   
    logging.info("VP format = %s", vp_format)   
    if vp_token and presentation_submission:
        logging.info('vp token received = %s', vp_token)
        vp_format_presentation_submission = presentation_submission["descriptor_map"][0]["format"]
        logging.info("VP format from presentation submission = %s", vp_format_presentation_submission)
        if vp_format not in ["vc+sd-jwt", "dc+sd-jwt", "ldp_vp"]:
            logging.error("vp format not supported")
            access = False
        elif vp_format != vp_format_presentation_submission:
            presentation_submission_status = "vp_format = " + vp_format + " but presentation submission vp_format = " + vp_format_presentation_submission
            logging.warning(presentation_submission_status)
    
    if not id_token and not vp_token:
        logging.error("invalid request format")
        access = False
    
    # check id_token signature
    if access and id_token:
        try:
            oidc4vc.verif_token(id_token)
        except Exception as e:
            logging.error(" id_token invalid format %s", str(e))
            access = False
            
    # check vp_token signature
    if access and vp_token:
        if vp_format in ["vc+sd-jwt", "dc+sd-jwt"]:
            vp_token_list = vp_token.split("~")
            nb_disclosure = len(vp_token_list)
            logging.info("nb of disclosure = %s", nb_disclosure - 2 )
            disclosure = []
            for i in range(1, nb_disclosure-1):
                _disclosure = vp_token_list[i]
                _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
                try:
                    logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                    disc = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                    disclosure.append(disc)
                except Exception:
                    logging.info("i = %s", i)
                    logging.info("_disclosure = %s", _disclosure)
            logging.info("vp token signature not checked yet")
        else: # ldp_vp
            pass

    # get data from nonce binding
    nonce = None
    if vp_token:
        logging.info("cnf in vp_token = %s",oidc4vc.get_payload_from_token(vp_token_list[0])['cnf'])
        nonce = oidc4vc.get_payload_from_token(vp_token_list[-1])['nonce']
        try:
            vp_sub = oidc4vc.get_payload_from_token(vp_token_list[0])['cnf']["kid"]
        except Exception:
            vp_sub = oidc4vc.thumbprint(oidc4vc.get_payload_from_token(vp_token_list[-1])['cnf']["jwk"])
    elif id_token:
        nonce = oidc4vc.get_payload_from_token(id_token)['nonce']
    data = json.loads(red.get(nonce).decode())
    session_id = data["session_id"]
    status_code = 200 if access else 400
    if status_code == 400:
        response = {
            "error": "access_denied"
        }
        logging.warning("Access denied")
    else:
        response = "{}"
    
    # follow up
    if id_token:
        sub = id_token_payload.get('sub')
    else:
        try:
            sub = vp_sub
        except Exception:
            sub = "Error"
    
    # data sent to application
    wallet_data = json.dumps({
                    "code": data["code"],
                    "access": access,
                    "vp_token": vp_token, # jwt_vp payload or json-ld 
                    "vp_format": vp_format,
                    "sub": sub,
                    "id_token": id_token,
                    "presentation_submission": presentation_submission
                    })
    red.setex(session_id + "_wallet_data", CODE_LIFE, wallet_data)
    
    event_data = json.dumps({"session_id": session_id})
    red.publish('signin_wallet_stream', event_data)
    
    return jsonify(response), status_code


def signin_login_followup():  
    """
    check if user is connected or not and redirect data to authorization server
    Prepare de data to transfer
    create activity record
    """
    red = current_app.config["REDIS"]
    logging.info("Enter follow up endpoint")
    try:
        session_id = request.args.get('session_id')
        session_id_wallet_data = json.loads(red.get(session_id + '_wallet_data').decode())
        code = session_id_wallet_data["code"]
    except Exception as e:
        logging.error("code expired in follow up = %d", str(e))
        resp = {
            'error': "access_denied",
            'error_description': "Session expired"
        }
        session.clear()
        return jsonify(resp), 401

    if not session_id_wallet_data['access']:
        resp = {
            'code': code,
            'error': 'access_denied',
        }
        session['verified'] = False
    else:
        session['verified'] = True
        red.setex(code + "_wallet_data", CODE_LIFE, json.dumps(session_id_wallet_data))
        resp = {'code': code}

    return redirect('/signin/app/authorize?' + urlencode(resp))


def signin_login_stream():
    red = current_app.config["REDIS"]
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('signin_wallet_stream')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(login_event_stream(red), headers=headers)

