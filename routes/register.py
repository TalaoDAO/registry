from flask import redirect, request, render_template, current_app, flash
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
from flask_login import login_required, login_user, logout_user
from db_model import User, db, Signin
import logging
from requests.exceptions import RequestException, HTTPError
from utils.kms import encrypt_json, decrypt_json

ngrok =  "https://c8e7a2920835.ngrok.app"

try:
    with open('keys.json') as f:
        keys = json.load(f)
except Exception:
    logging.error('Unable to load keys.json — file missing or corrupted.')
    sys.exit(1)

# OAuth clients (for Google & GitHub)
GOOGLE_CLIENT_ID = keys.get("google_client_id")
GOOGLE_CLIENT_SECRET = keys.get("google_client_id")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_CALLBACK = "https://vc-registry.com/register/auth/google/callback"

GITHUB_CLIENT_ID = keys.get("github_clent_id")
GITHUB_CLIENT_SECRET = keys.get("github_client_secret")
GITHUB_CALLBACK = "https://vc-registry.com/register/auth/github/callback"


google_client = WebApplicationClient(GOOGLE_CLIENT_ID)
github_client = WebApplicationClient(GITHUB_CLIENT_ID)
#talao_client = WebApplicationClient(TALAO_CLIENT_ID)


def init_app(app, db):
    
    app.add_url_rule('/register',  view_func=register, methods=['GET'])

    app.add_url_rule('/register/auth/google',  view_func=login_with_google, methods=['POST'])
    app.add_url_rule('/register/auth/google/callback', view_func=register_google_callback, methods=['GET', 'POST'], defaults={'db': db})
    app.add_url_rule('/register/auth/github',  view_func=login_with_github, methods=['GET', 'POST'])
    app.add_url_rule('/register/auth/github/callback',  view_func=register_github_callback, methods=['GET', 'POST'], defaults={'db': db})
    
    app.add_url_rule('/register/auth/wallet',  view_func=login_with_wallet, methods=['GET', 'POST'])
    app.add_url_rule('/register/auth/wallet/callback',  view_func=register_wallet_callback, methods=['GET', 'POST'], defaults={'db': db})
    
    app.add_url_rule('/register/test',  view_func=register_test, methods=['GET', 'POST'])

    

def register():
    mode = current_app.config["MODE"]
    return render_template("register.html", mode=mode, title="Register")

def login_with_google():
    google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
    auth_uri = google_client.prepare_request_uri(
        google_config["authorization_endpoint"],
        redirect_uri=GOOGLE_CALLBACK,
        scope=["openid", "email", "profile"],
        prompt="select_account"  # forces account picker on next login
    )
    return redirect(auth_uri)

def register_google_callback(db):
    google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_url, headers, body = google_client.prepare_token_request(
        google_config["token_endpoint"],
        authorization_response=request.url,
        redirect_url=GOOGLE_CALLBACK
    )
    token_response = requests.post(token_url, headers=headers, data=body, auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    google_client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_config["userinfo_endpoint"]
    uri, headers, body = google_client.add_token(userinfo_endpoint)
    userinfo = requests.get(uri, headers=headers, data=body).json()
    logging.info("user_info = %s", userinfo)
    if userinfo.get("email") in ["thierry.thevenet@talao.io"]:
        user = User.query.filter_by(name="admin").first()
        logging.info("Connected as Admin")
        flash(" ✅ You are connected as a Admin")
        login_user(user)
        return redirect("/menu")
    else:
        user = User.query.filter_by(email=userinfo.get("email")).first()
    if user:
        login_user(user)
        return redirect("/menu")
    new_user = User(
        email=userinfo["email"],
        given_name=userinfo["given_name"],
        family_name=userinfo["family_name"],
        name=userinfo["given_name"] + " " + userinfo["family_name"],
        registration="google",
        subscription="free"
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    print("user has been created")
    return redirect("/menu")



def login_with_github():
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_CALLBACK}&scope=user:email")

def register_github_callback(db):
    code = request.args.get("code")
    token_resp = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code
        }
    ).json()
    headers = {'Authorization': f'token {token_resp.get("access_token")}'}
    userinfo = requests.get("https://api.github.com/user", headers=headers).json()
    user = User.query.filter_by(login=userinfo.get("login")).first()
    if user:
        login_user(user)
        return redirect("/menu")
    new_user = User(
        login=userinfo["login"],
        registration="github",
        subscription="free",
        name=userinfo["login"]
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    print("user has been created")
    return redirect("/menu")


def login_with_wallet():
    mode = current_app.config["MODE"]
    signin = db.session.get(Signin, 1)
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_DISCOVERY_URL = application_api["url"] + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server + "register/auth/wallet/callback"
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    talao_config = requests.get(TALAO_DISCOVERY_URL).json()
    auth_uri = talao_client.prepare_request_uri(
        talao_config["authorization_endpoint"],
        redirect_uri=TALAO_CALLBACK,
        scope=["openid"],
        response_mode="query"
    )
    return redirect(auth_uri)


def register_wallet_callback(db):
    mode = current_app.config["MODE"]
    # Load verifier / client config from DB
    signin = db.session.get(Signin, 1)
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_CLIENT_SECRET = application_api["client_secret"]
    TALAO_DISCOVERY_URL = application_api["url"].rstrip("/") + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server.rstrip("/") + "/register/auth/wallet/callback"
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    try:
        # 1) Discover OIDC endpoints
        disc_resp = requests.get(TALAO_DISCOVERY_URL, timeout=10)
        disc_resp.raise_for_status()
        talao_config = disc_resp.json()
        token_endpoint = talao_config["token_endpoint"]
        userinfo_endpoint = talao_config["userinfo_endpoint"]

        # 2) Build and send the token request
        token_url, headers, body = talao_client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=TALAO_CALLBACK,
        )
        token_resp = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(TALAO_CLIENT_ID, TALAO_CLIENT_SECRET),
            timeout=10,
        )
        logging.info("Token response text: %s", token_resp.text)
        token_resp.raise_for_status()

        # Parse token response into the OAuth client
        talao_client.parse_request_body_response(token_resp.text)

        # 3) Call the userinfo endpoint with the access token
        uri, headers, _ = talao_client.add_token(userinfo_endpoint)
        ui_resp = requests.get(uri, headers=headers, timeout=10)

        # Handle non-2xx cleanly (401/403/etc. with JSON error bodies)
        if not ui_resp.ok:
            try:
                err = ui_resp.json()
            except ValueError:
                err = {"error": "http_error", "error_description": ui_resp.text}
            logging.warning("userinfo error %s: %s", ui_resp.status_code, err)
            flash(f"❌ Wallet verification failed ({ui_resp.status_code}): {err.get('error_description', err.get('error', 'Unknown error'))}")
            return redirect("/")

        userinfo = ui_resp.json()
        logging.info("userinfo response = %s", json.dumps(userinfo, indent=2))

        sub = userinfo.get("sub")
        if not sub:
            flash("❌ Wallet verification failed: missing 'sub' in userinfo.")
            return redirect("/")

        # 4) Create or log in user
        user = User.query.filter_by(sub=sub).first()
        if user:
            login_user(user)
            flash("✅ Welcome back.")
            return redirect("/menu")

        new_user = User(
            sub=sub,
            registration="wallet",
            subscription="free",
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("✅ You are now registered.")
        return redirect("/menu")

    except HTTPError as e:
        # HTTP 4xx/5xx from discovery/token endpoints
        resp = e.response
        details = None
        try:
            details = resp.json()
        except Exception:
            details = resp.text
        logging.exception("HTTP error during OIDC flow: %s %s", resp.status_code if resp else "?", details)
        flash("❌ We couldn't complete wallet verification (HTTP error). Please try again.")
        return redirect("/")

    except RequestException as e:
        # Network issues, timeouts, DNS, etc.
        logging.exception("Network error during OIDC flow: %s", e)
        flash("❌ Network error contacting the wallet provider. Please try again.")
        return redirect("/")

    except Exception as e:
        logging.exception("Unexpected error during OIDC flow: %s", e)
        flash("❌ We encountered an unexpected error.")
        return redirect("/")


def register_test():
    mode = current_app.config["MODE"]
    logout_user()
    user = User.query.filter_by(name="test").first()
    if mode.myenv == 'local':
        login_user(user)
    return redirect("/menu")

