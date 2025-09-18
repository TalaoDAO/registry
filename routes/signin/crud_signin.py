from flask import request, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from db_model import db, Signin, default_verifier_request_key, Credential
import secrets
import json
import os
from utils.kms import encrypt_json, decrypt_json
from utils import oidc4vc


def init_app(app):
    app.add_url_rule('/signin/create/<signin_type>', view_func=create_signin, methods=["GET", "POST"])
    app.add_url_rule('/signin/update/<signin_type>/<signin_id>', view_func=update_signin, methods=["GET", "POST"])

def title(signin_type, feature):
    if signin_type == "sandbox" and feature == "create":
        return "Create a Sign-In for Sandbox"
    elif signin_type == "sandbox" and feature == "update":
        return "Update a Sandbox Sign-In"
    elif signin_type == "qualified" and feature == "update":
        return "Update a Sign-In for Production"
    elif signin_type == "qualified" and feature == "create":
        return "Create a Sign-In for Production"

    
def create_application_api():
    # Generate a 16-character hex string (8 bytes) as client_id
    mode = current_app.config["MODE"]
    client_id = secrets.token_hex(8)
    return {
        "url": mode.server + "signin/app",
        "client_id": client_id,
        "client_secret": secrets.token_hex(32),
    }

def create_vp_formats():
    with open("vp_formats.json", "r") as f:
        vp_formats = json.load(f)
    return vp_formats

def calculate_client_id(draft, client_id_scheme, credential,mode):
    #https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html
    #https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html
    # https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html
    redirect_uri = mode.server + "signin/wallet/callback"
    client_id = "redirect_uri"
    if int(draft) == 8 :
        if client_id_scheme == "did":
            client_id = credential.did
        elif client_id_scheme == "url":
            client_id = redirect_uri
    
    elif int(draft) == 18: # client_id_scheme added
        if client_id_scheme == "redirect_uri":
            client_id = redirect_uri
        elif client_id_scheme == "did":
            client_id = credential.did
    
    elif int(draft) == 20: # 
        if client_id_scheme == "x509_san_dns":
            client_id = oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id = redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = oidc4vc.get_payload_from_token(credential.verifier_attestation)["sub"]
        elif client_id_scheme == "did":
            client_id = credential.did
            
    elif int(draft) ==  22: # no more client_id_scheme
        if client_id_scheme == "x509_san_dns":
            client_id = "x509_san_dns:" + oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id =  "redirect_uri:" + redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = "verifier_attestation:" + oidc4vc.get_payload_from_token(credential.signin_attestation)["sub"]
        elif client_id_scheme == "did":
            client_id = credential.did
    
    elif int(draft) >=  28:
        # no more client_id_scheme
        if client_id_scheme == "x509_san_dns":
            client_id = "x509_san_dns:" + oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id = "redirect_uri:" + redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = "verifier_attestation:" + oidc4vc.get_payload_from_token(credential.verifier_attestation)["sub"]
        elif client_id_scheme == "decentralized_identifier":
            client_id = "decentralized_identifier:" + credential.did
    return client_id
    


@login_required
def create_signin(signin_type):
    mode = current_app.config["MODE"]
    credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.credential_type == signin_type).filter(Credential.use == "sign").all()
    #landing_page_available_definitions = [f.split(".")[0] for f in os.listdir("templates/signin/landing_pages") if f.endswith(".html")]
    encryption_credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.use == "enc").filter(Credential.credential_type == signin_type).all()
    if request.method == "GET":
        return render_template(
            "signin/crud_signin.html",
            user=current_user,
            credentials=credentials,
            encryption_credentials=encryption_credentials,
            name="signin-" + str(secrets.randbelow(999999)),
            signin_type=signin_type,
            draft="20",
            #landing_page_available_definitions=landing_page_available_definitions,
            button="Create Signin",
            api=create_application_api(),
            signin_metadata={"vp_formats": create_vp_formats()},
            title=title(signin_type, "create")

        )

    def parse_json_field(raw, field_name, expect_list=False) -> dict:
        if not raw:
            return None
        try:
            val = json.loads(raw)
            if expect_list and not isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON array.")
            if not expect_list and isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON object or string, not an array.")
            return val
        except Exception as e:
            flash(f"❌ Invalid {field_name}: {e}")
            raise
        
    # POST request
    name = request.form.get("name")
    description = request.form.get("description")
    client_id_scheme = request.form.get("client_id_scheme")
    presentation_format = request.form.get("presentation_format")
    response_mode = request.form.get("response_mode", "direct_post")
    draft = request.form.get("draft")
    prefix = request.form.get("prefix")
    #landing_page = request.form.get("landing_page")
    api = request.form.get('api').replace("'", '"')
    credential_id = request.form.get("credential_id")
    credential_id_for_encryption = request.form.get("credential_id_for_encryption")
    response_encryption = request.form.get("response_encryption") == "True"
    raw_info = request.form.get("signin_info", "").strip() # json
    raw_metadata = request.form.get("signin_metadata", "").strip() # json
    log = request.form.get("log") == "True"
    
    try:
        info = parse_json_field(raw_info, "Signin Info JSON Array", expect_list = True)
        metadata = parse_json_field(raw_metadata, "Signin Metadata JSON ")
    except Exception:
        # flash already set in parse_json_field
        # re-render with previously entered values
        return render_template(
            "signin/crud_signin.html",
            user=current_user,
            description=description,
            client_id_scheme=client_id_scheme,
            presentation_format=presentation_format,
            #landing_page=landing_page,
            signin_metadata={"vp_formats": create_vp_formats()},
            signin_info=raw_info,
            response_encryption=response_encryption,
            credentials=credentials,
            draft=draft,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            name=name,
            response_mode=response_mode,
            encryption_credentials=encryption_credentials,
            signin_type=signin_type,
            #landing_page_available_definitions=landing_page_available_definitions,
            log=log,
            button="Create Signin",
            api=api,
            title=title(signin_type, "create")
        )
    
    if current_user.is_authenticated:
        # Create Signin object
        signin = Signin(
            user_id=current_user.id,
            name=name,
            description=description,
            signin_type=signin_type,
            client_id_scheme=client_id_scheme,
            presentation_format=presentation_format,
            #landing_page=landing_page,
            response_encryption=response_encryption,
            response_mode=response_mode,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            signin_info=json.dumps(info),
            signin_metadata=json.dumps(metadata),
            application_api=encrypt_json(json.loads(api)),
            application_api_client_id=json.loads(api).get("client_id"),
            draft=draft,
            prefix=prefix,
            log=log,
        )
        credential = Credential.query.filter(Credential.credential_id == credential_id).first()
        
        if signin.client_id_scheme in ["decentralized_identifier", "did"]:
            if not credential.did or not credential.verification_method:
                flash("❌ This Credential ID does not support DIDs.")
                return redirect("/signin/select/" + signin_type)
        elif signin.client_id_scheme == "signin_attestation" and not credential.signin_attestation:
            flash("❌ This Credential ID does not support signin attestation.")
            return redirect("/signin/select/" + signin_type)
        elif signin.client_id_scheme == "x509_san_dns" and not credential.x5c:
            flash("❌ This Credential ID does not support X509 certificates.")
            return redirect("/signin/select/" + signin_type)
        
        if response_encryption and response_mode == "direct_post":
            flash("❌ Encryption is not available for response_mode direct_post.")
            return redirect("/signin/select/" + signin_type)
        if response_encryption and not credential_id_for_encryption:
            flash("❌ The Credential ID does  not support encryption.")
            return redirect("/signin/select/" + signin_type)
        
        if client_id := calculate_client_id(draft, client_id_scheme, credential, mode):
            signin.client_id = client_id
        else:
            flash("❌ client_id error.")
            return redirect("/signin/create/" + signin_type)
        db.session.add(signin)
        db.session.commit()
        flash("✅ Signin created successfully.")
        return redirect("/signin/select/" + signin_type)
    else:
        flash("✅ Register to Create a Signin.")
        return redirect("/register")




@login_required
def update_signin(signin_type, signin_id):
    mode = current_app.config["MODE"]
    credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.credential_type == signin_type).filter(Credential.use == "sign").all()
    #landing_page_available_definitions = [f.split(".")[0] for f in os.listdir("templates/signin/landing_pages") if f.endswith(".html")]
    encryption_credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.use == "enc").filter(Credential.credential_type == signin_type).all()
    signin = Signin.query.filter_by(id=signin_id, user_id=current_user.id).first()
    api = decrypt_json(signin.application_api)
    if request.method == "GET":
        return render_template(
            "signin/crud_signin.html",
            user=current_user,
            description=signin.description,
            client_id_scheme=signin.client_id_scheme,
            presentation_format=signin.presentation_format,
            #landing_page=signin.landing_page,
            signin_metadata=json.loads(signin.signin_metadata),
            signin_info=json.loads(signin.signin_info),
            response_encryption=signin.response_encryption,
            credentials=credentials,
            draft=signin.draft,
            credential_id=signin.credential_id,
            credential_id_for_encryption=signin.credential_id_for_encryption,
            name=signin.name,
            response_mode=signin.response_mode,
            encryption_credentials=encryption_credentials,
            signin_type=signin_type,
            #landing_page_available_definitions=landing_page_available_definitions,
            button="Update Signin",
            log=signin.log,
            api=api,
            title=title(signin_type, "update")
        )

    def parse_json_field(raw, field_name, expect_list=False) -> dict:
        if not raw:
            return None
        try:
            val = json.loads(raw)
            if expect_list and not isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON array.")
            if not expect_list and isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON object or string, not an array.")
            return val
        except Exception as e:
            flash(f"❌ Invalid {field_name}: {e}")
            raise
        
    # POST request
    name = request.form.get("name")
    description = request.form.get("description")
    client_id_scheme = request.form.get("client_id_scheme")
    presentation_format = request.form.get("presentation_format")
    response_mode = request.form.get("response_mode", "direct_post")
    draft = request.form.get("draft")
    prefix = request.form.get("prefix")
    #landing_page = request.form.get("landing_page")
    credential_id = request.form.get("credential_id")
    credential_id_for_encryption = request.form.get("credential_id_for_encryption")
    response_encryption = request.form.get("response_encryption") == "True"
    raw_info = request.form.get("signin_info", "").strip() # json
    raw_metadata = request.form.get("signin_metadata", "").strip() # json
    log = request.form.get("log") == "True"
    api = request.form.get("api").replace("'", '"')
    
    try:
        info = parse_json_field(raw_info, "Signin Info JSON Array", expect_list = True)
        metadata = parse_json_field(raw_metadata, "Signin Metadata JSON ")
        
        credential = Credential.query.filter(Credential.credential_id == credential_id).first()
        if client_id_scheme in ["decentralized_identifier", "did"]:
            if not credential.did or not credential.verification_method:
                flash("❌ This Credential ID does not support DIDs.")
                return redirect("/signin/select/" + signin_type)
        elif client_id_scheme == "signin_attestation" and not credential.verifier_attestation:
            flash("❌ This Credential ID does not support verifier attestation.")
            return redirect("/signin/select/" + signin_type)
        elif client_id_scheme == "x509_san_dns" and not credential.x5c:
            flash("❌ This Credential ID does not support X509 certificates.")
            return redirect("/signin/select/" + signin_type)
        
        if response_encryption and response_mode == "direct_post":
            flash("❌ Encryption is not available for response_mode direct_post.")
            return redirect("/signin/select/" + signin_type)
        if response_encryption and not credential_id_for_encryption:
            flash("❌ The signin has no encryption key.")
            return redirect("/signin/select/" + signin_type)

    except Exception:
        try:
            json.loads(raw_metadata)
        except Exception:
            raw_metadata = signin.signin_metadata
        try:
            json.loads(raw_info)
        except Exception:
            raw_info = signin.signin_info
        # flash already set in parse_json_field
        # re-render with previously entered values
        return render_template(
            "signin/crud_signin.html",
            user=current_user,
            description=description,
            client_id_scheme=client_id_scheme,
            presentation_format=presentation_format,
            #landing_page=landing_page,
            signin_metadata=json.loads(raw_metadata),
            signin_info=json.loads(raw_info),
            response_encryption=response_encryption,
            credentials=credentials,
            draft=draft,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            name=name,
            response_mode=response_mode,
            encryption_credentials=encryption_credentials,
            signin_type=signin_type,
            #landing_page_available_definitions=landing_page_available_definitions,
            button="Update Signin",
            log=log,
            api=api,
            title=title(signin_type, "update")
        )
    
    client_id = calculate_client_id(draft, client_id_scheme, credential, mode)
    signin.client_id = client_id
    signin.name = name
    signin.description = description
    signin.signin_type = signin_type
    signin.client_id_scheme = client_id_scheme
    signin.presentation_format = presentation_format
    #signin.landing_page = landing_page
    signin.response_encryption = response_encryption
    signin.response_mode = response_mode
    signin.credential_id = credential_id
    signin.credential_id_for_encryption = credential_id_for_encryption
    signin.signin_info = json.dumps(info)
    signin.signin_metadata = json.dumps(metadata)
    signin.draft = draft
    signin.prefix = prefix
    signin.log = log
    try:
        db.session.commit()
        flash("✅ Signin updates successfully.")
        return redirect("/signin/select/" + signin_type)
    except Exception:
        flash("❌ Server error, impossible to update the Signin.")
        return redirect("/signin/select/" + signin_type)
