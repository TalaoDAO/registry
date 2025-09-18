from flask import request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from db_model import db, Credential
from sqlalchemy.exc import IntegrityError
from utils.kms import encrypt_json, decrypt_json
import json
from utils.key_validator import validate_asymmetric_private_jwk
    
def init_app(app):
    app.add_url_rule("/credential/create/<credential_type>", view_func=create_credential, methods=["GET","POST"])
    app.add_url_rule("/credential/update/<credential_type>/<int:credential_id>", view_func=update_credential, methods=["GET","POST"])

# ---------- helpers ----------

def _get_form_id(credential_type:str):
    """
    - sandbox: input name="credential_ID"
    - non-sandbox: select name="Credential_ID"
    """
    if credential_type == "sandbox":
        return (request.form.get("credential_ID") or "").strip()
    return (request.form.get("Credential_ID") or "").strip()

def _prefill_vars(cred=None):
    if not cred:
        return dict(credential_id="", key="", encryption_key="", x5c="", did="", verification_method="")
    
    def _dec(v):
        try:
            return decrypt_json(v) if v else ""
        except Exception:
            return ""
    
    return dict(
        credential_id=cred.credential_id or "",
        key=_dec(cred.key),
        encryption_key=_dec(cred.encryption_key),
        x5c=(cred.x5c or ""),  # <-- no decrypt, show raw JSON string
        did=cred.did or "",
        verification_method=cred.verification_method or "",
    )

# ---------- create ----------

@login_required
def create_credential(credential_type):
    if request.method == "GET":
        credentials = []
        return render_template(
            "credential/crud_credential.html",
            mode="create",
            credential_type=credential_type,
            credentials=credentials,
            **_prefill_vars(None),
            user=current_user
        )

    # POST
    credential_id = _get_form_id(credential_type)
    key_raw = (request.form.get("key") or "").strip()
    enc_key_raw = (request.form.get("encryption_key") or "").strip()
    x5c_raw = (request.form.get("x5c") or "").strip()
    did = (request.form.get("did") or "").strip()
    verification_method = (request.form.get("verification_method") or "").strip()
    print(request.form)

    # Validate x5c as JSON; store as a JSON string (public, not encrypted)
    x5c_json_string = None
    back_to_form = False
    
    if x5c_raw:
        try:
            x5c_json_string = json.dumps(json.loads(x5c_raw))
        except Exception as e:
            back_to_form = True
            flash(f"❌ x5c must be valid JSON (array or string): {e}")
    
    if key_raw:
        try:
            validate_asymmetric_private_jwk(key_raw)
        except Exception:          
            back_to_form = True
            flash(f"❌ Key must be a valid JWK")
    
    if back_to_form:
        return render_template(
                "credential/crud_credential.html",
                mode="create",
                credential_type=credential_type,
                credentials=[],
                credential_id=credential_id,
                key=key_raw,
                encryption_key=enc_key_raw,
                x5c=x5c_raw,
                did=did,
                verification_method=verification_method,
                user=current_user
            )

    try:
        cred = Credential(
            user_id=current_user.id,
            credential_type=credential_type,
            credential_id=credential_id or None,
            did=did or None,
            verification_method=verification_method or None,
        )
        cred.key = encrypt_json(key_raw) if key_raw else None
        cred.encryption_key = encrypt_json(enc_key_raw) if enc_key_raw else None
        cred.x5c = x5c_json_string  # <-- store plain JSON string (public)

        db.session.add(cred)
        db.session.commit()
        flash("✅ Credential created successfully.")
        return redirect(url_for("create_credential", credential_type=credential_type))
    except IntegrityError as ie:
        db.session.rollback()
        flash(f"❌ Database error: {ie}")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Unexpected error: {e}")

    return render_template(
        "credential/crud_credential.html",
        mode="create",
        credential_type=credential_type,
        credentials=[],
        credential_id=credential_id,
        key=key_raw, encryption_key=enc_key_raw, x5c=x5c_raw,
        did=did, verification_method=verification_method,
        user=current_user
    )

# ---------- update ----------

@login_required
def update_credential(credential_type, credential_id:int):
    cred = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if not cred:
        flash("❌ Credential not found or not accessible.")
        return redirect(url_for("create_credential", credential_type=credential_type))

    if request.method == "GET":
        credentials = []
        pre = _prefill_vars(cred)
        return render_template(
            "credential/crud_credential.html",
            mode="update",
            credential_type=credential_type,
            credential=cred,
            credentials=credentials,
            **pre,
            user=current_user
        )

    # POST: apply updates
    new_credential_id = _get_form_id(credential_type)
    key_raw = (request.form.get("key") or "").strip()
    enc_key_raw = (request.form.get("encryption_key") or "").strip()
    x5c_raw = (request.form.get("x5c") or "").strip()
    did = (request.form.get("did") or "").strip()
    verification_method = (request.form.get("verification_method") or "").strip()

    # Re-validate x5c when user provided a new value; store plain JSON string
    back_to_form = False
    if x5c_raw != "":
        try:
            cred.x5c = json.dumps(json.loads(x5c_raw)) if x5c_raw else None
        except Exception:
            flash(f"❌ x5c must be valid JSON (array or string)")
            back_to_form = True
            
    if key_raw:
        try:
            validate_asymmetric_private_jwk(key_raw)
        except Exception:          
            back_to_form = True
            flash(f"❌ Key must be a valid JWK (EC, RSA and Ed225519)")
    
    if back_to_form:
        pre = _prefill_vars(cred)
        pre.update(dict(credential_id=new_credential_id, key=key_raw, encryption_key=enc_key_raw, x5c=x5c_raw))
        return render_template(
                "credential/crud_credential.html",
                mode="update",
                credential_type=credential_type,
                credential=cred,
                credentials=[],
                **pre,
                user=current_user
            )

    try:
        cred.credential_id = new_credential_id or None
        cred.did = did or None
        cred.verification_method = verification_method or None

        # overwrite encrypted blobs only if provided; empty string leaves as-is
        if key_raw != "":
            cred.key = encrypt_json(key_raw) if key_raw else None
        if enc_key_raw != "":
            cred.encryption_key = encrypt_json(enc_key_raw) if enc_key_raw else None

        db.session.commit()
        flash("✅ Credential updated successfully.")
        return redirect(url_for("update_credential", credential_type=credential_type, credential_id=cred.id))
    except IntegrityError:
        db.session.rollback()
        flash(f"❌ Database error.")
    except Exception:
        db.session.rollback()
        flash(f"❌ Unexpected error.")

    pre = _prefill_vars(cred)
    pre.update(dict(credential_id=new_credential_id, key=key_raw, encryption_key=enc_key_raw, x5c=x5c_raw))
    return render_template(
        "credential/crud_credential.html",
        mode="update",
        credential_type=credential_type,
        credential=cred,
        credentials=[],
        **pre,
        user=current_user
    )
