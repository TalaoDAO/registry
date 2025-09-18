from flask import render_template, redirect, flash
from flask_login import login_required, current_user
from db_model import db, Signin
import json
from utils.kms import encrypt_json, decrypt_json

def init_app(app):
    app.add_url_rule('/signin/select/<signin_type>',  view_func=list_signins, methods = ['GET'])
    app.add_url_rule('/signin/delete/<signin_type>/<signin_id>',  view_func=delete_signin, methods = ['POST'])
    app.add_url_rule('/signin/go_to_production/<signin_type>/<signin_id>',  view_func=signin_go_to_production, methods = ['GET'])
    app.add_url_rule('/signin/go_to_sandbox/<signin_type>/<signin_id>',  view_func=signin_go_to_sandbox, methods = ['GET'])


@login_required
def list_signins(signin_type):
    print(signin_type)
    signins = Signin.query.filter(Signin.user_id == current_user.id, Signin.signin_type == signin_type).all()

    print(signins)
    for v in signins:
        if v.test:
            v.test = False
            db.session.commit()
        try:
            v.application_api_json = decrypt_json(v.application_api)
        except Exception:
            v.application_api_json = {}
    return render_template(
        "signin/select_signin.html",
        signins=signins,
        signin_type=signin_type,
        user=current_user
    )


@login_required
def delete_signin(signin_type, signin_id):
    signin = Signin.query.filter_by(id=signin_id, user_id=current_user.id).first()
    if signin:
        db.session.delete(signin)
        db.session.commit()
        flash("✅  Signin deleted.")
    else:
        flash("❌ Signin not found.")
    return redirect("/signin/select/" + signin_type)


@login_required
def signin_go_to_production(signin_type, signin_id):
    signin = Signin.query.filter_by(id=signin_id, user_id=current_user.id).first()
    if signin:
        signin.signin_type = "qualified"
        signin.credential_id = None
        signin.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Signin transfered to production.")
    else:
        flash("❌ Signin not found.")
    return redirect("/signin/select/" + signin_type)


@login_required
def signin_go_to_sandbox(signin_type, signin_id):
    signin = Signin.query.filter_by(id=signin_id, user_id=current_user.id).first()
    if signin:
        signin.signin_type = "sandbox"
        signin.credential_id = None
        signin.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Signin transfered to sandbox.")
    else:
        flash("❌ Signin not found.")
    return redirect("/signin/select/" + signin_type)
