from flask import render_template, redirect, flash
from flask_login import login_required, current_user
from db_model import db, Credential

def init_app(app):
    app.add_url_rule('/credential/select/<credential_type>',  view_func=list_credentials, methods = ['GET'])
    app.add_url_rule('/credential/delete/<credential_type>/<credential_id>',  view_func=delete_credential, methods = ['POST'])


@login_required
def list_credentials(credential_type):
    #credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.type == verifier_type).filter(Credential.use == "sign").all()

    credentials = Credential.query.filter(Credential.user_id.in_( [1, current_user.id]), Credential.credential_type == credential_type).all()
    return render_template(
        "credential/select_credential.html",
        credentials=credentials,
        credential_type=credential_type,
        user=current_user
    )


@login_required
def delete_credential(credential_type, credential_id):
    credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if credential:
        db.session.delete(credential)
        db.session.commit()
        flash("✅  Credential deleted.")
    else:
        flash("❌ You cannot delete this credential.")
    return redirect("/credential/select/" + credential_type)
