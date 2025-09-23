# extend_wizard.py
from flask import render_template
from flask_login import login_required

def init_app(app):
    app.add_url_rule("/vct/registry/extend", view_func=extend_wizard_page, methods=["GET"])

@login_required
def extend_wizard_page():
    # the template JS handles ?row_id=, ?integrity= etc.
    return render_template("extend_wizard.html")
