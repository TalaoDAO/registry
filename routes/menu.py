from flask import render_template
import logging
from flask_login import login_required, current_user

logging.basicConfig(level=logging.INFO)




def init_app(app):
    
    app.add_url_rule('/menu',  view_func=menu, methods = ['GET', 'POST'])

    return


@login_required
def menu():
    print(current_user.subscription)
    return render_template("menu.html", user=current_user)

