from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
from db_model import db

UPLOAD_FOLDER = 'static/uploads'  # make sure this folder exists


def init_app(app):
    app.add_url_rule('/user_profile', view_func=user_profile, methods=["GET", "POST"])

@login_required
def user_profile():
    if request.method == "POST":
        file = request.files.get("picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            current_user.profile_picture = filename
            db.session.commit()
            flash("Profile picture updated.")
            return redirect("/user_profile")

    return render_template("user_profile.html", user=current_user)
