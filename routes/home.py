# home.py
from flask import render_template, current_app, redirect
import logging
from flask_login import current_user, logout_user
import markdown

# NEW
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
import json
from db_model import db, VCTRegistry  # uses your existing SQLAlchemy setup

logging.basicConfig(level=logging.INFO)


def init_app(app):
    app.add_url_rule('/',  view_func=home, methods=['GET', 'POST'])
    app.add_url_rule('/signin',  view_func=signin, methods = ['GET', 'POST'])
    app.add_url_rule('/logout',  view_func=logout, methods = ['GET', 'POST'])
    app.add_url_rule("/documentation/<page>", view_func=show_markdown_page, methods=['GET'])
    app.add_url_rule('/debug/<debug_mode>',  view_func=debug, methods = ['GET', 'POST'])
    return


def _compute_home_stats():
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    q_public = VCTRegistry.query.filter(VCTRegistry.is_public.is_(True))

    total_public = db.session.query(func.count(VCTRegistry.id))\
        .filter(VCTRegistry.is_public.is_(True)).scalar() or 0

    new_week = db.session.query(func.count(VCTRegistry.id))\
        .filter(VCTRegistry.is_public.is_(True),
                VCTRegistry.created_at >= week_ago).scalar() or 0

    total_calls = db.session.query(func.coalesce(func.sum(VCTRegistry.calls_count), 0))\
        .filter(VCTRegistry.is_public.is_(True)).scalar() or 0

    avg_rating = db.session.query(func.coalesce(func.avg(VCTRegistry.avg_rating), 0.0))\
        .filter(VCTRegistry.is_public.is_(True),
                VCTRegistry.ratings_count > 0).scalar() or 0.0
    avg_rating = round(float(avg_rating), 2)

    # Top 3 most-called public VCTs
    top_rows = (
        q_public
        .order_by(VCTRegistry.calls_count.desc(), VCTRegistry.id.asc())
        .limit(3)
        .all()
    )
    top_vcts = [
        {
            "name": getattr(r, "name", None),
            "vct": getattr(r, "vct", None),
            "calls_count": int(getattr(r, "calls_count", 0) or 0),
        }
        for r in top_rows
    ]

    # Top languages from languages_supported JSON (simple parse, capped to 1000 rows)
    lang_counts = {}
    for (langs_text,) in db.session.query(VCTRegistry.languages_supported)\
                                   .filter(VCTRegistry.is_public.is_(True))\
                                   .limit(1000).all():
        try:
            langs = json.loads(langs_text or "[]")
        except Exception:
            langs = []
        for l in langs:
            code = (l or "").split("-")[0].lower()
            if code:
                lang_counts[code] = lang_counts.get(code, 0) + 1
    
    top_langs = sorted(lang_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    total_all = db.session.query(func.count(VCTRegistry.id)).scalar() or 0

    return {
        "total_public": int(total_public),
        "new_week": int(new_week),
        "total_calls": int(total_calls),
        "avg_rating": avg_rating,
        "top_vcts": top_vcts,   # <<— list of up to 3
        "top_langs": top_langs,
        "total_all": total_all,
    }


def home():
    stats = _compute_home_stats()
    
    return render_template("home.html", user=current_user, stats=stats)


def signin():
    mode = current_app.config["MODE"]
    return render_template("register.html", mode=mode, title="Sign-In")


def logout():
    logout_user()
    return redirect("/")


def show_markdown_page(page):
    try:
        with open(f"documentation/{page}.md", "r") as f:
            content = f.read()
    except FileNotFoundError:
        return "Page not found", 404
    html_content = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return render_template("markdown_template.html", page=page, html_content=html_content)


def debug(debug_mode):
    mode = current_app.config["MODE"]
    if debug_mode == "on":
        mode.debug_on()
    else:
        mode.debug_off()
    return render_template("menu.html", user=current_user)
