import os
import logging
from datetime import timedelta

from flask import Flask, redirect, request, render_template_string, current_app
#from flask_mobility import Mobility
from flask_session import Session
from flask_qrcode import QRcode
from flask_login import LoginManager
import redis
import markdown
from flask_migrate import Migrate
import env
from routes.generate_vct_from_issuer import init_app as init_bulk_api

from werkzeug.middleware.proxy_fix import ProxyFix


# Your modules
from utils import message
from db_model import (
    load_user, db,
    seed_credential, seed_signin_for_wallet_registration,
    seed_user
)

# Routes / APIs (kept as they are, just registered here)
from routes import (
    home, register, menu, user_profile,
    create_vct, vct_registry,
    extend_wizard, vct_translate, editor
)

    
from routes.signin import bridge, select_signin, crud_signin

from routes.credential import crud_credential, select_credential

from apis import signin_api


# ---- default constants (overridable via env) ----
DEFAULT_API_LIFE = 5000
DEFAULT_GRANT_LIFE = 5000
DEFAULT_ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

# Migrate object
migrate = Migrate()


def create_app() -> Flask:
    """Application factory: configure, wire dependencies, register routes/APIs."""
    # Base Flask app
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    init_bulk_api(app)    
    
    @app.get("/ping")
    def ping():
        return "pong"

    # ---- Logging (basic) ----
    # In production, prefer dictConfig with JSON or structured logs
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    # ---- Environment / Mode ----
    # Environment variables are set in gunicornconf.py and used via utils.environment
    myenv = os.getenv("MYENV", "local")
    mode = env.currentMode(myenv)  # object with .server, .port, .flaskserver, etc.
    mode.debug_on()

    # Redis init red = redis.StrictRedis()
    red = redis.Redis(host='localhost', port=6379, db=0)

    # ---- Security / secrets ----
    # NEVER hardcode secrets; load from env or secret manager
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-prod")

    # ---- Sessions (server-side via Redis) ----
    app.config.update(
        SESSION_PERMANENT=True,
        SESSION_COOKIE_NAME="connectors",
        SESSION_TYPE="redis",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30"))),
        SESSION_FILE_THRESHOLD=100,  # unused with redis, but OK to leave
    )

    # ---- App metadata / UI helpers ----
    app.jinja_env.globals["Version"] = os.getenv("APP_VERSION", "0.2")
    try:
        app.jinja_env.globals["Created"] = os.path.getctime(__file__)
    except Exception:
        app.jinja_env.globals["Created"] = ""

    # ---- SQLAlchemy ----
    db_path = os.getenv("SQLALCHEMY_DATABASE_URI") or ("sqlite:///" + os.path.abspath("data/registry.db"))
    app.config["SQLALCHEMY_DATABASE_URI"] = db_path

    # ---- App-wide config values (shared deps) ----
    app.config["MODE"] = mode
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = red
    app.config["REDIS"] = red
    app.config["API_LIFE"] = int(os.getenv("API_LIFE", DEFAULT_API_LIFE))
    app.config["GRANT_LIFE"] = int(os.getenv("GRANT_LIFE", DEFAULT_GRANT_LIFE))
    app.config["ACCEPTANCE_TOKEN_LIFE"] = int(os.getenv("ACCEPTANCE_TOKEN_LIFE", DEFAULT_ACCEPTANCE_TOKEN_LIFE))
    app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]
    app.config["AUDIT_LOG_DIR"] = "./log"  # or instance_path/audit-logs
    
    # OAUTHLIB_INSECURE_TRANSPORT is only for local/dev; do not enable in prod
    if myenv == "local":
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # ---- Init extensions bound to app ----
    db.init_app(app)
    migrate.init_app(app, db) 
    Session(app)
    QRcode(app)

    # ---- DB bootstrap / seed (idempotent) ----
    with app.app_context():
        db.create_all()
        # NOTE: seeding in production can be dangerous; guard by env flag
        if os.getenv("SEED_DATA", "1") == "1":
            logging.info("Run seed DB")
            seed_user()
            seed_credential()
            seed_signin_for_wallet_registration(mode)

    # ---- Flask-Login ----
    login_manager = LoginManager()
    login_manager.login_view = "register"   # endpoint name for redirect
    login_manager.init_app(app)
    login_manager.user_loader(load_user)

    # ---- Register routes / APIs ----
    # Prefer using app.config within routes instead of passing red/mode as defaults
    crud_credential.init_app(app)             # reads current_app.config as needed
    select_credential.init_app(app)

    select_signin.init_app(app)
    crud_signin.init_app(app)

    user_profile.init_app(app)

    bridge.init_app(app)
    
    signin_api.init_app(app)
    
    home.init_app(app)
    register.init_app(app, db)
    menu.init_app(app)
    create_vct.init_app(app)
    vct_registry.init_app(app)
    extend_wizard.init_app(app)
    vct_translate.init_app(app)
    editor.init_app(app)
        
    # ---- Error handlers ----
    @app.errorhandler(403)
    def page_abort(e):
        logging.warning("403 Forbidden: %s", e)
        return redirect(mode.server + "login/")

    @app.errorhandler(500)
    def error_500(e):
        try:
            message.message("Error 500 on vc-registry.com", "thierry.thevenet@talao.io", str(e), mode)
        except Exception as x:
            logging.warning("message() failed: %s", x)
        return redirect(mode.server + "/")

    # ---- Helpers attached to app context ----
    def front_publish(stream_id: str, error: str, error_description: str) -> None:
        """Publish an event on Redis pub/sub for the front channel."""
        payload = {"stream_id": stream_id}
        if error:
            payload["error"] = error
        if error_description:
            payload["error_description"] = error_description
        # Use the configured Redis instance
        current_app.config["REDIS"].publish("issuer_oidc", json.dumps(payload).encode("utf-8"))

    # make helper available if yo
    app.extensions = getattr(app, "extensions", {})
    app.extensions["front_publish"] = front_publish

    # ---- Minimal safe markdown file endpoint ----
    @app.get("/md_file")
    def md_file():
        """
        Render a whitelisted markdown file as HTML. Prevents path traversal.
        """
        allowed = {
            "privacy": "privacy_en.md",
            "terms_and_conditions": "mobile_cgu_en.md",
        }
        key = request.args.get("file", "")
        fname = allowed.get(key)
        if not fname:
            return redirect(mode.server + "login/")

        try:
            with open(fname, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return "File not found", 404

        html = markdown.markdown(content, extensions=["fenced_code"])
        return render_template_string(html)
    return app


# ---- Dev entrypoint: `python app.py` ----
if __name__ == "__main__":
    app = create_app()
    mode = app.config["MODE"]
    logging.info("Starting Flask dev server at %s:%s (env: %s)", mode.IP, mode.port, os.getenv("MYENV", "local"))
    app.run(host=mode.IP, port=mode.port, debug=os.getenv("FLASK_DEBUG", "1") == "1", threaded=True)
