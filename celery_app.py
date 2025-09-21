import os
from celery import Celery
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
import env


# ---- Environment / Mode ----
# Environment variables are set in gunicornconf.py and used via utils.environment
myenv = os.getenv("MYENV", "local")
mode = env.currentMode(myenv)  # object with .server, .port, .flaskserver, etc.


def create_app():
    from main import create_app as _create_app
    app = _create_app()
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    return app

def make_celery(app: Flask):
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    celery = Celery(app.import_name, broker=redis_url, backend=redis_url)
    celery.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
    )
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

app = create_app()
celery = make_celery(app)

# Register Celery tasks from your routes module
from routes.generate_vct_from_issuer import register_tasks_on
register_tasks_on(celery)
