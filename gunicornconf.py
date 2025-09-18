# gunicornconf.py

workers = 5
worker_class = 'gevent'
loglevel = 'info'

errorlog = "-"
accesslog = "-"

timeout = 180   # seconds
keepalive = 504 # seconds
capture_output = True

# Environment variables (passed into workers)
raw_env = [
    "MYENV=aws",       # you can override this (aws, local, prod…)
    "FLASK_DEBUG=0",   # no debug in prod
    "SECRET_KEY=mlkmmlkmlkmihh456"
]
