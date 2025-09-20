# Installation

## Requirements

Python 3.9+
didkit 0.3.0

## Install

mkdir registry  
cd issuer
python3 -m venv venv  
. venv/bin/activate  


pip install -r requirements.txt


## launch celery worker 
celery -A celery_app.celery worker -l info

### test worker

curl -X POST https://vc-registry.com/vct/registry/api/generate_from_issuer \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <YOUR_API_KEY>' \
  -d '{"issuer":"https://issuer.example"}'

curl -X POST http://192.168.0.20:4000/vct/registry/api/generate_from_issuer \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <YOUR_API_KEY>' \
  -d '{"issuer":"https://talao.co/issuer/hmvwdgszax"}'
