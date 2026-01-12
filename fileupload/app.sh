#!/bin/sh

cd /tmp
python3 -m venv venv_flask
source venv_flask/bin/activate
python -m pip install --no-index --find-links=/home/flaskuser/flask_download flask

cd /app
python3 /app/app.py