#!/bin/sh
set -e

/usr/src/venvs/app-main/bin/python manage.py migrate --noinput
/usr/src/venvs/app-main/bin/python manage.py collectstatic --noinput
/usr/src/venvs/app-main/bin/python create_admin.py

exec /usr/src/venvs/app-main/bin/gunicorn pwned_proxy.wsgi:application --bind 0.0.0.0:8000

