#!/bin/sh

echo "========================makemigrations ========================"
python manage.py makemigrations 

echo "=========== make migrations accounts ==========="
python manage.py makemigrations accounts


echo "================= migrate ====================================="
echo "==============================================================="
python manage.py migrate
echo "done ."
echo "==============================================================="
echo "================= collect static files ========================"
python manage.py collectstatic --noinput
echo "done ."
echo "=================running app==================================="
#daphne -b 0.0.0.0 -p 8000 -t 60000 app.asgi:application &
python manage.py runserver 0.0.0.0:8081 

# echo "Django server PID: $!"

# wait