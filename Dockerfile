FROM python:3.9

ENV PYTHONDONTWRITEBYTECODE 1

ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install python3 gcc libc-dev -y \
    && apt-get install -y binutils libproj-dev gdal-bin python3-gdal \
    postgis postgresql-postgis libgeoip1

RUN pip install --upgrade pip
COPY ./requirements.txt /requirements.txt
RUN  pip install -r /requirements.txt


RUN mkdir /app
WORKDIR /app
COPY ./app /app

EXPOSE 8000

COPY ./app/start.sh .
RUN sed -i 's/\r$//g' /app/start.sh
RUN chmod +x /app/start.sh


ENTRYPOINT [ "/app/start.sh" ]
