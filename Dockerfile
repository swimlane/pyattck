FROM python:3.6-alpine

COPY requirements.txt /

RUN apk add --update --no-cache g++ gcc libffi libxslt-dev python2-dev python3-dev libffi-dev openssl-dev
RUN apk add --no-cache jpeg-dev zlib-dev
RUN apk add --no-cache --virtual .build-deps build-base linux-headers
RUN pip install -r /requirements.txt

ENV TZ="America/Chicago"

COPY . /app

WORKDIR /app

RUN export PYTHONPATH=/app:$PYTHONPATH
RUN python setup.py install

CMD [ "python", "/app/bin/test.py" ]