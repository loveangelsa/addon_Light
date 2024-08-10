#ARG BUILD_FROM
#FROM $BUILD_FROM
FROM python:3.10
FROM python:3.8-slim-buster

ENV LANG C.UTF-8
ENV TZ=Asia/Seoul

RUN python3 -m pip install pyserial
RUN python3 -m pip install paho-mqtt

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir paho-mqtt
#RUN pip install --no-cache-dir telnetlib

COPY . /srv
COPY ezville_wallpad2.py /srv/
COPY ezville_wallpad.py /srv/
RUN chmod a+x /srv/run_addon.sh

WORKDIR /share

CMD [ "/srv/run_addon.sh" ]
