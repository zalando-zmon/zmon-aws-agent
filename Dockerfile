FROM registry.opensource.zalan.do/stups/python:latest

RUN apt-get update && apt-get install -y python3-dev libffi-dev libssl-dev libpq-dev
RUN pip3 install -U -e git+https://github.com/zalando-zmon/opentracing-utils.git#egg=opentracing-utils

COPY . /agent

WORKDIR /agent

RUN python setup.py install

RUN adduser --disabled-password --gecos '' zmon-agent

USER zmon-agent

CMD ["bash", "start.sh"]

