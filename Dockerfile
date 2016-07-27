FROM registry.opensource.zalan.do/stups/python:3.5.1-21

COPY . /agent

WORKDIR /agent

RUN python setup.py install

RUN adduser --disabled-password --gecos '' zmon-agent

ADD scm-source.json /scm-source.json

USER zmon-agent

CMD ["bash", "start.sh"]

