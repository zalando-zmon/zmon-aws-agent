FROM zalando/python:3.4.0-4

RUN apt-get install -y supervisor

ADD requirements.txt /requirements.txt
RUN pip3 install --upgrade -r /requirements.txt

ADD run.sh /run.sh
ADD start.sh /start.sh

ADD supervisord.conf /etc/supervisord.conf

RUN touch /etc/entity_service_url
RUN chmod uog+w /etc/entity_service_url

ADD scm-source.json /scm-source.json

ADD zmon-agent.py /zmon-agent.py

CMD ["bash", "start.sh"]
