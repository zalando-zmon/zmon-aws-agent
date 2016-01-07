#!/bin/bash

if [ -z $AGENT_SLEEP_SECONDS ] ; then
  export AGENT_SLEEP_SECONDS=60
fi

while :
do
    echo "Executing agent..."
    python3 /zmon-agent.py -e $(cat /etc/entity_service_url)
    echo "sleeping..." $AGENT_SLEEP_SECONDS "seconds"
    sleep $AGENT_SLEEP_SECONDS
done
