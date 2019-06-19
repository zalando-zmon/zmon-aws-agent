#!/bin/bash

if [ -z "$ENTITY_SERVICE_URL" ]; then
    echo 'ENTITY_SERVICE_URL must be set'
    exit 1
fi

echo "Entity Service: " $ENTITY_SERVICE_URL

if [ -z "$AGENT_SLEEP_SECONDS" ] ; then
  export AGENT_SLEEP_SECONDS=60
fi

while :
do
    echo "Executing AWS agent..."
    timeout $AGENT_SLEEP_SECONDS zmon-aws-agent -e $ENTITY_SERVICE_URL
    echo "sleeping..." $AGENT_SLEEP_SECONDS "seconds"
    sleep $AGENT_SLEEP_SECONDS
done
