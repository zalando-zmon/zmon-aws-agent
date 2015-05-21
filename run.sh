#!/bin/bash

while :
do
    echo "Executing agent..."
    python /zmon-agent.py -e $(cat /etc/entity_service_url)
    echo "sleeping..."
    sleep 60
done
