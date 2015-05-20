#!/bin/bash

while :
do
    python -e $(cat /etc/entity_service_url) zmon-agent.py
    sleep 60
done
