#!/bin/bash

if [ -z "$ENTITY_SERVICE_URL" ]; then
    echo 'ENTITY_SERVICE_URL must be set'
    exit 1
fi

echo "Entity Service: " $ENTITY_SERVICE_URL
echo $ENTITY_SERVICE_URL > /etc/entity_service_url

/run.sh
