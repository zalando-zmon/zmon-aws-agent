#!/bin/bash

if [ -z "$ENTITY_SERVICE_URL" ]; then
    echo 'ENTITY_SERVICE_URL must be set'
    exit 1
fi

echo $ENTITY_SERVICE_URL > /etc/entity_service_url
/usr/bin/supervisord -c /etc/supervisord.conf