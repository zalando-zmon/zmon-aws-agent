ZMON source code on GitHub is no longer in active development. Zalando will no longer actively review issues or merge pull-requests.

ZMON is still being used at Zalando and serves us well for many purposes. We are now deeper into our observability journey and understand better that we need other telemetry sources and tools to elevate our understanding of the systems we operate. We support the `OpenTelemetry <https://opentelemetry.io>`_ initiative and recommended others starting their journey to begin there.

If members of the community are interested in continuing developing ZMON, consider forking it. Please review the licence before you do.

==============
ZMON AWS Agent
==============

.. image:: https://travis-ci.org/zalando-zmon/zmon-aws-agent.svg?branch=master
    :target: https://travis-ci.org/zalando-zmon/zmon-aws-agent

.. image:: https://img.shields.io/codecov/c/github/zalando-zmon/zmon-aws-agent.svg?maxAge=2592000
    :target: https://codecov.io/gh/zalando-zmon/zmon-aws-agent

.. image:: https://img.shields.io/badge/OpenTracing-enabled-blue.svg
    :target: http://opentracing.io
    :alt: OpenTracing enabled

Use AWS API to retrieve "known" applications (currently expecting `STUPS <https://docs.stups.io/en/latest/components/senza.html>`_ compatible ``userData`` for this)

Currently need to grant read only policy to EC2 instance for agent to walk over EC2/ELB instances.

Supply ``ENTITY_SERVICE_URL`` environment variable to docker image, pointing to zmon-data-service or zmon-controller, depending on your setup.

Discovers
=========

* EC2 instances
* RDS instances
* Auto Scaling Groups
* ELBs (classic and application ELBv2)
* DynamoDB tables
* Elasticaches
* IAM/ACM certificates
* SQS queues

Tests
=====

.. code-block:: bash

    $ tox

Building
========

.. code-block:: bash

    $ docker build -t zmon-aws-agent .
