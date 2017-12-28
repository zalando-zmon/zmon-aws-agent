==============
ZMON AWS Agent
==============

.. image:: https://travis-ci.org/zalando-zmon/zmon-aws-agent.svg?branch=master
    :target: https://travis-ci.org/zalando-zmon/zmon-aws-agent

.. image:: https://img.shields.io/codecov/c/github/zalando-zmon/zmon-aws-agent.svg?maxAge=2592000
    :target: https://codecov.io/gh/zalando-zmon/zmon-aws-agent


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
