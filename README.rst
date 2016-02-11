==============
ZMON AWS Agent
==============
Use AWS API to retrieve "known" applications (currently expecting stups compatible userData for this)

Currently need to grant read only policy to EC2 instance for agent to walk over EC2/ELB instances.

Supply ENTITY_SERVICE_URL environment variable to docker image, pointing to zmon-data-service or zmon-controller, depending on your setup.

Discovers
=========

* EC2 instances
* RDS instances
* Auto Scaling Groups
* ELBs
* DynamoDB tables

Building
========

.. code-block:: bash

    $ sudo pip3 install scm-source
    $ scm-source
    $ docker build -t zmon-aws-agent .
