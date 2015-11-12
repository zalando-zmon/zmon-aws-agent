# zmon-aws-agent
Use AWS API to retrieve "known" applications ( currently expecting stups compatible userData for this )

Currently need to grant read only policy to ec2 instance for agent to walk over ec2/elb instances.

Supply ENTITY_SERVICE_URL environment variable to docker image, pointing to zmon-data-service or zmon-controller, dependingon your setup.

## Discovers
 * EC2 instances
 * RDS instances
 * Auto Scaling Groups
 * ELBs
 * DynamoDB tables
