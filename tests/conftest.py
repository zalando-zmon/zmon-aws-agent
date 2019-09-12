import json
import base64

from datetime import datetime
from dateutil.tz import tzutc

import pytest

from botocore.exceptions import ClientError

from zmon_aws_agent.aws import get_hash


ACCOUNT = 'aws:1234'
REGION = 'eu-central-1'


class ThrottleError(ClientError):
    def __init__(self, throttling=True):
        self.throttling = throttling
        self.response = {'Error': {'Code': 'Throttling' if throttling else 'BadRequest'}}


def get_elc_cluster():
    cluster = {
        'CacheClusterStatus': 'available',
        'CacheClusterId': 'elc-1',
        'Engine': 'redis',
        'EngineVersion': '1.0.5',
        'NumCacheNodes': 2,
        'CacheNodeType': 'redis',
        'ReplicationGroupId': 'elc-1-replica',
        'CacheNodes': [
            {
                'CacheNodeStatus': 'available', 'CacheNodeId': 'elc-n-1',
                'Endpoint': {'Port': 2727, 'Address': '0.0.0.0'}
            },
            {'CacheNodeStatus': 'unknown'}
        ]
    }

    resp = {
        'CacheClusters': [cluster.copy() for i in range(4)]
    }

    statuses = ('available', 'modifying', 'snapshotting', 'unknown')
    for idx, c in enumerate(resp['CacheClusters']):
        c['CacheClusterStatus'] = statuses[idx]

    node = {
        'id': 'elc-elc-1-elc-n-1[{}:{}]'.format(ACCOUNT, REGION),
        'region': REGION,
        'created_by': 'agent',
        'infrastructure_account': ACCOUNT,
        'type': 'elc',
        'cluster_id': 'elc-1',
        'node_id': 'elc-n-1',
        'engine': 'redis',
        'version': '1.0.5',
        'cluster_num_nodes': 2,
        'host': '0.0.0.0',
        'port': 2727,
        'instance_type': 'redis',
        'replication_group': 'elc-1-replica',
    }

    return resp, [node] * 3


def get_autoscaling():
    asg = {
        'AutoScalingGroupName': 'asg-1',
        'AvailabilityZones': ['zone-1', 'zone-2'],
        'DesiredCapacity': '3',
        'MaxSize': 10,
        'MinSize': 3,
        'Instances': [
            {'InstanceId': 'ins-1', 'LifecycleState': 'InService'},
            {'InstanceId': 'ins-2', 'LifecycleState': 'InService'},
            {'InstanceId': 'ins-3', 'LifecycleState': 'InService'},
            {'InstanceId': 'ins-4', 'LifecycleState': 'unknown'},
        ],
        'CreatedTime': datetime(2018, 6, 6, 9, 59, 38, 127000, tzinfo=tzutc())
    }

    reservations = {
        'Reservations': [
            {
                'Instances': [
                    {'PrivateIpAddress': '192.168.20.16', 'InstanceId': 'ins-1'},
                    {'InstanceId': 'ins-2'}
                ]
            }
        ]
    }

    instance_ids = ['ins-1', 'ins-2', 'ins-3']

    resp = {
        'AutoScalingGroups': [asg]
    }

    result = [
        {
            'id': 'asg-asg-1[{}:{}]'.format(ACCOUNT, REGION),
            'type': 'asg',
            'infrastructure_account': ACCOUNT,
            'region': REGION,
            'created_by': 'agent',
            'name': 'asg-1',
            'availability_zones': ['zone-1', 'zone-2'],
            'desired_capacity': '3',
            'max_size': 10,
            'min_size': 3,
            'instances': [{'aws_id': 'ins-1', 'ip': '192.168.20.16'}],
            'created_time': '2018-06-06 09:59:38.127000'
        }
    ]

    return resp, reservations, instance_ids, result


def get_elbs():
    resp = {
        'LoadBalancerDescriptions': [
            {
                'LoadBalancerName': 'elb-1',
                'DNSName': 'elb-1.example.org',
                'Scheme': 'https',
                'Instances': ['ins-1', 'ins-2', 'ins-3'],
                'ListenerDescriptions': [{'Listener': {'Protocol': 'HTTPS'}}],
            },
        ]
    }

    tags = {'TagDescriptions': [{'LoadBalancerName': 'elb-1'}]}

    health = {
        'InstanceStates': [
            {'State': 'InService'},
            {'State': 'InService'},
            {'State': 'OutOfService'},
        ]
    }

    result = [
        {
            'id': 'elb-elb-1[{}:{}]'.format(ACCOUNT, REGION),
            'type': 'elb',
            'infrastructure_account': ACCOUNT,
            'region': REGION,
            'created_by': 'agent',
            'elb_type': 'classic',
            'dns_name': 'elb-1.example.org',
            'host': 'elb-1.example.org',
            'name': 'elb-1',
            'scheme': 'https',
            'url': 'https://elb-1.example.org',
            'members': 3,
            'active_members': 2,
        }
    ]

    return resp, tags, health, result


def get_elbs_application():
    resp = {
        'LoadBalancers': [
            {
                'LoadBalancerArn': 'arn-/app/elb-1/123456',
                'LoadBalancerName': 'elb-1',
                'DNSName': 'elb-1.example.org',
                'Scheme': 'internal',
            }
        ]
    }

    listeners = {
        'Listeners': [{'Protocol': 'HTTP'}]
    }

    tags = {'TagDescriptions': [{'ResourceArn': 'arn-/app/elb-1/123456', 'Tags': []}]}

    groups = {'TargetGroups': [{'TargetGroupArn': 'arn-group-1-elb-1'}]}

    health = {
        'TargetHealthDescriptions': [
            {'TargetHealth': {'State': 'healthy'}},
            {'TargetHealth': {'State': 'healthy'}},
            {'TargetHealth': {'State': 'terminated'}},
        ]
    }

    result = [
        {
            'id': 'elb-elb-1[{}:{}]'.format(ACCOUNT, REGION),
            'type': 'elb',
            'infrastructure_account': ACCOUNT,
            'region': REGION,
            'created_by': 'agent',
            'elb_type': 'application',
            'dns_name': 'elb-1.example.org',
            'host': 'elb-1.example.org',
            'cloudwatch_name': 'app/elb-1/123456',
            'name': 'elb-1',
            'scheme': 'internal',
            'url': 'http://elb-1.example.org',
            'members': 3,
            'active_members': 2,
            'target_groups': 1,
            'target_groups_arns': ['arn-group-1-elb-1'],
        }
    ]

    return resp, tags, listeners, groups, health, result


def get_apps():
    resp = {
        'Reservations': [
            {
                'OwnerId': '1234',
                'Instances': [
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.16', 'PublicIpAddress': '194.194.20.16',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-1', 'StateTransitionReason': 'state',
                        'InstanceLifecycle': 'spot',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'stack-1'}, {'Key': 'StackVersion', 'Value': 'stack-1-1.0'},
                            {'Key': 'aws:cloudformation:logical-id', 'Value': 'cd-app'}
                        ],
                        'ImageId': 'ami-1234',
                    },
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.16',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-2', 'StateTransitionReason': 'state'
                    },
                    {
                        'State': {'Name': 'terminated'},
                    },
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.17',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-3', 'StateTransitionReason': 'state',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'myname'}
                        ]
                    },
                ],
            }
        ]
    }

    status_resp = {'InstanceStatuses': [{'Events': ['ev-1', 'ev-2']}]}

    user_data = [
        {
            'application_id': 'app-1', 'source': 'registry/stups/zmon-aws-agent:cd81',
            'ports': [2222], 'runtime': 'docker',
            'application_version': '1.0',
            'logging': {
                'fluentd_enabled': True,
                'log_destination': 's3'
            },
        },
        {
            'no-appliacation-id': 'dummy'
        }
    ]

    user_resp = [{'UserData': {'Value': base64.encodebytes(bytes(json.dumps(u), 'utf-8'))}} for u in user_data]

    result = [
        {
            'id': 'app-1-stack-1-1.0-{}[{}:{}]'.format(get_hash('192.168.20.16'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.16', 'host': '192.168.20.16', 'public_ip': '194.194.20.16',
            'instance_type': 't2.medium', 'aws_id': 'ins-1', 'fluentd_enabled': 'true',
            'state_reason': 'state', 'stack': 'stack-1', 'stack_version': 'stack-1-1.0',
            'resource_id': 'cd-app', 'application_id': 'app-1', 'application_version': '1.0',
            'source': 'registry/stups/zmon-aws-agent:cd81', 'source_base': 'registry/stups/zmon-aws-agent',
            'ports': [2222], 'runtime': 'docker', 'aws:cloudformation:logical_id': 'cd-app', 'name': 'stack-1',
            'events': ['ev-1', 'ev-2'], 'spot_instance': True, 'block_devices': {}, 'image': {
                'id': 'ami-1234',
                'name': 'Taupage-AMI-20170512-142225',
                'date': '2017-05-12T14:22:25.000+00:00',
            },
        },
        {
            'id': 'ins-2-{}[{}:{}]'.format(get_hash('192.168.20.16'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.16', 'host': '192.168.20.16', 'spot_instance': False,
            'instance_type': 't2.medium', 'aws_id': 'ins-2', 'block_devices': {}, 'image': {},
        },
        {
            'id': 'myname-{}[{}:{}]'.format(get_hash('192.168.20.17'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.17', 'host': '192.168.20.17', 'spot_instance': False,
            'instance_type': 't2.medium', 'aws_id': 'ins-3', 'name': 'myname', 'block_devices': {}, 'image': {},
        }
    ]

    images = {
        'Images': [
            {
                "Name": "Taupage-AMI-20170512-142225",
                "ImageId": "ami-1234",
                "CreationDate": "2017-05-12T14:22:25.000Z",
            }
        ]
    }

    return resp, status_resp, user_resp, result, images


def get_apps_existing():
    resp = {
        'Reservations': [
            {
                'OwnerId': '1234',
                'Instances': [
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.16', 'PublicIpAddress': '194.194.20.16',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-1', 'StateTransitionReason': 'state',
                        'InstanceLifecycle': 'spot',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'stack-1'}, {'Key': 'StackVersion', 'Value': 'stack-1-1.0'},
                            {'Key': 'aws:cloudformation:logical-id', 'Value': 'cd-app'}
                        ],
                    },
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.16',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-2', 'StateTransitionReason': 'state'
                    },
                    {
                        'State': {'Name': 'terminated'},
                    },
                    {
                        'State': {'Name': 'running'},
                        'PrivateIpAddress': '192.168.20.17',
                        'InstanceType': 't2.medium', 'InstanceId': 'ins-3', 'StateTransitionReason': 'state',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'myname'}
                        ]
                    },
                ],
            }
        ]
    }

    status_resp = {'InstanceStatuses': [{'Events': ['ev-1', 'ev-2']}]}

    user_data = [
        {
            'application_id': 'app-1', 'source': 'registry/stups/zmon-aws-agent:cd81',
            'ports': [2222], 'runtime': 'docker',
            'application_version': '1.0',
        },
        {
            'no-appliacation-id': 'dummy'
        }
    ]

    user_resp = [{'UserData': {'Value': base64.encodebytes(bytes(json.dumps(u), 'utf-8'))}} for u in user_data]

    result = [
        {
            'id': 'app-1-stack-1-1.0-{}[{}:{}]'.format(get_hash('192.168.20.16'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.16', 'host': '192.168.20.16', 'public_ip': '194.194.20.16',
            'instance_type': 't2.medium', 'aws_id': 'ins-1', 'fluentd_enabled': 'false',
            'state_reason': 'state', 'stack': 'stack-1', 'stack_version': 'stack-1-1.0',
            'resource_id': 'cd-app', 'application_id': 'app-1', 'application_version': '1.0',
            'source': 'registry/stups/zmon-aws-agent:cd81', 'source_base': 'registry/stups/zmon-aws-agent',
            'ports': [2222], 'runtime': 'docker', 'aws:cloudformation:logical_id': 'cd-app', 'name': 'stack-1',
            'events': [], 'spot_instance': True, 'block_devices': {}, 'image': {},
        },
        {
            'id': 'ins-2-{}[{}:{}]'.format(get_hash('192.168.20.16'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.16', 'host': '192.168.20.16', 'spot_instance': False,
            'instance_type': 't2.medium', 'aws_id': 'ins-2', 'block_devices': {}, 'image': {},
        },
        {
            'id': 'myname-{}[{}:{}]'.format(get_hash('192.168.20.17'), ACCOUNT, REGION),
            'type': 'instance', 'created_by': 'agent', 'region': REGION, 'infrastructure_account': 'aws:1234',
            'ip': '192.168.20.17', 'host': '192.168.20.17', 'spot_instance': False,
            'instance_type': 't2.medium', 'aws_id': 'ins-3', 'name': 'myname', 'block_devices': {}, 'image': {},
        }
    ]

    return resp, status_resp, user_resp, result


def get_certificates():
    resp_iam = {
        'ServerCertificateMetadataList': [
            {
                'Arn': 'arn-iam-zmon-cert-1',
                'Expiration': datetime(2023, 4, 26, 0, 0),
                'Path': '/',
                'ServerCertificateId': '123456',
                'ServerCertificateName': 'zmon-cert-1',
                'UploadDate': datetime(2016, 4, 27, 11, 8, 50)
            }
        ]
    }

    resp_acm = {
        'CertificateSummaryList': [
            {
                'CertificateArn': 'arn-acm-zmon-cert-2/2-123',
                'DomainName': 'zmon-cert-2',
            },
            {
                'CertificateArn': 'arn-acm-zmon-cert-3/3-123',
                'DomainName': 'zmon-cert-3',
            },
            {
                'CertificateArn': 'arn-acm-zmon-cert-4/4-123',
                'DomainName': 'zmon-cert-4',
            },
        ]
    }

    acm_certs = [
        {
            'Certificate': {
                'DomainName': 'zmon-cert-2',
                'CertificateArn': 'arn-acm-zmon-cert-2/2-123',
                'Status': 'ISSUED',
                'NotAfter': datetime(2023, 4, 26, 0, 0),
                'InUseBy': ['abc', 'def'],
                'DomainValidationOptions': {
                    'ValidationMethod': 'EMAIL'
                }
            }
        },
        {
            'Certificate': {
                'DomainName': 'zmon-cert-3',
                'CertificateArn': 'arn-acm-zmon-cert-3/3-123',
                'Status': 'VALIDATION_TIMED_OUT',
                'InUseBy': ['abc', 'def'],
                'DomainValidationOptions': {
                    'ValidationMethod': 'EMAIL'
                }
            }
        },
        {
            'Certificate': {
                'DomainName': 'zmon-cert-4',
                'CertificateArn': 'arn-acm-zmon-cert-4/4-123',
                'Status': 'ISSUED',
                'NotAfter': datetime(2023, 4, 26, 0, 0),
                'InUseBy': [],
                'DomainValidationOptions': {
                    'ValidationMethod': 'DNS'
                }
            }
        },
    ]

    result = [
        {
            'type': 'certificate', 'status': 'ISSUED', 'region': REGION, 'arn': 'arn-iam-zmon-cert-1',
            'certificate_type': 'iam', 'id': 'cert-iam-zmon-cert-1[{}:{}]'.format(ACCOUNT, REGION),
            'infrastructure_account': ACCOUNT, 'expiration': '2023-04-26T00:00:00',
            'created_by': 'agent', 'name': 'zmon-cert-1', 'in_use': 'true',
        },
        {
            'type': 'certificate', 'status': 'ISSUED', 'region': REGION, 'arn': 'arn-acm-zmon-cert-2/2-123',
            'certificate_type': 'acm', 'id': 'cert-acm-2-123-zmon-cert-2[{}:{}]'.format(ACCOUNT, REGION),
            'infrastructure_account': ACCOUNT, 'expiration': '2023-04-26T00:00:00',
            'created_by': 'agent', 'name': 'zmon-cert-2', 'in_use': 'true',
            'validation': 'EMAIL',
        },
        {
            'type': 'certificate', 'status': 'VALIDATION_TIMED_OUT', 'region': REGION,
            'arn': 'arn-acm-zmon-cert-3/3-123', 'certificate_type': 'acm',
            'id': 'cert-acm-3-123-zmon-cert-3[{}:{}]'.format(ACCOUNT, REGION), 'infrastructure_account': ACCOUNT,
            'expiration': '', 'created_by': 'agent', 'name': 'zmon-cert-3', 'in_use': 'true',
            'validation': 'EMAIL',
        },
        {
            'type': 'certificate', 'status': 'ISSUED', 'region': REGION, 'arn': 'arn-acm-zmon-cert-4/4-123',
            'certificate_type': 'acm', 'id': 'cert-acm-4-123-zmon-cert-4[{}:{}]'.format(ACCOUNT, REGION),
            'infrastructure_account': ACCOUNT, 'expiration': '2023-04-26T00:00:00',
            'created_by': 'agent', 'name': 'zmon-cert-4', 'in_use': 'false',
            'validation': 'DNS',
        }
    ]

    return resp_iam, resp_acm, acm_certs, result


@pytest.fixture(params=[
    (
        {
            'DBInstances': [
                {
                    'DBInstanceIdentifier': 'db-1', 'Engine': 'e-1', 'Endpoint': {'Port': 5432, 'Address': '0.0.0.0'},
                    'DBInstanceClass': 'm4.xlarge', 'StorageType': 'gp2', 'AllocatedStorage': 100
                },
                {
                    'DBInstanceIdentifier': 'db-2', 'Engine': 'e-1', 'Endpoint': {'Port': 5432, 'Address': '0.0.0.0'},
                    'EngineVersion': '1.0.2', 'DBName': 'db-2-name', 'DBInstanceClass': 'm4.xlarge',
                    'AllocatedStorage': 500
                },
            ]
        },
        [
            {
                'id': 'rds-db-1[{}]', 'name': 'db-1', 'engine': 'e-1', 'port': 5432, 'host': '0.0.0.0',
                'type': 'database', 'shards': {'db-1': '0.0.0.0:5432/db-1'}, 'instance_type': 'm4.xlarge',
                'storage_type': 'gp2', 'storage_size': 100
            },
            {
                'id': 'rds-db-2[{}]', 'name': 'db-2', 'engine': 'e-1', 'port': 5432, 'host': '0.0.0.0',
                'type': 'database', 'version': '1.0.2', 'shards': {'db-2-name': '0.0.0.0:5432/db-2-name'},
                'instance_type': 'm4.xlarge', 'storage_type': '', 'storage_size': 500
            },
        ]
    ),
    (
        RuntimeError,
        []
    )
])
def fx_rds(request):
    return request.param


@pytest.fixture(params=[
    (
        {
            'TableNames': ['t-1', 't-2', 't-3']  # paginator
        },
        [
            {'Table': {'TableStatus': 'ACTIVE', 'TableName': 't-1', 'TableArn': 'aws.t-1'}},
            {'Table': {'TableStatus': 'UPDATING', 'TableName': 't-2', 'TableArn': 'aws.t-2'}},
            {'Table': {'TableStatus': 'INACTIVE', 'TableName': 't-3', 'TableArn': 'aws.t-3'}},  # describe table
        ],
        [
            {'id': 'dynamodb-t-1[{}:{}]', 'type': 'dynamodb', 'name': 't-1', 'arn': 'aws.t-1'},
            {'id': 'dynamodb-t-2[{}:{}]', 'type': 'dynamodb', 'name': 't-2', 'arn': 'aws.t-2'},  # result
        ]
    ),
    (
        RuntimeError,
        [],
        []
    )
])
def fx_dynamodb(request):
    return request.param


def get_sqs_queues():
    url1 = 'https://{}.queue.amazonaws.com/123412341234/queue1'.format(REGION)
    url2 = 'https://{}.queue.amazonaws.com/123412341234/queue2'.format(REGION)
    arn1 = 'arn:aws:sqs:{}:123412341234:queue1'.format(REGION)
    arn2 = 'arn:aws:sqs:{}:123412341234:queue2'.format(REGION)

    urls = {'QueueUrls': [url1, url2]}
    attributes = [{'Attributes': {'ApproximateNumberOfMessagesNotVisible': '45',
                                  'MessageRetentionPeriod': '345600',
                                  'ApproximateNumberOfMessagesDelayed': '0',
                                  'MaximumMessageSize': '262144',
                                  'CreatedTimestamp': '1470131993',
                                  'ApproximateNumberOfMessages': '1',
                                  'ReceiveMessageWaitTimeSeconds': '10',
                                  'DelaySeconds': '0',
                                  'VisibilityTimeout': '30',
                                  'LastModifiedTimestamp': '1470131993',
                                  'QueueArn': arn1,
                                  'RedrivePolicy': json.dumps({'deadLetterTargetArn': arn2, 'maxReceiveCount': 3})
                                  }},
                  {'Attributes': {'ApproximateNumberOfMessagesNotVisible': '0',
                                  'MessageRetentionPeriod': '3600',
                                  'ApproximateNumberOfMessagesDelayed': '0',
                                  'MaximumMessageSize': '1024',
                                  'CreatedTimestamp': '1470131993',
                                  'ApproximateNumberOfMessages': '0',
                                  'ReceiveMessageWaitTimeSeconds': '15',
                                  'DelaySeconds': '20',
                                  'VisibilityTimeout': '60',
                                  'LastModifiedTimestamp': '1470131993',
                                  'QueueArn': arn2}}]

    dead_letter_sources = [
        {},
        {'queueUrls': [url1]}
    ]

    result = [
        {
            'id': 'sqs-queue1[{}:{}]'.format(ACCOUNT, REGION),
            'created_by': 'agent',
            'infrastructure_account': '{}'.format(ACCOUNT),
            'region': REGION,
            'type': 'aws_sqs',
            'name': 'queue1',
            'url': url1,
            'arn': arn1,
            'message_retention_period_seconds': 345600,
            'maximum_message_size_bytes': 262144,
            'receive_messages_wait_time_seconds': 10,
            'delay_seconds': 0,
            'visibility_timeout_seconds': 30,
            'redrive_policy_dead_letter_target_arn': arn2,
            'redrive_policy_max_receive_count': 3
        },
        {
            'id': 'sqs-queue2[{}:{}]'.format(ACCOUNT, REGION),
            'created_by': 'agent',
            'infrastructure_account': '{}'.format(ACCOUNT),
            'region': REGION,
            'type': 'aws_sqs',
            'name': 'queue2',
            'url': url2,
            'arn': arn2,
            'message_retention_period_seconds': 3600,
            'maximum_message_size_bytes': 1024,
            'receive_messages_wait_time_seconds': 15,
            'delay_seconds': 20,
            'visibility_timeout_seconds': 60,
            'redrive_policy_dead_letter_source_urls': [url1]
        }]

    return urls, attributes, dead_letter_sources, result


pg_infrastructure_account = 'aws:12345678'
pg_region = REGION


@pytest.fixture
def fx_addresses(request):
    return {'Addresses': [
        {'NetworkInterfaceOwnerId': '12345678',
         'InstanceId': 'i-1234',
         'PublicIp': '12.23.34.45',
         'AllocationId': 'eipalloc-12345678'},
        {'NetworkInterfaceOwnerId': '12345678',
         'PublicIp': '22.33.44.55',
         'AllocationId': 'eipalloc-22334455'},
        {'NetworkInterfaceOwnerId': '32165478',
         'InstanceId': 'i-7777',
         'PublicIp': '12.23.43.54',
         'AllocationId': 'eipalloc-45454545'}]}


@pytest.fixture
def fx_addresses_expected(request):
    return [
        {'NetworkInterfaceOwnerId': '12345678',
         'InstanceId': 'i-1234',
         'PublicIp': '12.23.34.45',
         'AllocationId': 'eipalloc-12345678'},
        {'NetworkInterfaceOwnerId': '12345678',
         'PublicIp': '22.33.44.55',
         'AllocationId': 'eipalloc-22334455'}]


@pytest.fixture()
def fx_asgs(request):
    return [
        {'type': 'asg',
         'infrastructure_account': pg_infrastructure_account,
         'region': 'eu-central-1',
         'spilo_cluster': 'bla',
         'name': 'spilo-bla',
         'instances': [{'aws_id': 'i-1234', 'ip': '11.22.33.44'},
                       {'aws_id': 'i-02e0', 'ip': '111.222.133.244'}]},
        {'type': 'asg',
         'infrastructure_account': pg_infrastructure_account,
         'region': 'eu-central-1',
         'spilo_cluster': 'malm',
         'name': 'spilo-malm',
         'instances': [{'aws_id': 'i-4444', 'ip': '10.20.30.40'},
                       {'aws_id': 'i-5555', 'ip': '100.200.100.200'}]},
        {'type': 'asg',
         'infrastructure_account': pg_infrastructure_account,
         'region': 'eu-central-1',
         'something_else': 'foo',
         'name': 'app-foo',
         'instances': [{'aws_id': 'i-7845'},
                       {'aws_id': 'i-9854'}]},
        {'type': 'asg',
         'infrastructure_account': 'aws:32165487',
         'region': 'eu-central-1',
         'spilo_cluster': 'baz',
         'name': 'spilo-baz',
         'instances': [{'aws_id': 'i-6587'},
                       {'aws_id': 'i-6565'}]}]


@pytest.fixture()
def fx_asgs_expected(request):
    return [
        {'type': 'asg',
         'infrastructure_account': pg_infrastructure_account,
         'region': 'eu-central-1',
         'spilo_cluster': 'bla',
         'name': 'spilo-bla',
         'instances': [{'aws_id': 'i-1234', 'ip': '11.22.33.44'},
                       {'aws_id': 'i-02e0', 'ip': '111.222.133.244'}]},
        {'type': 'asg',
         'infrastructure_account': pg_infrastructure_account,
         'region': 'eu-central-1',
         'spilo_cluster': 'malm',
         'name': 'spilo-malm',
         'instances': [{'aws_id': 'i-4444', 'ip': '10.20.30.40'},
                       {'aws_id': 'i-5555', 'ip': '100.200.100.200'}]}]


@pytest.fixture()
def fx_pg_instances(request):
    return [{'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-1234',
             'ip': '192.168.1.1',
             'role': 'master',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-02e0',
             'ip': '192.168.1.3',
             'role': 'replica',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-4444',
             'ip': '192.168.13.32',
             'role': 'master',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-5555',
             'ip': '192.168.31.154',
             'role': 'replica',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': 'aws:32165487',
             'aws_id': 'i-4321',
             'ip': '192.168.1.2',
             'role': 'replica',
             'stack_name': 'spilo'}]


@pytest.fixture()
def fx_pg_instances_expected(request):
    return [{'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-1234',
             'ip': '192.168.1.1',
             'role': 'master',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-02e0',
             'ip': '192.168.1.3',
             'role': 'replica',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-4444',
             'ip': '192.168.13.32',
             'role': 'master',
             'stack_name': 'spilo'},
            {'type': 'instance',
             'infrastructure_account': pg_infrastructure_account,
             'aws_id': 'i-5555',
             'ip': '192.168.31.154',
             'role': 'replica',
             'stack_name': 'spilo'}]


@pytest.fixture()
def fx_eip_allocation(request):
    return 'eipalloc-22334455'


@pytest.fixture()
def fx_launch_configuration(request):
    return {
        'LaunchConfigurations': [
            {
                'LaunchConfigurationName': 'spilo-malm-AppServerInstanceProfile-66CCXX77EEPP',
                'UserData': 'ZW52aXJvbm1lbnQ6IHtFSVBfQUxMT0NBVElPTjogZWlwYWxsb2MtMjIzMzQ0NTV9Cg=='
            },
            {
                'LaunchConfigurationName': 'spilo-foo-staging-AppServerInstanceProfile-66CCXX77YYZZ',
                'UserData': 'ZW52aXJvbm1lbnQ6IHtFSVBfQUxMTzMzQ0NTV9Cg=='
            }
        ]
    }


@pytest.fixture()
def fx_hosted_zones(request):
    return {'HostedZones': [
        {'ResourceRecordSetCount': 724,
         'Name': 'db.zalan.do.',
         'Config': {
             'PrivateZone': 'false',
             'Comment': 'Public Hosted Zone'},
         'CallerReference': 'sevenseconds-db.zalan.do',
         'Id': '/hostedzone/Z1FLVOF8MF971S'}]}


@pytest.fixture()
def fx_hosted_zones_expected(request):
    return ['/hostedzone/Z1FLVOF8MF971S']


@pytest.fixture()
def fx_launch_configuration_expected(request):
    return {'malm': 'ZW52aXJvbm1lbnQ6IHtFSVBfQUxMT0NBVElPTjogZWlwYWxsb2MtMjIzMzQ0NTV9Cg==',
            'foo-staging': 'ZW52aXJvbm1lbnQ6IHtFSVBfQUxMTzMzQ0NTV9Cg=='}


@pytest.fixture()
def fx_recordsets(request):
    return {'ResourceRecordSets': [
        {'Type': 'CNAME',
         'Name': 'this.that.db.zalan.do.',
         'ResourceRecords': [
             {'Value': 'ec2-11-22-33-44.eu-central-1.compute.amazonaws.com.'}],
         'TTL': 600},
        {'Type': 'CNAME',
         'Name': 'other.cluster.co.uk.',
         'ResourceRecords': [
             {'Value': 'ec2-22-33-44-55.eu-central-1.compute.amazonaws.com.'}],
         'TTL': 600},
        {'Type': 'CNAME',
         'Name': 'something.interesting.com.',
         'ResourceRecords': [
             {'Value': 'ec2-12-23-34-45.eu-central-1.compute.amazonaws.com.'}],
         'TTL': 600},
    ]}


@pytest.fixture()
def fx_ips_dnsnames(request):
    return {'11.22.33.44': 'this.that.db.zalan.do',
            '12.23.34.45': 'something.interesting.com',
            '22.33.44.55': 'other.cluster.co.uk'}


PG_CLUSTER = 'malm'
