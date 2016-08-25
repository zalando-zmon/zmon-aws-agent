import pytest

from mock import MagicMock, call

import zmon_aws_agent.aws as aws

from conftest import ThrottleError
from conftest import ACCOUNT, REGION, get_elc_cluster, get_autoscaling, get_elbs, get_apps


def get_boto_client(monkeypatch, *args):
    client = MagicMock()
    client.side_effect = args

    monkeypatch.setattr('boto3.client', client)

    return client


def call_retry_mock(f, *args, **kwargs):
    return f(*args, **kwargs)


@pytest.mark.parametrize('result', [{'AccountAliases': ['alias-1', 'alias-2']}, RuntimeError])
def test_aws_get_account_alias(monkeypatch, result):
    fail = True
    if type(result) is dict:
        fail = False

    iam_client = MagicMock()
    if fail:
        iam_client.list_account_aliases.side_effect = result
    else:
        iam_client.list_account_aliases.return_value = result

    boto = get_boto_client(monkeypatch, iam_client)

    res = aws.get_account_alias(REGION)

    if fail:
        assert res is None
    else:
        assert res == result['AccountAliases'][0]

    boto.assert_called_with('iam', region_name=REGION)


def test_aws_get_apps_from_entities(monkeypatch):
    instances = [{'application_id': 'app-1'}, {}]

    apps = aws.get_apps_from_entities(instances, ACCOUNT, REGION)

    res = [{
        'id': 'a-app-1[{}:{}]'.format(ACCOUNT, REGION),
        'region': REGION,
        'application_id': 'app-1',
        'infrastructure_account': ACCOUNT,
        'type': 'application',
        'created_by': 'agent',
    }]

    assert apps == res


def test_aws_get_rds_instances(monkeypatch, fx_rds):
    resp, result = fx_rds

    fail = True
    if type(resp) is dict:
        fail = False

    rds_client = MagicMock()
    rds_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp
    if fail:
        rds_client.get_paginator.return_value.paginate.return_value.build_full_result.side_effect = resp

    boto = get_boto_client(monkeypatch, rds_client)

    res = aws.get_rds_instances(REGION, ACCOUNT)

    if not fail:
        # Adjust result
        for r in result:
            r['infrastructure_account'] = ACCOUNT
            r['region'] = REGION
            r['id'] = r['id'].format(ACCOUNT)
            r['created_by'] = 'agent'

    assert res == result

    rds_client.get_paginator.assert_called_with('describe_db_instances')

    boto.assert_called_with('rds', region_name=REGION)


def test_aws_get_dynamodb_tables(monkeypatch, fx_dynamodb):
    resp, tables, result = fx_dynamodb

    fail = True
    if type(resp) is dict:
        fail = False

    dynamodb_client = MagicMock()
    dynamodb_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp
    dynamodb_client.describe_table.side_effect = tables
    if fail:
        dynamodb_client.get_paginator.return_value.paginate.return_value.build_full_result.side_effect = resp

    boto = get_boto_client(monkeypatch, dynamodb_client)

    res = aws.get_dynamodb_tables(REGION, ACCOUNT)

    if not fail:
        # Adjust result
        for r in result:
            r['infrastructure_account'] = ACCOUNT
            r['region'] = REGION
            r['id'] = r['id'].format(ACCOUNT, REGION)
            r['created_by'] = 'agent'

    assert res == result

    dynamodb_client.get_paginator.assert_called_with('list_tables')

    boto.assert_called_with('dynamodb', region_name=REGION)


def test_aws_get_elasticache(monkeypatch):
    resp, result = get_elc_cluster()

    elc_client = MagicMock()
    elc_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp

    boto = get_boto_client(monkeypatch, elc_client)

    res = aws.get_elasticache_nodes(REGION, ACCOUNT)

    assert res == result

    elc_client.get_paginator.assert_called_with('describe_cache_clusters')

    boto.assert_called_with('elasticache', region_name=REGION)


def test_aws_get_auto_scaling_groups(monkeypatch):
    resp, reservations, instance_ids, result = get_autoscaling()

    asg_client = MagicMock()
    asg_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp

    ec2_client = MagicMock()
    ec2_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = reservations

    boto = get_boto_client(monkeypatch, asg_client, ec2_client)

    res = aws.get_auto_scaling_groups(REGION, ACCOUNT)

    assert res == result

    asg_client.get_paginator.assert_called_with('describe_auto_scaling_groups')
    ec2_client.get_paginator.assert_called_with('describe_instances')
    ec2_client.get_paginator.return_value.paginate.assert_called_with(InstanceIds=instance_ids)

    calls = [call('autoscaling', region_name=REGION), call('ec2', region_name=REGION)]
    boto.assert_has_calls(calls, any_order=True)


@pytest.mark.parametrize('exc', [True, ThrottleError(), ThrottleError(throttling=False), RuntimeError])
def test_aws_get_running_elbs(monkeypatch, exc):
    resp, tags, health, result = get_elbs()

    fail = False

    elb_client = MagicMock()
    elb_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp
    elb_client.describe_tags.return_value = tags

    elb_client.describe_instance_health.return_value = health
    if exc is not True:
        if isinstance(exc, ThrottleError):
            fail = not exc.throttling
            if not fail:
                result[0]['active_members'] = 0
        else:
            fail = True
        elb_client.describe_instance_health.side_effect = exc

    monkeypatch.setattr('zmon_aws_agent.aws.call_and_retry', call_retry_mock)
    boto = get_boto_client(monkeypatch, elb_client)

    if fail:
        with pytest.raises(Exception):
            aws.get_running_elbs(REGION, ACCOUNT)
    else:
        res = aws.get_running_elbs(REGION, ACCOUNT)

        assert res == result

    elb_client.get_paginator.assert_called_with('describe_load_balancers')

    boto.assert_called_with('elb', region_name=REGION)


def test_aws_get_running_apps(monkeypatch):
    resp, status_resp, user_resp, result = get_apps()

    ec2_client = MagicMock()
    ec2_client.get_paginator.return_value.paginate.return_value.build_full_result.return_value = resp
    ec2_client.describe_instance_attribute.side_effect = user_resp
    ec2_client.describe_instance_status.return_value = status_resp

    boto = get_boto_client(monkeypatch, ec2_client)

    res = aws.get_running_apps(REGION)

    assert res == result

    calls = [call(InstanceId='ins-1', Attribute='userData'), call(InstanceId='ins-2', Attribute='userData')]
    ec2_client.describe_instance_attribute.assert_has_calls(calls, any_order=True)

    ec2_client.describe_instance_status.assert_called_with(InstanceIds=['ins-1'])

    boto.assert_called_with('ec2', region_name=REGION)


def test_aws_populate_dns(monkeypatch):
    resp = {
        'HostedZones': [
            {'Name': 'zone-1', 'Id': '1'},
            {'Name': 'zone-2', 'Id': '2'},
        ]
    }

    records_resp = [
        {
            'ResourceRecordSets': [
                {'SetIdentifier': 'r-1', 'Weight': '100', 'Type': 'CNAME'},
                {'SetIdentifier': 'r-2', 'Weight': '100', 'Type': 'A', 'AliasTarget': {'DNSName': 'app.example.org'}},
                {'SetIdentifier': 'r-skip', 'Weight': '100', 'Type': 'A', 'AliasTarget': {}},
                {'SetIdentifier': 'r-skip', 'Weight': '100', 'Type': 'A'},
                {'Weight': '100', 'Type': 'A'}, {'SetIdentifier': 'r-skip', 'Type': 'A'},
            ]
        },
        {'ResourceRecordSets': [{'SetIdentifier': 'r-2-2', 'Weight': '100', 'Type': 'CNAME'}]}
    ]

    route53_client = MagicMock()
    route53_client.list_hosted_zones.return_value = resp
    route53_client.list_resource_record_sets.side_effect = records_resp

    boto = get_boto_client(monkeypatch, route53_client)

    aws.populate_dns_data()

    dns_zone_cache = {
        'zone-1': {'Name': 'zone-1', 'Id': '1'},
        'zone-2': {'Name': 'zone-2', 'Id': '2'},
    }

    dns_rr_cache_zone = {
        'zone-1': [
            {'SetIdentifier': 'r-1', 'Weight': '100', 'Type': 'CNAME'},
            {'SetIdentifier': 'r-2', 'Weight': '100', 'Type': 'A', 'AliasTarget': {'DNSName': 'app.example.org'}},
        ],
        'zone-2': [{'SetIdentifier': 'r-2-2', 'Weight': '100', 'Type': 'CNAME'}]
    }

    assert dns_zone_cache == aws.DNS_ZONE_CACHE
    assert dns_rr_cache_zone == aws.DNS_RR_CACHE_ZONE

    calls = [call(HostedZoneId='1'), call(HostedZoneId='2')]
    route53_client.list_resource_record_sets.assert_has_calls(calls, any_order=True)

    boto.assert_called_with('route53')
