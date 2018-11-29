from unittest.mock import patch, MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from spotinst_sdk import SpotinstClientException
import requests_mock

import zmon_aws_agent
from zmon_aws_agent.elastigroup import Elastigroup, extract_instance_details


def test_get_elastigroup_entities(monkeypatch):
    stack_names = MagicMock()
    stack_names.return_value = ['foo', 'bar']
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_all_stack_names', stack_names)
    elastigroup_resources = MagicMock()
    elastigroup_resources.return_value = [Elastigroup('42', 'test', 'acct-id', 'acc-tkn')]
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup_resources', elastigroup_resources)

    elastigroup = MagicMock()
    elastigroup.return_value = {'name': 'test', 'created_at': 'now',
                                'compute': {'availability_zones': [{'name': 'az1'}],
                                            'instance_types': ['type1', 'type2'],
                                            'launch_specification': {
                                                'tags': [{'tag_key': 'tag1', 'tag_value': 'value1'}]
                                            }},
                                'capacity': {'target': 1, 'maximum': 1, 'minimum': 1},
                                'strategy': {'risk': 100, 'availability_vs_cost': 'balanced'}}
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup', elastigroup)
    elastigroup_status = MagicMock()
    elastigroup_status.return_value = [{"instance_id": "i-fake", "private_ip": "127.0.0.1"}]
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup_instances', elastigroup_status)
    entities = zmon_aws_agent.elastigroup.get_elastigroup_entities('region1', 'acc1')
    assert len(entities) == 2
    first = entities[0]
    assert first['type'] == 'elastigroup'
    assert first['risk'] == 100
    assert first['orientation'] == 'balanced'
    assert first['tag1'] == 'value1'  # validate that tags are added
    first_instance = first['instances'][0]
    assert first_instance['aws_id'] == 'i-fake'
    assert first_instance['ip'] == '127.0.0.1'


def test_get_elastigroup_entities_missing_attributes(monkeypatch):
    stack_names = MagicMock()
    stack_names.return_value = ['foo', 'bar']
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_all_stack_names', stack_names)
    elastigroup_resources = MagicMock()
    elastigroup_resources.return_value = [Elastigroup('42', 'test', 'acct-id', 'acc-tkn')]
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup_resources', elastigroup_resources)

    elastigroup = MagicMock()
    elastigroup.return_value = {'id': 'sig-123456'}
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup', elastigroup)
    elastigroup_status = MagicMock()
    elastigroup_status.return_value = [{"unexpected_key1": "i-fake"}]
    monkeypatch.setattr('zmon_aws_agent.elastigroup.get_elastigroup_instances', elastigroup_status)
    entities = zmon_aws_agent.elastigroup.get_elastigroup_entities('region1', 'acc1')
    assert len(entities) == 2
    first = entities[0]
    assert first['id'] == 'elastigroup-sig-123456[acc1:region1]'
    assert first['type'] == 'elastigroup'
    assert first['risk'] == 100
    assert first['orientation'] == 'balanced'
    first_instance = first['instances'][0]
    assert first_instance['aws_id'] == 'missing-instance-id'
    assert first_instance['ip'] == 'missing-private-ip'


@pytest.mark.parametrize(
    'lsr,gt,err,out',
    (
            # happy case with 1 stack of the expected type
            ({'StackResourceSummaries': [
                {'LogicalResourceId': 'test', 'PhysicalResourceId': '42', 'ResourceType': 'Custom::elastigroup'}]},
             {'TemplateBody': {'Resources': {'test': {'Properties': {'accessToken': 'fake', 'accountId': '12345'}}}}},
             None,
             [Elastigroup('42', 'test', '12345', 'fake')]),
            # resource with other type ignored
            ({'StackResourceSummaries': [
                {'LogicalResourceId': 'test', 'PhysicalResourceId': '42', 'ResourceType': 'Custom::elastigroup'},
                {'LogicalResourceId': 'test2', 'PhysicalResourceId': 'id', 'ResourceType': 'Custom::other-stuff'},
            ]},
             {'TemplateBody': {'Resources': {'test': {'Properties': {'accessToken': 'fake', 'accountId': '12345'}}}}},
             None,
             [Elastigroup('42', 'test', '12345', 'fake')]),
            # only resource with other types ignored
            ({'StackResourceSummaries': [
                {'LogicalResourceId': 'test', 'PhysicalResourceId': '42', 'ResourceType': 'Custom::foo'},
                {'LogicalResourceId': 'test2', 'PhysicalResourceId': 'id', 'ResourceType': 'Custom::bar'},
            ]},
             None,
             None,
             []),
            # boto error
            (None,
             None,
             ClientError({'Error': {'Code': '500', 'Message': 'Somebody Set Us Up The Bomb'}}, "dont-care"),
             []),

    )
)
def test_get_elastigroup_resources(lsr, gt, err, out):
    def mock_make_api_call(self, operation_name, kwarg):
        if err:
            raise err
        if operation_name == 'ListStackResources':
            return lsr
        elif operation_name == 'GetTemplate':
            return gt
        raise ValueError(operation_name + ' not expected')

    with patch('botocore.client.BaseClient._make_api_call', new=mock_make_api_call):
        cf = boto3.client('cloudformation', region_name='eu-central-1')
        resources = zmon_aws_agent.elastigroup.get_elastigroup_resources(cf, 'dontcare')
        # assert all([a == b for a, b in zip(resources, out)])
        assert resources == out


@pytest.mark.parametrize(
    'resp,err,out',
    (
            ({'StackSummaries': [{'StackName': 'foo'}]}, None, ['foo']),
            ({'StackSummaries': [{'StackName': 'foo'}, {'StackName': 'bar'}]}, None, ['foo', 'bar']),
            (None, ClientError({'Error': {'Code': '500', 'Message': 'Somebody Set Us Up The Bomb'}}, "dont-care"), []),
    )
)
def test_get_all_stack_names(resp, err, out):
    def mock_make_api_call(self, operation_name, kwarg):
        if operation_name == 'ListStacks':
            if err:
                raise err
            return resp
        raise ValueError(operation_name + ' not expected')

    with patch('botocore.client.BaseClient._make_api_call', new=mock_make_api_call):
        cf = boto3.client('cloudformation', region_name='eu-central-1')
        assert zmon_aws_agent.elastigroup.get_all_stack_names(cf) == out


@pytest.mark.parametrize(
    'data,err,result,expected',
    (
            (Elastigroup("42", "name", "1234", "fake"), None, {"id": "42", "foo": "bar"}, {"id": "42", "foo": "bar"}),
            (Elastigroup("42", "name", "1234", "fake"), SpotinstClientException("test", "fake"), None, None),
    )
)
def test_get_elastigroup(data, err, result, expected):
    with patch('spotinst_sdk.SpotinstClient.get_elastigroup') as elastigroup_mock:
        elastigroup_mock.return_value = result
        elastigroup_mock.side_effect = err
        got = zmon_aws_agent.elastigroup.get_elastigroup(data)
        assert got == expected


@pytest.mark.parametrize(
    'data,err,result,expected',
    (
            (Elastigroup("42", "name", "12345", "fake"), None, [{"foo": "bar"}], [{"foo": "bar"}]),
            (Elastigroup("42", "name", "12345", "fake"), SpotinstClientException("test", "fake"), None, []),
    )
)
def test_get_elastigroup_instances(data, err, result, expected):
    with patch('spotinst_sdk.SpotinstClient.get_elastigroup_active_instances') as elastigroup_status_mock:
        elastigroup_status_mock.return_value = result
        elastigroup_status_mock.side_effect = err
        got = zmon_aws_agent.elastigroup.get_elastigroup_instances(data)
        assert got == expected


def test_extract_instance_details():
    # Example from https://api.spotinst.com/spotinst-api/elastigroup/amazon-web-services/status/
    resp = '{"request":{"id":"890a90c2-5264-482b-a72b-e021557227e4","url":"/aws/ec2/group/sig-12345678/status",' \
           '"method":"GET","timestamp":"2018-06-25T11:51:42.629Z"},"response":{"status":{"code":200,"message":"OK"},' \
           '"kind":"spotinst:aws:ec2:group","items":[{"spotInstanceRequestId":"sir-3thgagpn",' \
           '"instanceId":"i-0cc289f12538e4758","instanceType":"t2.micro","product":"Linux/UNIX",' \
           '"groupId":"sig-12345678","availabilityZone":"us-west-2a","privateIp":"172.31.28.210",' \
           '"createdAt":"2018-06-25T11:49:00.000Z","publicIp":"10.10.10.10","status":"fulfilled"},' \
           '{"spotInstanceRequestId":null,"instanceId":"i-05ebb28abebdc718b","instanceType":"t2.medium",' \
           '"product":"Linux/UNIX","groupId":"sig-05417358","availabilityZone":"us-west-2a",' \
           '"privateIp":"172.31.17.189","createdAt":"2018-06-25T11:49:02.000Z","publicIp":"10.10.10.10",' \
           '"status":"running"}],"count":2}}'
    with requests_mock.Mocker() as m:
        m.get("https://api.spotinst.io/aws/ec2/group/42/status", text=resp)
        got = zmon_aws_agent.elastigroup.get_elastigroup_instances(Elastigroup("42", "name", "12345", "fake"))
        assert len(got) == 2
        inst1 = extract_instance_details(got[0])
        assert inst1['type'] == 't2.micro'
        assert inst1['spot']
        assert inst1['availability_zone'] == 'us-west-2a'
        inst2 = extract_instance_details(got[1])
        assert inst2['type'] == 't2.medium'
        assert inst2['spot'] is False
        assert inst2['availability_zone'] == 'us-west-2a'
