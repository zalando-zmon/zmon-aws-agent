from unittest.mock import patch, MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from spotinst_sdk import SpotinstClientException

import zmon_aws_agent
from zmon_aws_agent.elastigroup import Elastigroup


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
