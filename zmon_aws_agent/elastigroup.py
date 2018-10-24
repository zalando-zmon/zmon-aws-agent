import logging
import traceback

import boto3
import inflection
from botocore.exceptions import ClientError
from opentracing_utils import extract_span_from_kwargs, trace
from spotinst_sdk import SpotinstClient

from zmon_aws_agent.aws import entity_id, add_traffic_tags_to_entity, MAX_PAGE
from zmon_aws_agent.common import call_and_retry

ELASTIGROUP_RESOURCE_TYPE = 'Custom::elastigroup'
STACK_STATUS_FILTER = [
    "CREATE_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_FAILED",
    "UPDATE_IN_PROGRESS",
    "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_IN_PROGRESS",
    "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
    "UPDATE_ROLLBACK_COMPLETE"
]
logger = logging.getLogger(__name__)


class Elastigroup:
    """
    Data required to access SpotInst API
    """

    def __init__(self, group_id, group_name, account_id, access_token):
        self.group_id = group_id
        self.group_name = group_name
        self.account_id = account_id
        self.access_token = access_token

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, Elastigroup):
            return self.group_id == other.group_id and self.group_name == other.group_name and \
                   self.account_id == other.account_id and self.access_token == other.access_token
        return False


@trace(tags={'aws': 'elastigroup'}, pass_span=True)
def get_elastigroup_entities(region, acc, **kwargs):
    groups = []
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag("aws_region", region)
    current_span.set_tag("account_id", acc)
    try:
        cf = boto3.client('cloudformation', region_name=region)

        stack_names = get_all_stack_names(cf)
        for stack_name in stack_names:
            elastigroups = get_elastigroup_resources(cf, stack_name)
            for eg_data in elastigroups:
                eg_details = get_elastigroup(eg_data, **kwargs)
                eg_name = eg_details.get('name', eg_details.get('id', 'unknown-elastigroup'))
                capacity = eg_details.get('capacity', {})
                strategy = eg_details.get('strategy', {})
                compute = eg_details.get('compute', {})
                eg = {
                    'id': entity_id('elastigroup-{}[{}:{}]'.format(eg_name, acc, region)),
                    'type': 'elastigroup',
                    'infrastructure_account': acc,
                    'region': region,
                    'created_by': 'agent',
                    'name': eg_name,
                    'availability_zones': [az.get('name', 'unknown-az') for az in
                                           eg_details.get('compute', {}).get('availability_zones', [])],
                    'desired_capacity': capacity.get('target', 1),
                    'max_size': capacity.get('maximum', 1),
                    'min_size': capacity.get('minimum', 1),
                    'risk': strategy.get('risk', 100),
                    'orientation': strategy.get('availability_vs_cost', 'balanced'),
                    'instance_types': compute.get('instance_types', None),
                    'created_time': eg_details.get('created_at', None),
                }

                for tag in compute.get('launch_specification', {}).get('tags', []):
                    key = inflection.underscore(tag.get('tag_key', None))
                    val = tag.get('tag_value', None)
                    if key and val and key not in eg:
                        eg[key] = val
                add_traffic_tags_to_entity(eg)

                eg['instances'] = []
                instances = get_elastigroup_instances(eg_data)
                for instance in instances:
                    eg['instances'].append({'aws_id': instance.get('instance_id', 'missing-instance-id'),
                                            'ip': instance.get('private_ip', 'missing-private-ip')})

                groups.append(eg)
    except Exception as e:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDenied':
            msg = 'Access to required AWS API denied. Skipping Elastigroup discovery.'
            logger.warning(msg)
            current_span.log_kv({'message': msg})
            current_span.set_tag('permission_error', True)
        else:
            logger.exception('Failed to discover Elastigroups')

    return groups


@trace(pass_span=True)
def get_elastigroup_resources(cf, stack_name, **kwargs):
    """
    Extracts the Elastigroups from existing stacks, including the respective API access tokens and cloud account IDs
    It returns those parameters from the resource of Type ``Custom::elastigroup``
    found in the stack with the name provided as arguments
    """
    groups = []
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag('stack_name', stack_name)
    paginator = cf.get_paginator('list_stack_resources')
    try:
        resources = call_and_retry(
            lambda:
            paginator.paginate(PaginationConfig={'MaxItems': MAX_PAGE}, StackName=stack_name).build_full_result()[
                'StackResourceSummaries'])
        for resource in resources:
            elastigroups = []
            if resource['ResourceType'] == ELASTIGROUP_RESOURCE_TYPE:
                elastigroups.append(resource)

            if elastigroups:
                resources = cf.get_template(StackName=stack_name)['TemplateBody']['Resources']
                for elastigroup in elastigroups:
                    group_id = elastigroup["PhysicalResourceId"]
                    group_name = elastigroup["LogicalResourceId"]
                    spotinst_token = resources[group_name]['Properties']['accessToken']
                    spotinst_account_id = resources[group_name]['Properties']['accountId']
                    groups.append(Elastigroup(group_id, group_name, spotinst_account_id, spotinst_token))
    except Exception as e:
        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDenied':
            msg = 'Access to AWS API denied. You may need the cloudformation:ListStackResources and ' \
                          'cloudformation:GetTemplate permissions'
            logger.warning(msg)
            current_span.log_kv({'message': msg})
            current_span.set_tag('access_denied', True)
        else:
            current_span.set_tag('error', True)
            current_span.log_kv({'exception': traceback.format_exc()})
            logger.exception('Failed to retrieve Elastigroup resources from Stack "{}"'.format(stack_name))

    return groups


@trace(pass_span=True)
def get_all_stack_names(cf, **kwargs):
    stacks = []
    current_span = extract_span_from_kwargs(**kwargs)
    paginator = cf.get_paginator('list_stacks')

    try:
        response_iterator = call_and_retry(
            lambda: paginator.paginate(StackStatusFilter=STACK_STATUS_FILTER))
        for page in response_iterator:
            summaries = page['StackSummaries']
            for summary in summaries:
                stacks.append(summary['StackName'])
        current_span.log_kv({"num_stacks": len(stacks)})
    except Exception as e:
        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDenied':
            msg = 'Access to AWS CloudFormation denied. You may need the cloudformation:ListStacks permission'
            logger.warning(msg)
            current_span.log_kv({'message': msg})
            current_span.set_tag('access_denied', True)
        else:
            current_span.set_tag('error', True)
            current_span.log_kv({'exception': traceback.format_exc()})
            logger.exception('Failed to retrieve stack names')

    return stacks


@trace(pass_span=True)
def get_elastigroup(elastigroup_data, **kwargs):
    """
    Returns the first Elastigroup that matches the id provided in the argument object.
    """
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag("cloud_account_id", elastigroup_data.account_id)
    current_span.set_tag("elastigroup_id", elastigroup_data.group_id)
    current_span.set_tag("elastigroup_name", elastigroup_data.group_name)
    current_span.set_tag("span.kind", "client")

    client = SpotinstClient(auth_token=elastigroup_data.access_token, account_id=elastigroup_data.account_id,
                            print_output=False)

    try:
        return client.get_elastigroup(elastigroup_data.group_id)
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception('Failed to get elastigroup {} {} in account {}'.format(elastigroup_data.group_name,
                                                                                elastigroup_data.group_id,
                                                                                elastigroup_data.account_id))


@trace(pass_span=True)
def get_elastigroup_instances(elastigroup_data, **kwargs):
    """
    Returns a list containing the active instances of an Elastigroup.
    """
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag("cloud_account_id", elastigroup_data.account_id)
    current_span.set_tag("elastigroup_id", elastigroup_data.group_id)
    current_span.set_tag("elastigroup_name", elastigroup_data.group_name)
    current_span.set_tag("span.kind", "client")

    client = SpotinstClient(auth_token=elastigroup_data.access_token, account_id=elastigroup_data.account_id,
                            print_output=False)
    try:
        return client.get_elastigroup_active_instances(elastigroup_data.group_id)
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception('Failed to get instance status for elastigroup {} {} in account {}'.format(
            elastigroup_data.group_name,
            elastigroup_data.group_id, elastigroup_data.account_id))
        return []
