import logging
import base64
import hashlib
import inflection
import re
import string

from datetime import datetime

import boto3
import yaml

from botocore.exceptions import ClientError

from zmon_aws_agent.common import call_and_retry


BASE_LIST = string.digits + string.ascii_letters
BASE_DICT = dict((c, i) for i, c in enumerate(BASE_LIST))

DNS_ZONE_CACHE = {}
DNS_RR_CACHE_ZONE = {}

INVALID_ENTITY_CHARS_PATTERN = re.compile('[^a-zA-Z0-9@._:\[\]-]')

logger = logging.getLogger(__name__)


def entity_id(s: str) -> str:
    '''
    >>> entity_id('a_bc/def[123:456]')
    'a_bc-def[123:456]'
    '''
    return INVALID_ENTITY_CHARS_PATTERN.sub('-', s)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError('Type not serializable')


def base_decode(string, reverse_base=BASE_DICT):
    length = len(reverse_base)
    ret = 0
    for i, c in enumerate(string[::-1]):
        ret += (length ** i) * reverse_base[c]

    return ret


def base_encode(integer, base=BASE_LIST):
    length = len(base)
    ret = ''
    while integer != 0:
        ret = base[integer % length] + ret
        integer = int(integer / length)

    return ret


def populate_dns_data():
    route53 = boto3.client('route53')
    result = route53.list_hosted_zones()
    zones = result['HostedZones']

    while result.get('IsTruncated', False):
        recordfilter = {'Marker': result['NextMarker']}
        result = route53.list_hosted_zones(**recordfilter)
        zones.extend(result['HostedZones'])

    if len(zones) == 0:
        raise ValueError('No Zones are configured!')

    for zone in zones:
        DNS_ZONE_CACHE[zone['Name']] = zone

        result = route53.list_resource_record_sets(HostedZoneId=zone['Id'])
        records = result['ResourceRecordSets']

        while result['IsTruncated']:
            recordfilter = {
                'HostedZoneId': zone['Id'],
                'StartRecordName': result['NextRecordName'],
                'StartRecordType': result['NextRecordType']
            }
            if result.get('NextRecordIdentifier'):
                recordfilter['StartRecordIdentifier'] = result.get('NextRecordIdentifier')

            result = route53.list_resource_record_sets(**recordfilter)
            records.extend(result['ResourceRecordSets'])

        DNS_RR_CACHE_ZONE[zone['Name']] = [
            r for r in records if (
                ('SetIdentifier' in r and 'Weight' in r) and
                (r['Type'] == 'CNAME' or r.get('AliasTarget', {}).get('DNSName'))
            )
        ]


def get_weight_for_stack(stack_name, stack_version):
    if len(DNS_ZONE_CACHE.keys()) != 1:
        logger.info('Multiple hosted zones not supported - skipping weight')
        return None

    zone = list(DNS_ZONE_CACHE.keys())[0]

    records = list(filter(lambda x: x['SetIdentifier'] == stack_name + '-' + stack_version, DNS_RR_CACHE_ZONE[zone]))
    if len(records) != 1:
        return None

    return records[0]['Weight']


def add_traffic_tags_to_entity(entity):
    if 'stack_name' in entity and 'stack_version' in entity:
        weight = get_weight_for_stack(entity['stack_name'], entity['stack_version'])

        if weight is not None and int(weight) > 0:
            entity.update({'dns_weight': weight, 'dns_traffic': 'true'})


def get_hash(ip):
    m = hashlib.sha256()
    m.update(ip.encode())
    h = m.hexdigest()
    h = base_encode(int(h[10:18], 16))
    return h


def get_tags_dict(tags):
    return {t['Key']: t['Value'] for t in tags}


def assign_properties_from_tags(obj, tags):
    for tag in tags:
        key = inflection.underscore(tag['Key'])
        if key not in obj:
            obj[key] = tag['Value']


def get_running_apps(region):
    aws_client = boto3.client('ec2', region_name=region)

    paginator = aws_client.get_paginator('describe_instances')
    rs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': 1000}).build_full_result()['Reservations'])

    result = []

    for r in rs:

        owner = r['OwnerId']

        instances = r['Instances']

        for i in instances:

            if str(i['State']['Name']) != 'running':
                continue

            user_data = None
            try:
                user_data_response = call_and_retry(aws_client.describe_instance_attribute,
                                                    InstanceId=i['InstanceId'],
                                                    Attribute='userData')

                user_data = base64.b64decode(user_data_response['UserData']['Value'])
                user_data = yaml.safe_load(user_data)
            except:
                pass

            tags = get_tags_dict(i.get('Tags', []))

            ins = {
                'type': 'instance',
                'created_by': 'agent',
                'region': region,
                'ip': i['PrivateIpAddress'],
                'host': i['PrivateIpAddress'],
                'instance_type': i['InstanceType'],
                'aws_id': i['InstanceId'],
                'infrastructure_account': 'aws:{}'.format(owner),
            }

            if 'PublicIpAddress' in i:
                public_ip = i.get('PublicIpAddress')
                if public_ip != '' and public_ip is not None:
                    ins.update({'public_ip': public_ip})

            # for now limit us to instances with valid user data ( senza/taupage )
            if isinstance(user_data, dict) and 'application_id' in user_data:
                ins['state_reason'] = i['StateTransitionReason']

                instance_status_resp = call_and_retry(aws_client.describe_instance_status,
                                                      InstanceIds=[i['InstanceId']])

                if 'Events' in instance_status_resp['InstanceStatuses'][0]:
                    ins['events'] = instance_status_resp['InstanceStatuses'][0]['Events']
                else:
                    ins['events'] = []

                stack_version = user_data['application_version']
                if 'StackVersion' in tags:
                    ins['stack'] = tags['Name']
                    stack_version = tags['StackVersion']
                    if 'aws:cloudformation:logical-id' in tags:
                        ins['resource_id'] = tags['aws:cloudformation:logical-id']

                ins['id'] = entity_id('{}-{}-{}[aws:{}:{}]'.format(user_data['application_id'],
                                                                   stack_version,
                                                                   get_hash(i['PrivateIpAddress'] + ''),
                                                                   owner,
                                                                   region))

                ins['application_id'] = user_data['application_id']
                ins['application_version'] = user_data['application_version']
                ins['source'] = user_data['source']

                if 'ports' in user_data:
                    ins['ports'] = user_data['ports']

                ins['runtime'] = user_data['runtime']

                # `tags` is already a dict, but we need the raw list
                assign_properties_from_tags(ins, i.get('Tags', []))

                add_traffic_tags_to_entity(ins)

                if 'Name' in tags and 'cassandra' in tags['Name'] and 'opscenter' not in tags['Name']:
                    cas = ins.copy()
                    cas['type'] = 'cassandra'
                    cas['id'] = entity_id('cas-{}'.format(cas['id']))
                    result.append(cas)

                result.append(ins)

            else:
                ins['id'] = entity_id('{}-{}[aws:{}:{}]'.format(i['InstanceId'], get_hash(i['PrivateIpAddress'] + ''),
                                                                owner, region))

                # `tags` is already a dict, but we need the raw list
                assign_properties_from_tags(ins, i.get('Tags', []))

                if 'Name' in tags:
                    ins['name'] = tags['Name'].replace(' ', '-')

                result.append(ins)

    return result


def get_running_elbs(region, acc):
    elb_client = boto3.client('elb', region_name=region)

    paginator = elb_client.get_paginator('describe_load_balancers')

    elbs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': 1000}).build_full_result()['LoadBalancerDescriptions'])

    # get all the tags and cache them in a dict
    elb_names = [e['LoadBalancerName'] for e in elbs]
    #
    # boto3 places an arbitrary and undocumented limit of 20 ELB names per
    # describe_tags() request, and it doesn't provide any sort of paginator:
    # work around it in a really ugly way
    #
    name_chunks = [elb_names[i: i + 20] for i in range(0, len(elb_names), 20)]

    tag_desc_chunks = [call_and_retry(elb_client.describe_tags, LoadBalancerNames=names)
                       for names in name_chunks]

    tags = {d['LoadBalancerName']: d.get('Tags', [])
            for tag_desc in tag_desc_chunks for d in tag_desc['TagDescriptions']}

    lbs = []

    for e in elbs:
        name = e['LoadBalancerName']

        lb = {'type': 'elb', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        lb['id'] = entity_id('elb-{}[{}:{}]'.format(name, acc, region))
        lb['dns_name'] = e['DNSName']
        lb['host'] = e['DNSName']
        lb['name'] = name
        lb['scheme'] = e['Scheme']
        lb['url'] = 'https://{}'.format(lb['host'])
        lb['region'] = region
        lb['members'] = len(e['Instances'])
        assign_properties_from_tags(lb, tags[name])
        add_traffic_tags_to_entity(lb)
        lbs.append(lb)

        ihealth = []

        try:
            ihealth = call_and_retry(elb_client.describe_instance_health,
                                     LoadBalancerName=e['LoadBalancerName'])['InstanceStates']
        except ClientError as e:
            if e.response['Error']['Code'] not in ('LoadBalancerNotFound', 'ValidationError', 'Throttling'):
                raise

        in_service = 0
        for ih in ihealth:
            if ih['State'] == 'InService':
                in_service += 1

        lb['active_members'] = in_service

    return lbs


def get_auto_scaling_groups(region, acc):
    groups = []

    as_client = boto3.client('autoscaling', region_name=region)
    ec2_client = boto3.client('ec2', region_name=region)

    paginator = as_client.get_paginator('describe_auto_scaling_groups')

    asgs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': 1000}).build_full_result()['AutoScalingGroups'])

    for g in asgs:
        sg = {'type': 'asg', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        sg['id'] = entity_id('asg-{}[{}:{}]'.format(g['AutoScalingGroupName'], acc, region))
        sg['name'] = g['AutoScalingGroupName']
        sg['availability_zones'] = g['AvailabilityZones']
        sg['desired_capacity'] = g['DesiredCapacity']
        sg['max_size'] = g['MaxSize']
        sg['min_size'] = g['MinSize']
        assign_properties_from_tags(sg, g.get('Tags', []))
        add_traffic_tags_to_entity(sg)

        instance_ids = [i['InstanceId'] for i in g['Instances'] if i['LifecycleState'] == 'InService']

        ec2_paginator = ec2_client.get_paginator('describe_instances')

        reservations = call_and_retry(
            lambda: ec2_paginator.paginate(InstanceIds=instance_ids).build_full_result()['Reservations'])

        sg['instances'] = []
        for r in reservations:
            for i in r['Instances']:
                if 'PrivateIpAddress' in i:
                    sg['instances'].append({
                        'aws_id': i['InstanceId'],
                        'ip': i['PrivateIpAddress'],
                    })
        groups.append(sg)

    return groups


def get_elasticache_nodes(region, acc):
    elc = boto3.client('elasticache', region_name=region)
    paginator = elc.get_paginator('describe_cache_clusters')

    elcs = call_and_retry(
        lambda: paginator.paginate(
            ShowCacheNodeInfo=True, PaginationConfig={'MaxItems': 1000}).build_full_result()['CacheClusters'])

    nodes = []

    for c in elcs:
        if c['CacheClusterStatus'] not in ['available', 'modifying', 'snapshotting']:
            continue

        for n in c['CacheNodes']:
            if n['CacheNodeStatus'] != 'available':
                continue

            node = {
                'id': entity_id('elc-{}-{}[{}:{}]'.format(c['CacheClusterId'], n['CacheNodeId'], acc, region)),
                'region': region,
                'created_by': 'agent',
                'infrastructure_account': '{}'.format(acc),
                'type': 'elc',
                'cluster_id': c['CacheClusterId'],
                'node_id': n['CacheNodeId'],
                'engine': c['Engine'],
                'version': c['EngineVersion'],
                'cluster_num_nodes': c['NumCacheNodes'],
                'host': n['Endpoint']['Address'],
                'port': n['Endpoint']['Port'],
                'instance_type': c['CacheNodeType'],
            }

            if 'ReplicationGroupId' in c:
                node['replication_group'] = c['ReplicationGroupId']

            nodes.append(node)

    return nodes


def get_dynamodb_tables(region, acc):
    tables = []

    # catch exception here, original agent policy does not allow scanning dynamodb
    try:
        ddb = boto3.client('dynamodb', region_name=region)

        paginator = ddb.get_paginator('list_tables')

        ts = call_and_retry(
            lambda: paginator.paginate(PaginationConfig={'MaxItems': 1000}).build_full_result()['TableNames'])

        tables = []

        for tn in ts:
            t = call_and_retry(ddb.describe_table, TableName=tn)['Table']

            if t['TableStatus'] not in ['ACTIVE', 'UPDATING']:
                continue

            table = {
                'id': entity_id('dynamodb-{}[{}:{}]'.format(t['TableName'], acc, region)),
                'region': region,
                'created_by': 'agent',
                'infrastructure_account': '{}'.format(acc),
                'type': 'dynamodb',
                'name': '{}'.format(t['TableName']),
                'arn': '{}'.format(t['TableArn'])
            }

            tables.append(table)
    except:
        logger.exception('Got exception while listing dynamodb tables, IAM role not allowed to access?')
        pass

    return tables


def get_rds_instances(region, acc):
    rds_instances = []

    try:
        rds_client = boto3.client('rds', region_name=region)

        paginator = rds_client.get_paginator('describe_db_instances')

        instances = call_and_retry(lambda: paginator.paginate(PaginationConfig={'MaxItems': 1000}).build_full_result())

        for i in instances['DBInstances']:

            db = {
                'id': entity_id('rds-{}[{}]'.format(i['DBInstanceIdentifier'], acc)),
                'created_by': 'agent',
                'infrastructure_account': '{}'.format(acc)
            }

            db['type'] = 'database'
            db['engine'] = i['Engine']
            db['port'] = i['Endpoint']['Port']
            db['host'] = i['Endpoint']['Address']
            db['name'] = i['DBInstanceIdentifier']
            db['region'] = region

            if 'EngineVersion' in i:
                db['version'] = i['EngineVersion']

            cluster_name = db['name']
            if i.get('DBName'):
                cluster_name = i['DBName']

            db['shards'] = {cluster_name: '{}:{}/{}'.format(db['host'], db['port'], cluster_name)}

            rds_instances.append(db)

    except Exception:
        logger.exception('Failed to get RDS instance')

    return rds_instances


def get_account_alias(region):
    try:
        iam_client = boto3.client('iam', region_name=region)
        resp = iam_client.list_account_aliases()
        return resp['AccountAliases'][0]
    except:
        return None


def get_apps_from_entities(instances, account, region):
    apps = set()
    for i in instances:
        if 'application_id' in i:
            apps.add(i['application_id'])

    applications = []
    for a in apps:
        applications.append({
            'id': entity_id('a-{}[{}:{}]'.format(a, account, region)),
            'application_id': a,
            'region': region,
            'infrastructure_account': account,
            'type': 'application',
            'created_by': 'agent',
        })

    return applications
