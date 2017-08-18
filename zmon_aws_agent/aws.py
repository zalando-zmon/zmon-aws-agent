import logging
import base64
import hashlib
import inflection
import re
import string
import json

from datetime import datetime

import boto3
import yaml

from botocore.exceptions import ClientError

from zmon_aws_agent.common import call_and_retry


BASE_LIST = string.digits + string.ascii_letters
BASE_DICT = dict((c, i) for i, c in enumerate(BASE_LIST))

DNS_ZONE_CACHE = {}
DNS_RR_CACHE_ZONE = {}

INVALID_ENTITY_FIRST_CHAR = re.compile('^[^a-z]+')
INVALID_ENTITY_CHARS_PATTERN = re.compile('[^a-zA-Z0-9@._:\[\]-]')

# hack, to identify kubernetes ELBs
KUBE_SERVICE_TAG = 'kubernetes.io/service_name'

MAX_PAGE = 10000

logger = logging.getLogger(__name__)


def entity_id(s: str) -> str:
    return INVALID_ENTITY_CHARS_PATTERN.sub('-', INVALID_ENTITY_FIRST_CHAR.sub('', s))


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

        while result.get('IsTruncated', False):
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
    records = []

    for zone in DNS_ZONE_CACHE.keys():
        records = [r for r in DNS_RR_CACHE_ZONE[zone] if r['SetIdentifier'] == stack_name + '-' + stack_version]

        if records:
            break

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

            if key == KUBE_SERVICE_TAG:
                obj['kube_service_name'] = tag['Value'].split('/')[-1]


def get_instance_devices(aws_client, instance):
    devices = {}

    for device in instance.get('BlockDeviceMappings', []):
        if 'Ebs' in device:
            devices[device['DeviceName']] = {
                'volume_id': device['Ebs']['VolumeId'],
                'volume_type': 'ebs',
                'attach_time': str(device['Ebs']['AttachTime'])
            }

    return devices


def get_instance_events(aws_client, instance):
    try:
        instance_status_resp = call_and_retry(aws_client.describe_instance_status,
                                              InstanceIds=[instance['InstanceId']])

        if 'Events' in instance_status_resp['InstanceStatuses'][0]:
            return instance_status_resp['InstanceStatuses'][0]['Events']
    except:
        logger.exception('Failed to retrieve instance events for instance: {}'.format(instance['InstanceId']))

    return []


def get_running_apps(region, existing_entities=None):
    aws_client = boto3.client('ec2', region_name=region)

    paginator = aws_client.get_paginator('describe_instances')
    rs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['Reservations'])

    now = datetime.now()

    existing_instances = (
        {e['aws_id']: e for e in existing_entities if e['type'] == 'instance'} if existing_entities else {}
    )

    result = []
    images = set()

    for r in rs:

        owner = r['OwnerId']

        instances = r['Instances']

        for i in instances:

            if str(i['State']['Name']) != 'running':
                continue

            if (now.minute % 7) and i['InstanceId'] in existing_instances:
                ins = existing_instances[i['InstanceId']]
                if 'image' in ins:
                    images.add(ins['image']['id'])
            else:

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

                is_spot_instance = True if i.get('InstanceLifecycle', '') == 'spot' else False

                ins = {
                    'type': 'instance',
                    'created_by': 'agent',
                    'region': region,
                    'ip': i['PrivateIpAddress'],
                    'host': i['PrivateIpAddress'],
                    'instance_type': i['InstanceType'],
                    'spot_instance': is_spot_instance,
                    'aws_id': i['InstanceId'],
                    'infrastructure_account': 'aws:{}'.format(owner),
                }

                ins['image'] = {}
                if 'ImageId' in i:
                    images.add(i['ImageId'])
                    ins['image'] = {'id': i['ImageId']}

                ins['block_devices'] = get_instance_devices(aws_client, i)

                if 'PublicIpAddress' in i:
                    public_ip = i.get('PublicIpAddress')
                    if public_ip != '' and public_ip is not None:
                        ins.update({'public_ip': public_ip})

                # for now limit us to instances with valid user data ( senza/taupage )
                if isinstance(user_data, dict) and 'application_id' in user_data:
                    ins['state_reason'] = i['StateTransitionReason']

                    ins['events'] = []

                    stack_version = user_data.get('application_version', 'NOT_SET')
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

                    if 'application_version' in user_data:
                        ins['application_version'] = user_data['application_version']

                    ins['source'] = user_data['source']
                    ins['source_base'] = ins['source'].split(":")[0]

                    if 'ports' in user_data:
                        ins['ports'] = user_data['ports']

                    ins['runtime'] = user_data['runtime']

                    # `tags` is already a dict, but we need the raw list
                    assign_properties_from_tags(ins, i.get('Tags', []))

                    add_traffic_tags_to_entity(ins)
                else:
                    ins['id'] = entity_id('{}-{}[aws:{}:{}]'.format(tags.get('Name') or i['InstanceId'],
                                                                    get_hash(i['PrivateIpAddress'] + ''),
                                                                    owner, region))

                    # `tags` is already a dict, but we need the raw list
                    assign_properties_from_tags(ins, i.get('Tags', []))

                    if 'Name' in tags:
                        ins['name'] = tags['Name'].replace(' ', '-')

            if 'application_id' in ins and not (now.minute % 10):
                ins['events'] = get_instance_events(aws_client, i)
                ins['block_devices'] = get_instance_devices(aws_client, i)

            result.append(ins)

        imgs = []
        # prevent fetching all images (in case the images is empty, it will do so):
        if list(images):
            try:
                imgs = aws_client.describe_images(ImageIds=list(images))['Images']
                for i in result:
                    if 'image' not in i or 'id' not in i['image']:
                        continue
                    for img in imgs:
                        if img['ImageId'] == i['image']['id']:
                            i['image']['name'] = img.get('Name', 'UNKNOWN')
                            date = img.get('CreationDate', '1970-01-01T00:00:00.000+00:00').replace('Z', '+00:00')
                            i['image']['date'] = date
                            break
            except:
                logger.exception('Failed to retrieve image descriptions')

    return result


def get_running_elbs(region, acc):
    return get_running_elbs_classic(region, acc) + get_running_elbs_application(region, acc)


def get_running_elbs_classic(region, acc):
    elb_client = boto3.client('elb', region_name=region)

    paginator = elb_client.get_paginator('describe_load_balancers')

    elbs = call_and_retry(
        lambda: paginator.paginate(
            PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['LoadBalancerDescriptions'])

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

        protocol = e['ListenerDescriptions'][0]['Listener']['Protocol']

        lb = {
            'id': entity_id('elb-{}[{}:{}]'.format(name, acc, region)),
            'type': 'elb',
            'infrastructure_account': acc,
            'region': region,
            'created_by': 'agent',
            'elb_type': 'classic',
            'dns_name': e['DNSName'],
            'host': e['DNSName'],
            'name': name,
            'scheme': e['Scheme'],
            'url': '{}://{}'.format(protocol.lower(), e['DNSName']),
            'members': len(e['Instances']),
        }

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


def get_running_elbs_application(region, acc):
    elb_client = boto3.client('elbv2', region_name=region)

    paginator = elb_client.get_paginator('describe_load_balancers')

    elbs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['LoadBalancers'])

    elb_arns = [e['LoadBalancerArn'] for e in elbs]

    arn_chunks = [elb_arns[i: i + 20] for i in range(0, len(elb_arns), 20)]

    tag_desc_chunks = [call_and_retry(elb_client.describe_tags, ResourceArns=arns) for arns in arn_chunks]

    tags = {d['ResourceArn']: d.get('Tags', []) for tag_desc in tag_desc_chunks for d in tag_desc['TagDescriptions']}

    lbs = []

    for e in elbs:
        arn = e['LoadBalancerArn']
        name = e['LoadBalancerName']

        tg_paginator = elb_client.get_paginator('describe_target_groups')
        try:
            target_groups = call_and_retry(
                lambda: tg_paginator.paginate(LoadBalancerArn=arn).build_full_result()['TargetGroups'])
        except:
            target_groups = []

        listeners = elb_client.describe_listeners(LoadBalancerArn=arn)['Listeners']

        protocol = listeners[0]['Protocol'] if listeners else ''

        lb = {
            'id': entity_id('elb-{}[{}:{}]'.format(name, acc, region)),
            'type': 'elb',
            'infrastructure_account': acc,
            'region': region,
            'created_by': 'agent',
            'elb_type': 'application',
            'dns_name': e['DNSName'],
            'host': e['DNSName'],
            'cloudwatch_name': '/'.join(arn.rsplit('/')[-3:]),  # name used by Cloudwatch!
            'name': name,
            'scheme': e['Scheme'],
            'url': '{}://{}'.format(protocol.lower(), e['DNSName']) if protocol else '',
            'target_groups': len(target_groups),
            'target_groups_arns': [tg['TargetGroupArn'] for tg in target_groups]
        }

        assign_properties_from_tags(lb, tags[arn])

        add_traffic_tags_to_entity(lb)

        healthy_targets = 0
        members = 0
        for tg in target_groups:
            try:
                target_health = call_and_retry(
                    elb_client.describe_target_health, TargetGroupArn=tg['TargetGroupArn'])['TargetHealthDescriptions']

                members += len(target_health)

                for th in target_health:
                    if th['TargetHealth']['State'] == 'healthy':
                        healthy_targets += 1
            except ClientError as e:
                if e.response['Error']['Code'] not in ('LoadBalancerNotFound', 'ValidationError', 'Throttling'):
                    raise

        lb['members'] = members
        lb['active_members'] = healthy_targets

        lbs.append(lb)

    return lbs


def get_auto_scaling_groups(region, acc):
    groups = []

    as_client = boto3.client('autoscaling', region_name=region)
    ec2_client = boto3.client('ec2', region_name=region)

    paginator = as_client.get_paginator('describe_auto_scaling_groups')

    asgs = call_and_retry(
        lambda: paginator.paginate(PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['AutoScalingGroups'])

    for g in asgs:
        sg = {
            'id': entity_id('asg-{}[{}:{}]'.format(g['AutoScalingGroupName'], acc, region)),
            'type': 'asg',
            'infrastructure_account': acc,
            'region': region,
            'created_by': 'agent',
            'name': g['AutoScalingGroupName'],
            'availability_zones': g['AvailabilityZones'],
            'desired_capacity': g['DesiredCapacity'],
            'max_size': g['MaxSize'],
            'min_size': g['MinSize'],
        }

        assign_properties_from_tags(sg, g.get('Tags', []))

        add_traffic_tags_to_entity(sg)

        sg['instances'] = []
        instance_ids = [i['InstanceId'] for i in g['Instances'] if i['LifecycleState'] == 'InService']
        #
        # Avoid describing instances when there's nothing to filter
        # for: that would claim *every* instance in the account.
        #
        if instance_ids:
            ec2_paginator = ec2_client.get_paginator('describe_instances')

            try:
                reservations = call_and_retry(
                    lambda: ec2_paginator.paginate(InstanceIds=instance_ids).build_full_result()['Reservations'])

                for r in reservations:
                    for i in r['Instances']:
                        if 'PrivateIpAddress' in i:
                            sg['instances'].append({
                                'aws_id': i['InstanceId'],
                                'ip': i['PrivateIpAddress'],
                            })
            except:
                logger.exception('Failed in retrieving instances for ASG: {}'.format(sg['name']))

        groups.append(sg)

    return groups


def get_elasticache_nodes(region, acc):
    elc = boto3.client('elasticache', region_name=region)
    paginator = elc.get_paginator('describe_cache_clusters')

    elcs = call_and_retry(
        lambda: paginator.paginate(
            ShowCacheNodeInfo=True, PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['CacheClusters'])

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
            lambda: paginator.paginate(PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result()['TableNames'])

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
        logger.exception('Got exception while listing dynamodb tables, IAM role has no access?')

    return tables


def get_rds_instances(region, acc, existing_entities):
    entities = []

    now = datetime.now()

    rds_entities = [r for r in existing_entities if r['type'] == 'database' and r['id'].startswith('rds-')]

    if now.minute % 15:
        return rds_entities

    try:
        rds_client = boto3.client('rds', region_name=region)

        paginator = rds_client.get_paginator('describe_db_instances')

        instances = call_and_retry(lambda: paginator.paginate(
            PaginationConfig={'MaxItems': MAX_PAGE}).build_full_result())

        for i in instances['DBInstances']:

            db = {
                'id': entity_id('rds-{}[{}]'.format(i['DBInstanceIdentifier'], acc)),
                'created_by': 'agent',
                'infrastructure_account': '{}'.format(acc),
                'region': region,
                'type': 'database',
                'engine': i['Engine'],
                'port': i['Endpoint']['Port'],
                'host': i['Endpoint']['Address'],
                'name': i['DBInstanceIdentifier'],
                'instance_type': i.get('DBInstanceClass', ''),
                'storage_type': i.get('StorageType', ''),
                'storage_size': i.get('AllocatedStorage', ''),
            }

            if 'EngineVersion' in i:
                db['version'] = i['EngineVersion']

            cluster_name = db['name']
            if i.get('DBName'):
                cluster_name = i['DBName']

            db['shards'] = {cluster_name: '{}:{}/{}'.format(db['host'], db['port'], cluster_name)}

            entities.append(db)

    except Exception:
        logger.exception('Failed to get RDS instance')

    return entities


def get_certificates(region, acc):
    iam_client = boto3.client('iam', region_name=region)
    acm_client = boto3.client('acm', region_name=region)

    entities = []

    try:
        server_certs = iam_client.list_server_certificates()['ServerCertificateMetadataList']

        acm_certs = acm_client.list_certificates()['CertificateSummaryList']

        for cert in server_certs:
            e = {
                'id': entity_id('cert-iam-{}[{}:{}]'.format(cert['ServerCertificateName'], acc, region)),
                'type': 'certificate',
                'infrastructure_account': acc,
                'region': region,
                'created_by': 'agent',
                'certificate_type': 'iam',
                'name': cert['ServerCertificateName'],
                'arn': cert['Arn'],
                'status': 'ISSUED',
                'expiration': cert['Expiration'].isoformat(),
            }

            entities.append(e)

        for cert in acm_certs:
            c = acm_client.describe_certificate(CertificateArn=cert['CertificateArn'])['Certificate']

            e = {
                'id': entity_id('cert-acm-{}[{}:{}]'.format(c['DomainName'], acc, region)),
                'type': 'certificate',
                'infrastructure_account': acc,
                'region': region,
                'created_by': 'agent',
                'certificate_type': 'acm',
                'name': c['DomainName'],
                'arn': c['CertificateArn'],
                'status': c['Status'],
                'expiration': c['NotAfter'].isoformat() if 'NotAfter' in c else '',
            }

            entities.append(e)
    except:
        logger.exception('Failed while retrieving IAM/ACM certificates, IAM role has no access?')

    return entities


def get_account_alias(region):
    try:
        iam_client = boto3.client('iam', region_name=region)
        resp = iam_client.list_account_aliases()
        return resp['AccountAliases'][0]
    except:
        return None


def get_account_id(region):
    try:
        iam_client = boto3.client('iam', region_name=region)
        role = iam_client.list_roles()['Roles'][0]
        return role['Arn'].split(':')[4]
    except:
        return None


def get_apps_from_entities(instances, account, region):
    applications = [{
        'id': entity_id('a-{}[{}:{}]'.format(a['application_id'], account, region)),
        'application_id': a['application_id'],
        'region': region,
        'infrastructure_account': account,
        'type': 'application',
        'created_by': 'agent',
    } for a in instances if 'application_id' in a]

    return applications


def get_limits(region, acc, apps, elbs):
    limits = {
        'ec2-max-instances': 20,
        'ec2-used-instances': len([a for a in apps if a['type'] == 'instance' and not a.get('spot_instance', False)]),
        'ec2-max-spot-instances': 20,  # Assume default max-spot-instances
        'ec2-used-spot-instances': len([a for a in apps if a['type'] == 'instance' and a.get('spot_instance', False)]),
        'elb-max-count': 20,
        'elb-used-count': len(elbs),
    }
    ec2 = boto3.client('ec2', region_name=region)
    rds = boto3.client('rds', region_name=region)
    asg = boto3.client('autoscaling', region_name=region)
    iam = boto3.client('iam', region_name=region)

    try:
        attrs = ec2.describe_account_attributes()['AccountAttributes']
        for attr in attrs:
            if attr['AttributeName'] == 'max-instances':
                limits['ec2-max-instances'] = int(attr['AttributeValues'][0]['AttributeValue'])
    except:
        logger.exception('Failed to query EC2 account attributes!')

    try:
        quota_names = ('ReservedDBInstances', 'AllocatedStorage')
        quotas = rds.describe_account_attributes()['AccountQuotas']
        q = {
            q['AccountQuotaName']: q for q in quotas if q['AccountQuotaName'] in quota_names
        }
        limits['rds-max-reserved'] = q['ReservedDBInstances']['Max']
        limits['rds-used-reserved'] = q['ReservedDBInstances']['Used']
        limits['rds-max-allocated'] = q['AllocatedStorage']['Max']
        limits['rds-used-allocated'] = q['AllocatedStorage']['Used']
    except:
        logger.exception('Failed to query RDS account attributes!')

    try:
        asg_limits = asg.describe_account_limits()
        limits['asg-max-groups'] = asg_limits['MaxNumberOfAutoScalingGroups']
        limits['asg-max-launch-configurations'] = asg_limits['MaxNumberOfLaunchConfigurations']
        limits['asg-used-groups'] = asg_limits['NumberOfAutoScalingGroups']
        limits['asg-used-launch-configurations'] = asg_limits['NumberOfLaunchConfigurations']
    except:
        logger.exception('Failed to query ASG limits!')

    try:
        iam_limits = iam.get_account_summary()['SummaryMap']
        limits['iam-used-server-certificates'] = iam_limits['ServerCertificates']
        limits['iam-max-server-certificates'] = iam_limits['ServerCertificatesQuota']

        limits['iam-used-instance-profiles'] = iam_limits['InstanceProfiles']
        limits['iam-max-instance-profiles'] = iam_limits['InstanceProfilesQuota']

        limits['iam-used-policies'] = iam_limits['Policies']
        limits['iam-max-policies'] = iam_limits['PoliciesQuota']

    except:
        logger.exception('Failed to query IAM account summary!')

    entity = {
        'id': entity_id('aws-limits[{}:{}]'.format(acc, region)),
        'type': 'aws_limits',
        'created_by': 'agent',
        'region': region,
        'infrastructure_account': acc,
    }

    entity.update(limits)

    return entity


def get_sqs_queues(region, acc, all_entities=None):
    if all_entities is None:
        all_entities = []
    sqs_queues = []

    try:
        sqs_client = boto3.client('sqs', region_name=region)
        list_queues_response = call_and_retry(sqs_client.list_queues) or {}
        existing_entities = {e['url']: e for e in all_entities if e['type'] == 'aws_sqs'}
        for queue_url in list_queues_response.get('QueueUrls', []):
            try:
                existing_entity = existing_entities.get(queue_url, None)
                if existing_entity and (datetime.now().minute % 15):
                    sqs_queues.append(existing_entity)
                else:
                    attributes_response = call_and_retry(sqs_client.get_queue_attributes, QueueUrl=queue_url,
                                                         AttributeNames=['All'])
                    attributes = attributes_response['Attributes']
                    queue_arn = attributes['QueueArn']
                    arn_tokens = queue_arn.split(':')
                    if len(arn_tokens) == 6:
                        queue_name = arn_tokens[-1]
                    else:
                        logger.error('Illegal SQS queue ARN: "%s" while processing url %s', queue_arn, queue_url)
                        continue

                    sqs_entity = {
                        'id': entity_id('sqs-{}[{}:{}]'.format(queue_name, acc, region)),
                        'created_by': 'agent',
                        'infrastructure_account': acc,
                        'region': region,
                        'type': 'aws_sqs',
                        'name': queue_name,
                        'url': queue_url,
                        'arn': queue_arn,
                        'message_retention_period_seconds': int(attributes.get('MessageRetentionPeriod', 345600)),
                        'maximum_message_size_bytes': int(attributes.get('MaximumMessageSize', 262144)),
                        'receive_messages_wait_time_seconds': int(attributes.get('ReceiveMessageWaitTimeSeconds', 0)),
                        'delay_seconds': int(attributes.get('DelaySeconds', 0)),
                        'visibility_timeout_seconds': int(attributes.get('VisibilityTimeout', 30))}

                    redrive_policy = json.loads(attributes.get('RedrivePolicy', '{}'))
                    dead_letter_target_arn = redrive_policy.get('deadLetterTargetArn', None)
                    if dead_letter_target_arn:
                        sqs_entity['redrive_policy_dead_letter_target_arn'] = dead_letter_target_arn
                    max_receive_count = redrive_policy.get('maxReceiveCount', None)
                    if max_receive_count:
                        sqs_entity['redrive_policy_max_receive_count'] = max_receive_count

                    dl_sources_response = call_and_retry(sqs_client.list_dead_letter_source_queues, QueueUrl=queue_url)
                    dead_letter_source_urls = dl_sources_response.get('queueUrls', None)
                    if dead_letter_source_urls:
                        sqs_entity['redrive_policy_dead_letter_source_urls'] = dead_letter_source_urls

                    sqs_queues.append(sqs_entity)
            except Exception:
                logger.exception('Failed to obtain details about queue with url="%s"', queue_url)
    except Exception as e:
        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDenied':
            logger.warning('Access to AWS SQS denied. Skip queue discovery.')
        else:
            logger.exception('Failed to list SQS queues.')

    return sqs_queues
