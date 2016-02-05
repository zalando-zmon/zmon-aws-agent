import os
import argparse
import boto3
from botocore.exceptions import ClientError
import logging
import json
import base64
import yaml
import requests
import hashlib
import time
import tokens

from datetime import datetime
import string

BASE_LIST = string.digits + string.ascii_letters
BASE_DICT = dict((c, i) for i, c in enumerate(BASE_LIST))

logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARN)

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


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


def get_hash(ip):
    m = hashlib.sha256()
    m.update(ip.encode())
    h = m.hexdigest()
    h = base_encode(int(h[10:18], 16))
    return h


def get_tags_dict(tags):
    return { t['Key']: t['Value'] for t in tags }

def assign_properties_from_tags(obj, tags):
    import inflection
    for tag in tags:
        key = inflection.underscore(tag['Key'])
        if key not in obj:
            obj[key] = tag['Value']


def get_running_apps(region):
    aws_client = boto3.client('ec2', region_name=region)
    rs = aws_client.describe_instances()['Reservations']
    result = []

    for r in rs:

        owner = r['OwnerId']

        instances = r['Instances']

        for i in instances:

            if str(i['State']['Name']) != 'running':
                continue

            max_tries = 10
            sleep_time = 5
            user_data = None
            for n in range(max_tries):
                try:
                    user_data_response = aws_client.describe_instance_attribute(InstanceId=i['InstanceId'],
                                                                                Attribute='userData')
                    user_data = base64.b64decode(user_data_response['UserData']['Value'])
                    user_data = yaml.safe_load(user_data)
                    break
                except ClientError as e:
                    if e.response['Error']['Code'] == "Throttling":
                        if n < max_tries - 1:
                            logging.info("Throttling AWS API requests...")
                            time.sleep(sleep_time)
                            sleep_time = min(30, sleep_time * 1.5)
                            continue
                    pass
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
                if public_ip != "" and public_ip is not None:
                    ins.update({"public_ip": public_ip})

            # for now limit us to instances with valid user data ( senza/taupage )
            if isinstance(user_data, dict) and 'application_id' in user_data:
                ins['state_reason'] = i['StateTransitionReason']

                instance_status_resp = []
                max_tries = 10
                sleep_time = 5
                for n in range(max_tries):
                    try:
                        instance_status_resp = aws_client.describe_instance_status(InstanceIds=[i['InstanceId']])
                        break
                    except ClientError as e:
                        if e.response['Error']['Code'] == "Throttling":
                            if n < max_tries - 1:
                                logging.info("Throttling AWS API requests...")
                                time.sleep(sleep_time)
                                sleep_time = min(30, sleep_time * 1.5)
                                continue
                        raise

                if 'Events' in instance_status_resp['InstanceStatuses'][0]:
                    ins['events'] = instance_status_resp['InstanceStatuses'][0]['Events']
                else:
                    ins['events'] = []

                ins['id'] = '{}-{}-{}[aws:{}:{}]'.format(user_data['application_id'],
                                                         user_data['application_version'],
                                                         get_hash(i['PrivateIpAddress'] + ""),
                                                         owner,
                                                         region)

                ins['application_id'] = user_data['application_id']
                ins['application_version'] = user_data['application_version']
                ins['source'] = user_data['source']

                if 'ports' in user_data:
                    ins['ports'] = user_data['ports']

                ins['runtime'] = user_data['runtime']

                if 'StackVersion' in tags:
                    ins['stack'] = tags['Name']
                    if 'aws:cloudformation:logical-id' in tags:
                        ins['resource_id'] = tags['aws:cloudformation:logical-id']

                # `tags` is already a dict, but we need the raw list
                assign_properties_from_tags(ins, i.get('Tags', []))

                if 'Name' in tags and 'cassandra' in tags['Name'] and 'opscenter' not in tags['Name']:
                    cas = ins.copy()
                    cas['type'] = 'cassandra'
                    cas['id'] = "cas-{}".format(cas['id'])
                    result.append(cas)

                result.append(ins)

            else:
                ins['id'] = '{}-{}[aws:{}:{}]'.format(i['InstanceId'], get_hash(i['PrivateIpAddress'] + ""),
                                                      owner, region)
                # `tags` is already a dict, but we need the raw list
                assign_properties_from_tags(ins, i.get('Tags', []))

                if 'Name' in tags:
                    ins['name'] = tags['Name'].replace(" ", "-")

                result.append(ins)

    return result


def get_running_elbs(region, acc):
    elb_client = boto3.client('elb', region_name=region)
    elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']

    # get all the tags and cache them in a dict
    elb_names = [e['LoadBalancerName'] for e in elbs]
    #
    # boto3 places an arbitrary and undocumented limit of 20 ELB names per
    # describe_tags() request, and it doesn't provide any sort of paginator:
    # work around it in a really ugly way
    #
    name_chunks = [elb_names[i: i + 20] for i in range(0, len(elb_names), 20)]
    tag_desc_chunks = [elb_client.describe_tags(LoadBalancerNames=names)
                       for names in name_chunks]
    tags = { d['LoadBalancerName']: d.get('Tags', [])
             for tag_desc in tag_desc_chunks for d in tag_desc['TagDescriptions'] }

    lbs = []

    for e in elbs:
        name = e['LoadBalancerName']

        lb = {'type': 'elb', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        lb['id'] = 'elb-{}[{}:{}]'.format(name, acc, region)
        lb['dns_name'] = e['DNSName']
        lb['host'] = e['DNSName']
        lb['name'] = name
        lb['scheme'] = e['Scheme']
        lb['url'] = 'https://{}'.format(lb['host'])
        lb['region'] = region
        lb['members'] = len(e['Instances'])
        assign_properties_from_tags(lb, tags[name])
        lbs.append(lb)

        max_tries = 10
        sleep_time = 5
        ihealth = []
        for i in range(max_tries):
            try:
                ihealth = elb_client.describe_instance_health(LoadBalancerName=e['LoadBalancerName'])['InstanceStates']
                break
            except ClientError as e:
                if e.response['Error']['Code'] == "Throttling":
                    if i < max_tries - 1:
                        # Try again
                        time.sleep(sleep_time)
                        sleep_time = min(30, sleep_time * 1.5)
                        continue
                if e.response['Error']['Code'] in ('LoadBalancerNotFound', 'ValidationError', 'Throttling'):
                    break
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
    asgs = as_client.describe_auto_scaling_groups()['AutoScalingGroups']
    for g in asgs:
        sg = {'type': 'asg', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        sg['id'] = 'asg-{}[{}:{}]'.format(g['AutoScalingGroupName'], acc, region)
        sg['name'] = g['AutoScalingGroupName']
        sg['availability_zones'] = g['AvailabilityZones']
        sg['desired_capacity'] = g['DesiredCapacity']
        sg['max_size'] = g['MaxSize']
        sg['min_size'] = g['MinSize']
        assign_properties_from_tags(sg, g.get('Tags', []))

        instance_ids = [i['InstanceId'] for i in g['Instances'] if i['LifecycleState'] == 'InService']
        reservations = ec2_client.describe_instances(InstanceIds=instance_ids)['Reservations']
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
    nodes = []
    for c in elc.describe_cache_clusters(ShowCacheNodeInfo=True)['CacheClusters']:
        if c["CacheClusterStatus"] not in ["available", "modifying", "snapshotting"]:
            continue
        for n in c['CacheNodes']:
            if n["CacheNodeStatus"] != "available":
                continue

            node = {
                "id": "elc-{}-{}[{}:{}]".format(c["CacheClusterId"], n["CacheNodeId"], acc, region),
                "region": region,
                "created_by": "agent",
                "infrastructure_account": "{}".format(acc),
                "type": "elc",
                "cluster_id": c["CacheClusterId"],
                "node_id": n["CacheNodeId"],
                "engine": c["Engine"],
                "version": c["EngineVersion"],
                "cluster_num_nodes": c["NumCacheNodes"],
                "host": n["Endpoint"]["Address"],
                "port": n["Endpoint"]["Port"],
                "instance_type": c["CacheNodeType"],
            }

            if "ReplicationGroupId" in c:
                node["replication_group"] = c["ReplicationGroupId"]
            nodes.append(node)
    return nodes


def get_dynamodb_tables(region, acc):
    tables = []

    # catch exception here, original agent policy does not allow scanning dynamodb
    try:
        ddb = boto3.client('dynamodb', region_name=region)
        tables = []
        for tn in ddb.list_tables()['TableNames']:
            t = ddb.describe_table(TableName=tn)['Table']
            if t['TableStatus'] not in ['ACTIVE', 'UPDATING']:
                continue
            table = {
                "id": "dynamodb-{}[{}:{}]".format(t["TableName"], acc, region),
                "region": region,
                "created_by": "agent",
                "infrastructure_account": "{}".format(acc),
                "type": "dynamodb",
                "name": "{}".format(t["TableName"]),
                "arn": "{}".format(t["TableArn"])
            }
            tables.append(table)
    except Exception as e:
        logging.info("Got exception while listing dynamodb tables, IAM role not allowed to access? {}".format(e))
        pass

    return tables


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
        applications.append({"id": "a-{}[{}:{}]".format(a, account, region), "application_id": a, "region": region,
                             "infrastructure_account": account, "type": "application", "created_by": "agent"})

    return applications


def get_rds_instances(region, acc):
    rds_instances = []

    try:
        rds_client = boto3.client('rds', region_name=region)
        instances = rds_client.describe_db_instances()

        for i in instances["DBInstances"]:

            db = {"id": "rds-{}[{}]".format(i["DBInstanceIdentifier"], acc), "created_by": "agent",
                  "infrastructure_account": "{}".format(acc)}

            db["type"] = "database"
            db["engine"] = i["Engine"]
            db["port"] = i["Endpoint"]["Port"]
            db["host"] = i["Endpoint"]["Address"]
            db["name"] = i["DBInstanceIdentifier"]
            db["region"] = region

            if "EngineVersion" in i:
                db["version"] = i["EngineVersion"]

            cluster_name = db["name"]
            if i.get("DBName"):
                cluster_name = i["DBName"]

            db["shards"] = {cluster_name: "{}:{}/{}".format(db["host"], db["port"], cluster_name)}

            rds_instances.append(db)

    except Exception:
        logging.exception('Failed to get RDS instance')

    return rds_instances


def main():
    argp = argparse.ArgumentParser(description='ZMon AWS Agent')
    argp.add_argument('-e', '--entity-service', dest='entityservice')
    argp.add_argument('-r', '--region', dest='region', default=None)
    argp.add_argument('-j', '--json', dest='json', action='store_true')
    argp.add_argument('--no-oauth2', dest='disable_oauth2', action='store_true', default=False)
    args = argp.parse_args()

    if not args.disable_oauth2:
        tokens.configure()
        tokens.manage('uid', ['uid'])
        tokens.start()

    logging.basicConfig(level=logging.INFO)

    if not args.region:
        logging.info("Trying to figure out region...")
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone', timeout=2)
        except:
            logging.error("Region was not specified as a parameter and can not be fetched from instance meta-data!")
            raise
        region = response.text[:-1]
    else:
        region = args.region

    logging.info("Using region: {}".format(region))

    logging.info("Entity service url: %s", args.entityservice)

    apps = get_running_apps(region)
    if len(apps) > 0:
        infrastructure_account = apps[0]['infrastructure_account']
        elbs = get_running_elbs(region, infrastructure_account)
        scaling_groups = get_auto_scaling_groups(region, infrastructure_account)
        rds = get_rds_instances(region, infrastructure_account)
        elasticaches = get_elasticache_nodes(region, infrastructure_account)
        dynamodbs = get_dynamodb_tables(region, infrastructure_account)
    else:
        elbs = []
        scaling_groups = []
        rds = []

    if args.json:
        d = {'apps': apps, 'elbs': elbs, 'rds': rds, 'elc': elasticaches, 'dynamodb': dynamodbs}
        print(json.dumps(d))
    else:

        if infrastructure_account is not None:
            account_alias = get_account_alias(region)
            ia_entity = {"type": "local",
                         "infrastructure_account": infrastructure_account,
                         "account_alias": account_alias,
                         "region": region,
                         "id": "aws-ac[{}:{}]".format(infrastructure_account, region),
                         "created_by": "agent"}

            application_entities = get_apps_from_entities(apps, infrastructure_account, region)

            current_entities = []

            for e in elbs:
                current_entities.append(e["id"])

            for e in scaling_groups:
                current_entities.append(e["id"])

            for a in apps:
                current_entities.append(a["id"])

            for a in application_entities:
                current_entities.append(a["id"])

            for a in rds:
                current_entities.append(a["id"])

            for a in elasticaches:
                current_entities.append(a["id"])

            for a in dynamodbs:
                current_entities.append(a["id"])

            current_entities.append(ia_entity["id"])

            headers = {'Content-Type': 'application/json'}
            if not args.disable_oauth2:
                token = os.getenv('ZMON_AGENT_TOKEN', tokens.get('uid'))
                logging.info("Adding oauth2 token to requests {}...{}".format(token[:1], token[-1:]))
                headers.update({'Authorization': 'Bearer {}'.format(token)})

            # removing all entities
            query = {'infrastructure_account': infrastructure_account, 'region': region, 'created_by': 'agent'}
            r = requests.get(args.entityservice,
                             params={'query': json.dumps(query)}, headers=headers)
            entities = r.json()

            existing_entities = {}

            to_remove = []
            for e in entities:
                existing_entities[e['id']] = e
                if not e["id"] in current_entities:
                    to_remove.append(e["id"])

            if os.getenv('zmon_user'):
                auth = (os.getenv('zmon_user'), os.getenv('zmon_password', ''))
            else:
                auth = None

            for e in to_remove:
                logging.info("removing instance: {}".format(e))

                r = requests.delete(args.entityservice + "{}/".format(e), auth=auth, headers=headers)

                logging.info("...%s", r.status_code)

            def put_entity(entity_type, entity):
                logging.info("Adding {} entity: {}".format(entity_type, entity['id']))

                r = requests.put(args.entityservice, auth=auth,
                                 data=json.dumps(entity, default=json_serial),
                                 headers=headers)

                logging.info("...%s", r.status_code)

            put_entity('LOCAL', ia_entity)

            for instance in apps:
                put_entity('instance', instance)

            for asg in scaling_groups:
                put_entity('Auto Scaling group', asg)

            for elb in elbs:
                put_entity('elastic load balancer', elb)

            for db in rds:
                put_entity('RDS instance', db)

            # merge here or we loose it on next pull
            for app in application_entities:
                if app['id'] in existing_entities:
                    ex = existing_entities[app['id']]
                    if 'scalyr_ts_id' in ex:
                        app['scalyr_ts_id'] = ex['scalyr_ts_id']

            for app in application_entities:
                put_entity('application', app)

            for elasticache in elasticaches:
                put_entity('elasticache', elasticache)

            for dynamodb in dynamodbs:
                put_entity('dynamodb', dynamodb)

if __name__ == '__main__':
    main()
