from __future__ import print_function

import os
import argparse
import boto3
import logging
import json
import base64
import yaml
import requests
import hashlib

import string
BASE_LIST = string.digits + string.letters
BASE_DICT = dict((c, i) for i, c in enumerate(BASE_LIST))


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
        integer /= length

    return ret


def get_hash(ip):
    m = hashlib.sha256()
    m.update(ip)
    h = m.hexdigest()
    h = base_encode(int(h[10:18], 16))
    return h


def get_running_apps(region):
    aws_client = boto3.client('ec2')
    rs = aws_client.describe_instances()['Reservations']
    result = []

    for r in rs:

        owner = r['OwnerId']

        instances = r['Instances']

        for i in instances:

            if str(i['State']['Name']) != 'running':
                continue

            try:
                user_data_response = aws_client.describe_instance_attribute(InstanceId=i['InstanceId'],
                                                                            Attribute='userData')
                user_data = base64.b64decode(user_data_response['UserData']['Value'])
                user_data = yaml.load(user_data)
            except:
                pass

            tags = {}
            if i['Tags']:
                for t in i['Tags']:
                    tags[t['Key']] = t['Value']

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

            # for now limit us to instances with valid user data ( senza/taupage )
            if isinstance(user_data, dict) and 'application_id' in user_data:
                ins['state_reason'] = i['StateTransitionReason']

                instance_status_resp = aws_client.describe_instance_status(InstanceIds=[i['InstanceId']])
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
                    ins['resource_id'] = tags['aws:cloudformation:logical-id']

                if 'Name' in tags and 'cassandra' in tags['Name'] and 'opscenter' not in tags['Name']:
                    cas = ins.copy()
                    cas['type'] = 'cassandra'
                    cas['id'] = "cas-{}".format(cas['id'])
                    result.append(cas)

                result.append(ins)

            else:
                ins['id'] = '{}-{}[aws:{}:{}]'.format(i['InstanceId'], get_hash(i['PrivateIpAddress'] + ""),
                                                      owner, region)
                if 'Name' in tags:
                    ins['name'] = tags['Name'].replace(" ", "-")

                result.append(ins)

    return result


def get_running_elbs(region, acc):
    elb_client = boto3.client('elb')
    elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']

    lbs = []

    for e in elbs:
        lb = {'type': 'elb', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        lb['id'] = 'elb-{}[{}:{}]'.format(e['LoadBalancerName'], acc, region)
        lb['dns_name'] = e['DNSName']
        lb['host'] = e['DNSName']
        lb['name'] = e['LoadBalancerName']
        lb['scheme'] = e['Scheme']

        stack = e['LoadBalancerName'].rsplit('-', 1)
        lb['stack_name'] = stack[0]
        lb['stack_version'] = stack[-1]

        lb['url'] = 'https://{}'.format(lb['host'])
        lb['region'] = region
        lb['members'] = len(e['Instances'])
        lbs.append(lb)

        ihealth = elb_client.describe_instance_health(LoadBalancerName=e['LoadBalancerName'])['InstanceStates']
        in_service = 0
        for ih in ihealth:
            if ih['State'] == 'InService':
                in_service += 1

        lb['active_members'] = in_service

    return lbs


def get_auto_scaling_groups(region, acc):
    groups = []
    as_client = boto3.client('autoscaling')
    ec2_client = boto3.client('ec2')
    asgs = as_client.describe_auto_scaling_groups()['AutoScalingGroups']
    for g in asgs:
        sg = {'type': 'asg', 'infrastructure_account': acc, 'region': region, 'created_by': 'agent'}
        sg['id'] = 'asg-{}[{}:{}]'.format(g['AutoScalingGroupName'], acc, region)
        sg['name'] = g['AutoScalingGroupName']
        sg['availability_zones'] = g['AvailabilityZones']
        sg['desired_capacity'] = g['DesiredCapacity']
        sg['max_size'] = g['MaxSize']
        sg['min_size'] = g['MinSize']

        stack_name_tag = [t for t in g['Tags'] if t['Key'] == 'StackName']
        if stack_name_tag:
            sg['stack_name_tag'] = stack_name_tag[0]['Value']

        instance_ids = [i['InstanceId'] for i in g['Instances']]
        reservations = ec2_client.describe_instances(InstanceIds=instance_ids)['Reservations']
        sg['instances'] = []
        for r in reservations:
            for i in r['Instances']:
                sg['instances'].append({
                    'aws_id': i['InstanceId'],
                    'ip': i['PrivateIpAddress'],
                })
        groups.append(sg)

    return groups


def get_account_alias(region):
    try:
        iam_client = boto3.client('iam')
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
        rds_client = boto3.client('rds')
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
    args = argp.parse_args()

    logging.basicConfig(level=logging.INFO)

    if not args.region:
        logging.info("Trying to figure out region...")
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone', timeout=2)
        except:
            logging.error("Region was not specified as a parameter and can not be fetched from instance meta-data!")
            raise
        region = response.text
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
    else:
        elbs = []
        scaling_groups = []
        rds = []

    if args.json:
        d = {'apps': apps, 'elbs': elbs}
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

            current_entities.append(ia_entity["id"])

            # removing all entities
            query = {'infrastructure_account': infrastructure_account, 'region': region, 'created_by': 'agent'}
            r = requests.get(args.entityservice,
                             params={'query': json.dumps(query)})
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

                r = requests.delete(args.entityservice+"{}/".format(e), auth=auth)

                logging.info("...%s", r.status_code)

            def put_entity(entity_type, entity):
                logging.info("Adding {} entity: {}".format(entity_type, entity['id']))

                r = requests.put(args.entityservice, auth=auth,
                                 data=json.dumps(entity),
                                 headers={'content-type': 'application/json'})

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

if __name__ == '__main__':
    main()
