import os
import argparse
import boto.iam
import boto.ec2
import boto.ec2.elb
import boto.cloudformation
import boto.utils
import json
import base64
import yaml
import requests
from requests.auth import HTTPBasicAuth
from pprint import pprint

def get_running_apps(region):
    aws = boto.ec2.connect_to_region(region)
    rs = aws.get_all_reservations()
    result = []

    for r in rs:

        owner = r.owner_id

        instances = r.instances

        for i in instances:
            if str(i._state) != 'running(16)':
                continue

            try:
                user_data = base64.b64decode(str(i.get_attribute('userData')["userData"]))
                user_data = yaml.load(user_data)
            except Exception as ex:
               pass

            # for now limit us to instances with valid user data ( senza/taupage )
            if isinstance(user_data, dict) and 'application_id' in user_data:
                ins = {'type':'instance', 'created_by':'agent'}

                ins['id'] = '{}[aws:{}:{}]'.format(i.id, owner, region)
                ins['instance_type'] = i.instance_type

                ins['application_id'] = user_data['application_id']
                ins['application_version'] = user_data['application_version']
                ins['source'] = user_data['source']
                if 'ports' in user_data:
                    ins['ports'] = user_data['ports']
                    for p in ins['ports'].keys():
                        ins['url']= '{}:{}'.format(i.private_dns_name, p)
                        break

                ins['runtime'] = user_data['runtime']
                ins['ip'] = i.private_ip_address
                ins['host'] = i.private_dns_name
                ins['infrastructure_account'] = 'aws:{}'.format(owner)
                ins['region'] = region

                if i.tags:
                    if 'StackVersion' in i.tags:
                        ins['stack'] = i.tags['Name']
                        ins['resource_id'] = i.tags['aws:cloudformation:logical-id']

                result.append(ins)

    return result

def get_running_elbs(region, acc):
    aws = boto.ec2.elb.connect_to_region(region)

    elbs = aws.get_all_load_balancers()

    lbs = []

    for e in elbs:
        lb = {'type':'elb', 'infrastructure_account':acc, 'region': region, 'created_by':'agent'}
        lb['id'] = 'elb-{}[aws:{}:{}]'.format(e.name, acc, region)
        lb['dns_name'] = e.dns_name
        lb['host'] = e.dns_name
        lb['name'] = e.name
        lb['url'] = 'https://{}'.format(lb['host'])
        lbs.append(lb)

    return lbs


def get_account_alias(region):
    try:
        c = boto.iam.connect_to_region(region)
        resp = c.get_account_alias()
        return resp['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]
    except:
        return None

def main():
    argp = argparse.ArgumentParser(description='ZMon AWS Agent')
    argp.add_argument('-e', '--entity-service', dest='entityserivce')
    argp.add_argument('-r', '--region', dest='region', default=None)
    argp.add_argument('-j', '--json', dest='json', action='store_true')
    args = argp.parse_args()

    if args.region == None:
        print "Trying to figure out region..."
        region = boto.utils.get_instance_metadata()['placement']['availability-zone'][:-1]
    else:
        region = args.region

    print "Using region: {}".format(region)

    print "Entity service url: ", args.entityserivce

    apps = get_running_apps(region)
    if len(apps) > 0:
        infrastructure_account = apps[0]['infrastructure_account']
        elbs = get_running_elbs(region, infrastructure_account)
    else:
        elbs = []

    if args.json:
        d = {'apps':apps, 'elbs':elbs}
        print json.dumps(d)
    else:

        if infrastructure_account is not None:
            account_alias = get_account_alias(region)
            ia_entity = { "type": "local",
                          "infrastructure_account": infrastructure_account,
                          "account_alias": account_alias,
                          "region": region,
                          "id": "aws-ac[{}:{}]".format(infrastructure_account, region),
                          "created_by": "agent" }

            print "Adding LOCAL entity: {}".format(ia_entity['id'])

            if os.getenv('zmon_user', None) is not None:
                r = requests.put(args.entityserivce, auth=HTTPBasicAuth(os.getenv('zmon_user', None), os.getenv('zmon_password', None)), data=json.dumps(ia_entity), headers={'content-type':'application/json'})
            else:
                r = requests.put(args.entityserivce, data=json.dumps(ia_entity), headers={'content-type':'application/json'})

            print "...", r.status_code

            current_entities = []
            for e in elbs:
                current_entities.append(e["id"])

            for a in apps:
                current_entities.append(a["id"])

            current_entities.append(ia_entity["id"])

            # removing all entities
            r = requests.get(args.entityserivce, params={'query':'{"infrastructure_account": "'+infrastructure_account+'", "created_by":"agent"}'})
            entities = r.json()


            to_remove = []
            for e in entities:
                if not e["id"] in current_entities:
                    to_remove.append(e["id"])

            for e in to_remove:
                print "removing instance: {}".format(e)

                if os.getenv('zmon_user', None) is not None:
                    r = requests.delete(args.entityserivce+"{}/".format(e), auth=HTTPBasicAuth(os.getenv('zmon_user', None), os.getenv('zmon_password', None)))
                else:
                    r = requests.delete(args.entityserivce+"{}/".format(e))

                print "...", r.status_code

        for instance in apps:
            print "Adding instance: {}".format(instance['id'])

            if os.getenv('zmon_user', None) is not None:
                r = requests.put(args.entityserivce, auth=HTTPBasicAuth(os.getenv('zmon_user', None), os.getenv('zmon_password', None)), data=json.dumps(instance), headers={'content-type':'application/json'})
            else:
                r = requests.put(args.entityserivce, data=json.dumps(instance), headers={'content-type':'application/json'})

            print "...", r.status_code

        for elb in elbs:
            print "Adding elastic load balancer: {}".format(elb['id'])

            if os.getenv('zmon_user', None) is not None:
                r = requests.put(args.entityserivce, auth=HTTPBasicAuth(os.getenv('zmon_user', None), os.getenv('zmon_password', None)), data=json.dumps(elb), headers={'content-type':'application/json'})
            else:
                r = requests.put(args.entityserivce, data=json.dumps(elb), headers={'content-type':'application/json'})
            print "...", r.status_code

if __name__ == '__main__':
    main()
