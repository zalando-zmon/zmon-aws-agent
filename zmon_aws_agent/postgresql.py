import logging
import psycopg2
import boto3
import yaml
import base64
import traceback
import os

# better move that one to common?
from zmon_aws_agent.aws import entity_id
from zmon_aws_agent.common import call_and_retry, clean_opentracing_span

from opentracing_utils import trace, extract_span_from_kwargs
from opentracing.ext import tags as ot_tags


logger = logging.getLogger(__name__)

POSTGRESQL_DEFAULT_PORT = 5432
POSTGRESQL_CONNECT_TIMEOUT = os.environ.get('AGENT_POSTGRESQL_CONNECT_TIMEOUT', 2)


@trace(pass_span=True, tags={'aws': 'postgres'})
def list_postgres_databases(*args, **kwargs):
    try:
        query = """
            SELECT datname
              FROM pg_database
             WHERE datname NOT IN('postgres', 'template0', 'template1')
        """
        current_span = extract_span_from_kwargs(**kwargs)
        kwargs = clean_opentracing_span(**kwargs)

        current_span.set_tag(ot_tags.PEER_ADDRESS,
                             'psql://{}:{}'.format(kwargs.get('host'), kwargs.get('port')))
        current_span.set_tag(ot_tags.DATABASE_INSTANCE, kwargs.get('dbname'))
        current_span.set_tag(ot_tags.DATABASE_STATEMENT, query)

        kwargs.update({'connect_timeout': POSTGRESQL_CONNECT_TIMEOUT})
        conn = psycopg2.connect(*args, **kwargs)
        cur = conn.cursor()
        cur.execute(query)
        return [row[0] for row in cur.fetchall()]
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception("Failed to list DBs!")
        return []


@trace(tags={'aws': 'postgres'})
def get_databases_from_clusters(pgclusters, infrastructure_account, region,
                                postgresql_user, postgresql_pass):
    entities = []

    for pg in pgclusters:
        try:
            dnsname = pg.get('dnsname')

            if dnsname:
                dbnames = list_postgres_databases(host=dnsname,
                                                  port=POSTGRESQL_DEFAULT_PORT,
                                                  user=postgresql_user,
                                                  password=postgresql_pass,
                                                  dbname='postgres',
                                                  sslmode='require')
                for db in dbnames:
                    entity = {
                        'id': entity_id('{}-{}[{}:{}]'.format(db, dnsname, infrastructure_account, region)),
                        'type': 'postgresql_database',
                        'created_by': 'agent',
                        'infrastructure_account': infrastructure_account,
                        'region': region,

                        'postgresql_cluster': pg.get('id'),
                        'database_name': db,
                        'shards': {
                            db: '{}:{}/{}'.format(dnsname, POSTGRESQL_DEFAULT_PORT, db)
                        }
                    }
                    entities.append(entity)
        except Exception:
            logger.exception('Failed to make Database entities for PostgreSQL clusters on {}!'
                             .format(pg.get('dnsname', '')))

    return entities


@trace(tags={'aws': 'ec2'})
def collect_eip_addresses(infrastructure_account, region):
    ec2 = boto3.client('ec2', region_name=region)

    addresses = call_and_retry(ec2.describe_addresses)['Addresses']

    return [a for a in addresses if a.get('NetworkInterfaceOwnerId') == infrastructure_account.split(':')[1]]


def filter_asgs(infrastructure_account, asgs):
    return [gr for gr in asgs
            if gr.get('infrastructure_account') == infrastructure_account and 'spilo_cluster' in gr.keys()]


def filter_instances(infrastructure_account, instances):
    return [i for i in instances if i.get('infrastructure_account') == infrastructure_account]


@trace(tags={'aws': 'asg'})
def collect_launch_configurations(infrastructure_account, region):
    asg = boto3.client('autoscaling', region_name=region)
    lc_paginator = asg.get_paginator('describe_launch_configurations')
    lcs = call_and_retry(lambda: lc_paginator.paginate().build_full_result()['LaunchConfigurations'])

    user_data = {}

    for lc in lcs:
        # LaunchConfigurationName takes the form of spilo-your-cluster-AppServerInstanceProfile-66CCXX77EEPP
        lc_name = '-'.join(lc.get('LaunchConfigurationName', '').split('-')[1:-2])
        user_data[lc_name] = lc.get('UserData')

    return user_data


def extract_eipalloc_from_lc(launch_configuration, cluster_name):
    lc = launch_configuration.get(cluster_name, '')

    user_data = base64.decodebytes(lc.encode('utf-8')).decode('utf-8')
    user_data = yaml.safe_load(user_data)

    return user_data.get('environment', {}).get('EIP_ALLOCATION', '')


@trace(tags={'aws': 'route53'})
def collect_hosted_zones(infrastructure_account, region):
    r53 = boto3.client('route53', region_name=region)
    hosted_zones = r53.list_hosted_zones()  # we expect here approx. one entry
    return [hz['Id'] for hz in hosted_zones['HostedZones']]


@trace(tags={'aws': 'route53'})
def collect_recordsets(infrastructure_account, region):
    r53 = boto3.client('route53', region_name=region)
    hosted_zone_ids = collect_hosted_zones(infrastructure_account, region)
    rs_paginator = r53.get_paginator('list_resource_record_sets')

    recordsets = []
    for hz in hosted_zone_ids:
        recordsets = call_and_retry(
            lambda: rs_paginator.paginate(HostedZoneId=hz).build_full_result()['ResourceRecordSets'])

    ret = {}
    for rs in recordsets:
        if rs['Type'] == 'CNAME':
            rcs = rs.get('ResourceRecords', [])
            if rcs:
                ip = rcs[0]['Value'].split('.')[0].replace('ec2-', '').replace('-', '.')
                ret[ip] = rs.get('Name', '')[0:-1]  # cut off the final .

    return ret


@trace(tags={'aws': 'postgres'})
def get_postgresql_clusters(region, infrastructure_account, asgs, insts):
    entities = []

    try:
        addresses = collect_eip_addresses(infrastructure_account, region)
        spilo_asgs = filter_asgs(infrastructure_account, asgs)
        instances = filter_instances(infrastructure_account, insts)
        dns_records = collect_recordsets(infrastructure_account, region)
    except Exception:
        logger.exception('Failed to collect the AWS objects for PostgreSQL cluster detection')
        return []

    launch_configs = []

    # we will use the ASGs as a skeleton for building the entities
    for cluster in spilo_asgs:
        cluster_name = cluster['spilo_cluster']

        cluster_instances = []
        eip = []
        public_ip_instance_id = ''
        allocation_error = ''
        public_ip = ''

        for i in cluster['instances']:
            instance_id = i['aws_id']

            try:
                i_data = [inst for inst in instances if inst['aws_id'] == instance_id][0]
            except IndexError:
                logger.exception('Failed to find a Spilo EC2 instance: %s', instance_id)

            private_ip = i_data['ip']
            role = i_data.get("role", "")

            cluster_instances.append({'instance_id': instance_id,
                                      'private_ip': private_ip,
                                      'role': role})

            address = [a for a in addresses if a.get('InstanceId') == instance_id]
            if address:
                eip.append(address[0])  # we currently expect only one EIP per instance

        if len(eip) > 1:
            pass  # in the future, this might be a valid case, when replicas also get public IPs
        elif not eip:
            # in this case we have to look at the cluster definition, to see if there was an EIP assigned,
            # but for some reason currently is not.

            # this is so for reducing boto3 call numbers
            try:
                if not launch_configs:
                    launch_configs = collect_launch_configurations(infrastructure_account, region)

                eip_allocation = extract_eipalloc_from_lc(launch_configs, cluster_name)

                if eip_allocation:
                    address = [a for a in addresses if a.get('AllocationId') == eip_allocation]
                    if address:
                        public_ip = address[0]['PublicIp']
                        allocation_error = 'There is a public IP defined but not attached to any instance'
            except Exception:
                logger.exception('Failed to collect launch configurations')
                return []
        else:
            public_ip = eip[0]['PublicIp']
            public_ip_instance_id = eip[0]['InstanceId']

        dnsname = dns_records.get(public_ip, '')

        entities.append({'type': 'postgresql_cluster',
                         'id': entity_id('pg-{}[{}:{}]'.format(cluster_name, infrastructure_account, region)),
                         'region': region,
                         'spilo_cluster': cluster_name,
                         'elastic_ip': public_ip,
                         'elastic_ip_instance_id': public_ip_instance_id,
                         'allocation_error': allocation_error,
                         'instances': cluster_instances,
                         'infrastructure_account': infrastructure_account,
                         'dnsname': dnsname,
                         'shards': {'postgres': '{}:5432/postgres'.format(dnsname)}})

    return entities
