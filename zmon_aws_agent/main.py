#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import json

from opentracing_utils import init_opentracing_tracer, trace_requests, trace, extract_span_from_kwargs

from zmon_aws_agent import elastigroup

trace_requests()  # noqa
import opentracing

import requests
import tokens
import os
import traceback

from zmon_cli.client import Zmon, compare_entities

import zmon_aws_agent.aws as aws
import zmon_aws_agent.postgresql as postgresql

from zmon_aws_agent.common import get_user_agent


logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARN)
logging.getLogger('botocore.vendored.requests.packages').setLevel(logging.WARN)

logger = logging.getLogger('zmon-aws-agent')


def get_existing_ids(existing_entities):
    """Return existing entities IDs based on a condition to facilitate entity update path."""
    return {entity['id'] for entity in existing_entities}


@trace(pass_span=True)
def remove_entity(zmon_client, entity_id, **kwargs):
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag('entity_id', entity_id)
    try:
        logger.info('Removing entity with id: {}'.format(entity_id))

        deleted = zmon_client.delete_entity(entity_id)

        if not deleted:
            logger.error('Failed to delete entity!')
            return 1
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception('Exception while deleting entity: {}'.format(entity_id))
        return 1
    return 0


@trace()
def remove_missing_entities(existing_ids, current_ids, zmon_client, json=False):
    to_be_removed_ids = list(set(existing_ids) - set(current_ids))

    error_count = 0

    if not json:
        logger.info('Removing {} entities from ZMON'.format(len(to_be_removed_ids)))
        for entity_id in to_be_removed_ids:
            error_count += remove_entity(zmon_client, entity_id)

    return to_be_removed_ids, error_count


def new_or_updated_entity(entity, existing_entities_dict):
    # check if new entity
    if entity['id'] not in existing_entities_dict:
        return True

    existing_entities_dict[entity['id']].pop('last_modified', None)

    return not compare_entities(entity, existing_entities_dict[entity['id']])


@trace(pass_span=True)
def add_entity(zmon_client, entity, **kwargs):
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag('entity_type', entity['type'])
    current_span.set_tag('entity_id', entity['id'])
    try:
        logger.info('Adding new {} entity with ID: {}'.format(entity['type'], entity['id']))
        zmon_client.add_entity(entity)
        return 0
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception('Failed to add entity: {}'.format(entity))
        return 1


@trace()
def add_new_entities(all_current_entities, existing_entities, zmon_client, json=False):
    existing_entities_dict = {e['id']: e for e in existing_entities if e['type'] != 'local'}
    new_entities = [e for e in all_current_entities
                    if e['type'] != 'local' and new_or_updated_entity(e, existing_entities_dict)]

    error_count = 0

    if not json:
        logger.info('Adding {} new entities in ZMON'.format(len(new_entities)))
        for entity in new_entities:
            error_count += add_entity(zmon_client, entity)
    return new_entities, error_count


@trace(pass_span=True)
def update_local_entity(zmon_client, entity, **kwargs):
    current_span = extract_span_from_kwargs(**kwargs)
    current_span.set_tag('entity_type', 'local')
    current_span.set_tag('entity_id', entity['id'])
    try:
        zmon_client.add_entity(entity)
    except Exception:
        current_span.set_tag('error', True)
        current_span.log_kv({'exception': traceback.format_exc()})
        logger.exception('Failed to add Local entity: {}'.format(entity))


def main():
    argp = argparse.ArgumentParser(description='ZMON AWS Agent')
    argp.add_argument('-e', '--entity-service', dest='entityservice')
    argp.add_argument('-r', '--region', dest='region', default=None)
    argp.add_argument('-j', '--json', dest='json', action='store_true')
    argp.add_argument('-t', '--tracer', dest='tracer', default=os.environ.get('OPENTRACING_TRACER', 'noop'))
    argp.add_argument('-T', '--timeout', dest='timeout', default=15, type=int)  # default in zmon is 10 sec
    argp.add_argument('--no-oauth2', dest='disable_oauth2', action='store_true', default=False)
    argp.add_argument('--postgresql-user', dest='postgresql_user', default=os.environ.get('AGENT_POSTGRESQL_USER'))
    argp.add_argument('--postgresql-pass', dest='postgresql_pass', default=os.environ.get('AGENT_POSTGRESQL_PASS'))
    args = argp.parse_args()

    if not args.disable_oauth2:
        tokens.configure()
        tokens.manage('uid', ['uid'])
        tokens.start()

    init_opentracing_tracer(args.tracer)
    root_span = opentracing.tracer.start_span(operation_name='aws_entity_discovery')
    with root_span:

        logging.basicConfig(level=logging.INFO)
        # 0. Fetch extra data for entities
        entity_extras = {}
        for ex in os.getenv('EXTRA_ENTITY_FIELDS', '').split(','):
            if '=' not in ex:
                continue
            k, v = ex.split('=', 1)
            if k and v:
                entity_extras[k] = v

        # 1. Determine region
        if not args.region:
            logger.info('Trying to figure out region..')
            try:
                response = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone',
                                        timeout=2)
            except Exception:
                root_span.set_tag('error', True)
                root_span.log_kv({'exception': traceback.format_exc()})
                logger.exception('Region was not specified as a parameter and' +
                                 'can not be fetched from instance meta-data!')
                raise
            region = response.text[:-1]
        else:
            region = args.region

        root_span.set_tag('region', region)

        logger.info('Using region: {}'.format(region))

        logger.info('Entity service URL: %s', args.entityservice)

        logger.info('Reading DNS data for hosted zones')
        aws.populate_dns_data()

        aws_account_id = aws.get_account_id(region)
        infrastructure_account = 'aws:{}'.format(aws_account_id) if aws_account_id else None

        if not infrastructure_account:
            logger.error('AWS agent: Cannot determine infrastructure account ID. Terminating!')
            return
        root_span.set_tag('account', infrastructure_account)

        # 2. ZMON entities
        if not args.disable_oauth2:
            token = os.getenv('ZMON_TOKEN', None) or tokens.get('uid')
        zmon_client = Zmon(args.entityservice, token=token, user_agent=get_user_agent(), timeout=args.timeout)

        query = {'infrastructure_account': infrastructure_account, 'region': region, 'created_by': 'agent'}
        entities = zmon_client.get_entities(query)

        # 3. Get running apps
        apps = aws.get_running_apps(region, entities)

        elbs = []
        scaling_groups = []
        elastigroups = []
        certificates = []
        rds = []
        elasticaches = []
        dynamodbs = []
        sqs = []
        postgresql_clusters = []
        aws_limits = []

        new_entities = []
        to_be_removed = []

        if len(apps) > 0:
            elbs = aws.get_running_elbs(region, infrastructure_account)
            scaling_groups = aws.get_auto_scaling_groups(region, infrastructure_account)
            elastigroups = elastigroup.get_elastigroup_entities(region, infrastructure_account)
            rds = aws.get_rds_instances(region, infrastructure_account, entities)
            elasticaches = aws.get_elasticache_nodes(region, infrastructure_account)
            dynamodbs = aws.get_dynamodb_tables(region, infrastructure_account)
            certificates = aws.get_certificates(region, infrastructure_account)
            aws_limits = aws.get_limits(region, infrastructure_account, apps, elbs, entities)
            sqs = aws.get_sqs_queues(region, infrastructure_account, entities)
            postgresql_clusters = postgresql.get_postgresql_clusters(region, infrastructure_account,
                                                                     scaling_groups, apps)

        account_alias = aws.get_account_alias(region)
        ia_entity = {
            'type': 'local',
            'infrastructure_account': infrastructure_account,
            'account_alias': account_alias,
            'region': region,
            'id': 'aws-ac[{}:{}]'.format(infrastructure_account, region),
            'created_by': 'agent',
        }

        account_alias_prefix = os.getenv('ACCOUNT_ALIAS_PREFIX', None)
        owner = account_alias
        if account_alias_prefix:
            owner = owner.replace(account_alias_prefix, '', 1)
        root_span.set_tag('team', owner)

        application_entities = aws.get_apps_from_entities(apps, infrastructure_account, region)

        if args.postgresql_user and args.postgresql_pass:
            postgresql_databases = postgresql.get_databases_from_clusters(postgresql_clusters,
                                                                          infrastructure_account,
                                                                          region,
                                                                          args.postgresql_user,
                                                                          args.postgresql_pass)
        else:
            # Pretend the list of DBs is empty, but also make sure we don't remove
            # any pre-existing database entities because we don't know about them.
            postgresql_databases = []
            entities = [e for e in entities if e.get('type') != 'postgresql_database']

        current_entities = (
            elbs + scaling_groups + elastigroups + apps + application_entities +
            rds + postgresql_databases + postgresql_clusters + elasticaches + dynamodbs +
            certificates + sqs)
        current_entities.append(aws_limits)
        current_entities.append(ia_entity)

        for entity in current_entities:
            entity.update(entity_extras)
            entity.update({'alias': owner})

        # 4. Removing misssing entities
        existing_ids = get_existing_ids(entities)
        current_entities_ids = {e['id'] for e in current_entities}

        to_be_removed, delete_error_count = remove_missing_entities(
            existing_ids, current_entities_ids, zmon_client, json=args.json)

        root_span.log_kv({'total_entitites': str(len(current_entities))})
        root_span.log_kv({'removed_entities': str(len(to_be_removed))})
        logger.info('Found {} removed entities from {} entities ({} failed)'.format(
                    len(to_be_removed), len(current_entities), delete_error_count))

        # 5. Get new/updated entities
        new_entities, add_error_count = add_new_entities(current_entities, entities, zmon_client, json=args.json)

        root_span.log_kv({'new_entities': str(len(new_entities))})
        logger.info('Found {} new entities from {} entities ({} failed)'.format(
                    len(new_entities), len(current_entities), add_error_count))

        # 6. Always add Local entity
        if not args.json:
            ia_entity['errors'] = {'delete_count': delete_error_count, 'add_count': add_error_count}
            update_local_entity(zmon_client, ia_entity)

        types = {e['type']: len([t for t in new_entities if t['type'] == e['type']]) for e in new_entities}

        for t, v in types.items():
            logger.info('Found {} new entities of type: {}'.format(v, t))

        # Check if it is a dry run!
        if args.json:
            d = {
                'applications': application_entities,
                'apps': apps,
                'elastigroups': elastigroups,
                'dynamodb': dynamodbs,
                'elbs': elbs,
                'elc': elasticaches,
                'rds': rds,
                'certificates': certificates,
                'aws_limits': aws_limits,
                'sqs_queues': sqs,
                'new_entities': new_entities,
                'to_be_removed': to_be_removed,
                'posgresql_clusters': postgresql_clusters
            }

            print(json.dumps(d, indent=4))


if __name__ == '__main__':
    main()
