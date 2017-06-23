#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import json
import requests
import tokens
import os

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


def remove_missing_entities(existing_ids, current_ids, zmon_client, json=False):
    to_be_removed_ids = list(set(existing_ids) - set(current_ids))

    error_count = 0

    if not json:
        logger.info('Removing {} entities from ZMON'.format(len(to_be_removed_ids)))
        for entity_id in to_be_removed_ids:
            try:
                logger.info('Removing entity with id: {}'.format(entity_id))

                deleted = zmon_client.delete_entity(entity_id)

                if not deleted:
                    logger.error('Failed to delete entity!')
                    error_count += 1
            except:
                logger.exception('Exception while deleting entity: {}'.format(entity_id))
                error_count += 1

    return to_be_removed_ids, error_count


def new_or_updated_entity(entity, existing_entities_dict):
    # check if new entity
    if entity['id'] not in existing_entities_dict:
        return True

    existing_entities_dict[entity['id']].pop('last_modified', None)

    return not compare_entities(entity, existing_entities_dict[entity['id']])


def add_new_entities(all_current_entities, existing_entities, zmon_client, json=False):
    existing_entities_dict = {e['id']: e for e in existing_entities}
    new_entities = [e for e in all_current_entities if new_or_updated_entity(e, existing_entities_dict)]

    error_count = 0

    if not json:
        logger.info('Adding {} new entities in ZMON'.format(len(new_entities)))
        for entity in new_entities:
            try:
                logger.info('Adding new {} entity with ID: {}'.format(entity['type'], entity['id']))

                zmon_client.add_entity(entity)
            except:
                logger.exception('Failed to add entity: {}'.format(entity))
                error_count += 1

    return new_entities, error_count


def main():
    argp = argparse.ArgumentParser(description='ZMON AWS Agent')
    argp.add_argument('-e', '--entity-service', dest='entityservice')
    argp.add_argument('-r', '--region', dest='region', default=None)
    argp.add_argument('-j', '--json', dest='json', action='store_true')
    argp.add_argument('--no-oauth2', dest='disable_oauth2', action='store_true', default=False)
    argp.add_argument('--postgresql-user', dest='postgresql_user', default=os.environ.get('AGENT_POSTGRESQL_USER'))
    argp.add_argument('--postgresql-pass', dest='postgresql_pass', default=os.environ.get('AGENT_POSTGRESQL_PASS'))
    args = argp.parse_args()

    if not args.disable_oauth2:
        tokens.configure()
        tokens.manage('uid', ['uid'])
        tokens.start()

    logging.basicConfig(level=logging.INFO)

    # 1. Determine region
    if not args.region:
        logger.info('Trying to figure out region..')
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone', timeout=2)
        except:
            logger.exception('Region was not specified as a parameter and can not be fetched from instance meta-data!')
            raise
        region = response.text[:-1]
    else:
        region = args.region

    logger.info('Using region: {}'.format(region))

    logger.info('Entity service URL: %s', args.entityservice)

    logger.info('Reading DNS data for hosted zones')
    aws.populate_dns_data()

    aws_account_id = aws.get_account_id(region)
    infrastructure_account = 'aws:{}'.format(aws_account_id) if aws_account_id else None

    if not infrastructure_account:
        logger.error('AWS agent: Cannot determine infrastructure account ID. Terminating!')
        return

    # 2. ZMON entities
    token = None if args.disable_oauth2 else tokens.get('uid')
    zmon_client = Zmon(args.entityservice, token=token, user_agent=get_user_agent())

    query = {'infrastructure_account': infrastructure_account, 'region': region, 'created_by': 'agent'}
    entities = zmon_client.get_entities(query)

    # 3. Get running apps
    apps = aws.get_running_apps(region, entities)

    elbs = []
    scaling_groups = []
    rds = []
    elasticaches = []
    dynamodbs = []
    sqs = []

    new_entities = []
    to_be_removed = []

    if len(apps) > 0:
        elbs = aws.get_running_elbs(region, infrastructure_account)
        scaling_groups = aws.get_auto_scaling_groups(region, infrastructure_account)
        rds = aws.get_rds_instances(region, infrastructure_account, entities)
        elasticaches = aws.get_elasticache_nodes(region, infrastructure_account)
        dynamodbs = aws.get_dynamodb_tables(region, infrastructure_account)
        certificates = aws.get_certificates(region, infrastructure_account)
        aws_limits = aws.get_limits(region, infrastructure_account, apps, elbs)
        sqs = aws.get_sqs_queues(region, infrastructure_account, entities)

    account_alias = aws.get_account_alias(region)
    ia_entity = {
        'type': 'local',
        'infrastructure_account': infrastructure_account,
        'account_alias': account_alias,
        'region': region,
        'id': 'aws-ac[{}:{}]'.format(infrastructure_account, region),
        'created_by': 'agent',
    }

    application_entities = aws.get_apps_from_entities(apps, infrastructure_account, region)

    if args.postgresql_user and args.postgresql_pass:
        postgresql_clusters = zmon_client.get_entities({
            'infrastructure_account': infrastructure_account,
            'region': region,
            'type': 'postgresql_cluster'
        })
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
        elbs + scaling_groups + apps + application_entities +
        rds + postgresql_databases + elasticaches + dynamodbs +
        certificates + sqs)
    current_entities.append(aws_limits)
    current_entities.append(ia_entity)

    # 4. Removing misssing entities
    existing_ids = get_existing_ids(entities)
    current_entities_ids = {e['id'] for e in current_entities}

    to_be_removed, delete_error_count = remove_missing_entities(
        existing_ids, current_entities_ids, zmon_client, json=args.json)

    logger.info('Found {} removed entities from {} entities ({} failed)'.format(
        len(new_entities), len(current_entities), delete_error_count))

    # 5. Get new/updated entities
    new_entities, add_error_count = add_new_entities(current_entities, entities, zmon_client, json=args.json)

    logger.info('Found {} new entities from {} entities ({} failed)'.format(
        len(new_entities), len(current_entities), add_error_count))

    # 6. Always add Local entity
    if not args.json:
        ia_entity['errors'] = {'delete_count': delete_error_count, 'add_count': add_error_count}
        try:
            zmon_client.add_entity(ia_entity)
        except:
            logger.exception('Failed to add Local entity: {}'.format(ia_entity))

    types = {e['type']: len([t for t in new_entities if t['type'] == e['type']]) for e in new_entities}

    for t, v in types.items():
        logger.info('Found {} new entities of type: {}'.format(v, t))

    # Check if it is a dry run!
    if args.json:
        d = {
            'applications': application_entities,
            'apps': apps,
            'dynamodb': dynamodbs,
            'elbs': elbs,
            'elc': elasticaches,
            'rds': rds,
            'certificates': certificates,
            'aws_limits': aws_limits,
            'sqs_queues': sqs,
            'new_entities': new_entities,
            'to_be_removed': to_be_removed,
        }

        print(json.dumps(d, indent=4))


if __name__ == '__main__':
    main()
