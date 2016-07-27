#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import argparse
import logging
import json
import requests
import tokens

import zmon_aws_agent.aws as aws

from zmon_aws_agent.zmon import ZMon


logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARN)
logging.getLogger('botocore.vendored.requests.packages').setLevel(logging.WARN)

logger = logging.getLogger('zmon-aws-agent')


def get_existing_ids(existing_entities):
    """Return existing entities IDs based on a condition to facilitate entity update path."""
    return [entity['id'] for entity in existing_entities]


def remove_missing_entities(existing_ids, current_ids, zmon_client, json=False):
    to_be_removed_ids = list(set(existing_ids) - set(current_ids))

    if not json:
        logger.info('Removing {} entities from ZMon'.format(len(to_be_removed_ids)))
        for entity_id in to_be_removed_ids:
            logger.info('Removing entity with id: {}'.format(entity_id))
            deleted = zmon_client.delete_entity(entity_id)
            if deleted:
                logger.info('ZMon entity deleted successfully')
            else:
                logger.error('Failed to delete entity!')

    return to_be_removed_ids


def new_or_updated_entity(entity, existing_entities_dict):
    # check if new entity
    if entity['id'] not in existing_entities_dict:
        return True

    existing_entities_dict[entity['id']].pop('last_modified', None)
    return entity != existing_entities_dict[entity['id']]


def add_new_entities(all_current_entities, existing_entities, zmon_client, json=False):
    existing_entities_dict = {e['id']: e for e in existing_entities}
    new_entities = [e for e in all_current_entities if new_or_updated_entity(e, existing_entities_dict)]

    if not json:
        try:
            logger.info('Found {} new entities to be added in ZMon'.format(len(new_entities)))
            for entity in new_entities:
                logger.info(
                    'Adding new {} entity with ID: {}'.format(entity['type'], entity['id']))
                resp = zmon_client.add_entity(entity)
                logger.info('ZMon response ... {}'.format(resp.status_code))
        except:
            logger.exception('Failed to add entity!')

    return new_entities


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

    # 1. Determine region
    if not args.region:
        logger.info('Trying to figure out region..')
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone', timeout=2)
        except:
            logger.error('Region was not specified as a parameter and can not be fetched from instance meta-data!')
            raise
        region = response.text[:-1]
    else:
        region = args.region

    logger.info('Using region: {}'.format(region))

    logger.info('Entity service URL: %s', args.entityservice)

    logger.info('Reading DNS data for hosted zones')
    aws.populate_dns_data()

    # 2. Get running apps
    apps = aws.get_running_apps(region)

    infrastructure_account = None

    elbs = []
    scaling_groups = []
    rds = []
    elasticaches = []
    dynamodbs = []

    new_entities = []
    to_be_removed = []

    if len(apps) > 0:
        infrastructure_account = apps[0]['infrastructure_account']
        elbs = aws.get_running_elbs(region, infrastructure_account)
        scaling_groups = aws.get_auto_scaling_groups(region, infrastructure_account)
        rds = aws.get_rds_instances(region, infrastructure_account)
        elasticaches = aws.get_elasticache_nodes(region, infrastructure_account)
        dynamodbs = aws.get_dynamodb_tables(region, infrastructure_account)

    if infrastructure_account:
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

        current_entities = elbs + scaling_groups + apps + application_entities + rds + elasticaches + dynamodbs

        # 3. ZMON entities
        token = None if args.disable_oauth2 else os.getenv('ZMON_AGENT_TOKEN', tokens.get('uid'))
        zmon_client = ZMon(args.entityservice, token=token)

        query = {'infrastructure_account': infrastructure_account, 'region': region, 'created_by': 'agent'}
        entities = zmon_client.get_entities(query)

        # 4. Removing misssing entities
        existing_ids = get_existing_ids(entities)
        current_entities_ids = [e['id'] for e in current_entities]

        to_be_removed = remove_missing_entities(existing_ids, current_entities_ids, zmon_client, json=args.json)

        # 5. Always add Local entity
        if not args.json:
            zmon_client.add_entity(ia_entity)

        # 6. Get new/updated entities
        new_entities = add_new_entities(current_entities, entities, zmon_client, json=args.json)

        logger.info('Found {} new entities from {} entities'.format(len(new_entities), len(current_entities)))

    # Check if it is a dry run!
    if args.json:
        d = {
            'applications': application_entities,
            'apps': apps,
            'dynamodb': dynamodbs,
            'elbs': elbs,
            'elc': elasticaches,
            'rds': rds,
            'new_entities': new_entities,
            'to_be_removed': to_be_removed,
        }

        print(json.dumps(d, indent=4))


if __name__ == '__main__':
    main()
