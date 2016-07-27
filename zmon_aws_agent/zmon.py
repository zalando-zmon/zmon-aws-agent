import os
import json
import logging

import requests

from zmon_aws_agent.common import get_user_agent

logger = logging.getLogger(__name__)


class ZMon(object):
    def __init__(self, url, token=None, username=None, password=None, debug=False, timeout=10, verify=True):
        # Ensure trailing slash!
        self.url = os.path.join(url, '')
        self.timeout = timeout

        self._session = requests.Session()

        if username and password and token is None:
            self._session.auth = (username, password)

        self._session.headers.update({'User-Agent': get_user_agent(), 'Content-Type': 'application/json'})

        if token:
            self._session.headers.update({'Authorization': 'Bearer {}'.format(token)})

        if not verify:
            logger.warning('ZMON client will skip SSL verification!')
            self._session.verify = False

        if debug:
            logger.setLevel(logging.DEBUG)

    @property
    def session(self):
        return self._session

    def entity_url(self, entity_id):
        # Ensure a trailing slash exists.
        return os.path.join(self.url, entity_id, '')

    def get_entities(self, query=None):
        try:
            query_str = json.dumps(query) if query else ''
            logger.debug('Retrieving entities with query: {} ...'.format(query_str))

            params = {'query': query_str} if query else None

            resp = self.session.get(self.url, params=params, timeout=self.timeout)
            resp.raise_for_status()

            return resp.json()
        except:
            logger.error('Failed to retrieve entities from {}'.format(self.url))
            raise

    def add_entity(self, entity):
        """
        Create or update entity on ZMON.

        ZMON PUT entity API doesn't return JSON response.

        :return: Response object.
        """
        try:
            logger.debug('Adding new enitity: {} ...'.format(entity['id']))

            resp = self.session.put(self.url, json=entity)
            resp.raise_for_status()

            return resp
        except:
            logger.error('Failed to add entity {}'.format(entity['id']))
            raise

    def delete_entity(self, entity_id):
        """
        Delete entity from ZMON.

        ZMON DELETE entity API doesn't return JSON response.

        :return: True if succeeded, False otherwise.
        :rtype: bool
        """
        try:
            logger.debug('Removing existing enitity: {} ...'.format(entity_id))

            resp = self.session.delete(self.entity_url(entity_id))
            resp.raise_for_status()

            return resp.text == '1'
        except:
            logger.error('Failed to add entity {}'.format(entity_id))
            raise
