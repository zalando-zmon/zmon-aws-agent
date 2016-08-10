import time
import logging

from botocore.exceptions import ClientError

from zmon_aws_agent import __version__


MAX_RETRIES = 10

logger = logging.getLogger(__name__)


def get_user_agent():
    return 'zmon-aws-agent/{}'.format(__version__)


def get_sleep_duration(retries):
    return 2 ** retries * 0.5


def call_and_retry(fn, *args, **kwargs):
    """Call `fn` and retry in case of API Throttling exception."""
    count = 0

    while True:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'Throttling':
                if count < MAX_RETRIES:
                    logger.info('Throttling AWS API requests...')
                    time.sleep(get_sleep_duration(count))
                    count += 1
                    continue
            raise
