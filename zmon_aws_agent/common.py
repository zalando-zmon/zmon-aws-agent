import time
import logging

from botocore.exceptions import ClientError

from zmon_aws_agent import __version__

import opentracing
from opentracing import child_of, follows_from


MAX_RETRIES = 10
TIME_OUT = 0.5

logger = logging.getLogger(__name__)


def get_user_agent():
    return 'zmon-aws-agent/{}'.format(__version__)


def get_sleep_duration(retries):
    return 2 ** retries * TIME_OUT


def call_and_retry(fn, *args, **kwargs):
    """Call `fn` and retry in case of API Throttling exception."""
    count = 0

    while True:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'Throttling' or \
               'RequestLimitExceeded' in str(e):
                if count < MAX_RETRIES:
                    logger.info('Throttling AWS API requests...')
                    time.sleep(get_sleep_duration(count))
                    count += 1
                    continue
            raise


def extract_tracing_span(carrier, use_follows_from=False):
    try:
        span_context = opentracing.tracer.extract(opentracing.Format.TEXT_MAP, carrier)

        references = [follows_from(span_context)] if use_follows_from else [child_of(span_context)]

        return opentracing.tracer.start_span(references=references)
    except Exception:
        return opentracing.tracer.start_span()


def inject_tracing_span(span, carrier):
    opentracing.tracer.inject(span.context, opentracing.Format.TEXT_MAP, carrier)
    return carrier
