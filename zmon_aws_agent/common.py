from zmon_aws_agent import __version__


def get_user_agent():
    return 'zmon-aws-agent/{}'.format(__version__)
