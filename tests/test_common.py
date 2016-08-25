import pytest

from mock import MagicMock

from zmon_aws_agent import __version__
from zmon_aws_agent.common import get_user_agent, call_and_retry

from conftest import ThrottleError


# Speed up tests.
MAX_RETRIES = 5


def test_common_user_agent(monkeypatch):
    agent = get_user_agent()

    assert 'zmon-aws-agent/{}'.format(__version__) == agent


@pytest.mark.parametrize(
    'rets,expected',
    [
        ([ThrottleError, '1'], '1'),
        ([ThrottleError()] * MAX_RETRIES + ['1'], '1'),
        ([ThrottleError()] * (MAX_RETRIES + 1), ThrottleError),
        ([ThrottleError(throttling=False)], ThrottleError),
        ([RuntimeError], RuntimeError),
    ]
)
def test_common_call_and_retry(monkeypatch, rets, expected):
    f = MagicMock()
    f.side_effect = rets

    monkeypatch.setattr('zmon_aws_agent.common.MAX_RETRIES', MAX_RETRIES)
    monkeypatch.setattr('zmon_aws_agent.common.TIME_OUT', 0.01)

    fail = True
    if type(expected) is str:
        fail = False

    args = [1, 2, '3']
    kwargs = {'k': 'value'}

    if fail:
        with pytest.raises(expected):
            call_and_retry(f, *args, **kwargs)
    else:
        res = call_and_retry(f, *args, **kwargs)

        assert res == expected

    f.assert_called_with(*args, **kwargs)
