import pytest

from mock import MagicMock, call

from requests.exceptions import HTTPError

from zmon_aws_agent.main import remove_missing_entities, add_new_entities


@pytest.mark.parametrize('json', [True, False])
def test_remove_missing_entities(monkeypatch, json):
    zmon_client = MagicMock()
    zmon_client.delete_entity.return_value = True

    existing_ids = ['1', '2', '3']
    current_ids = ['2', '3']

    to_be_removed_ids, count = remove_missing_entities(existing_ids, current_ids, zmon_client, json=json)

    assert to_be_removed_ids == ['1']
    assert count == 0

    if not json:
        zmon_client.delete_entity.assert_called_with('1')
    else:
        zmon_client.delete_entity.assert_not_called()


@pytest.mark.parametrize('json', [True, False])
def test_add_new_entities(monkeypatch, json):
    zmon_client = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    zmon_client.add_entity.return_value = resp

    existing_ids = ['1', '2', '3']
    current_ids = ['2', '3', '4', '5']

    existing_entities = [{'id': i, 'type': 'e-type'} for i in existing_ids]
    all_current_entities = [{'id': i, 'type': 'e-type'} for i in existing_ids + current_ids]

    new_entities, count = add_new_entities(all_current_entities, existing_entities, zmon_client, json=json)

    expected = [{'id': '4', 'type': 'e-type'}, {'id': '5', 'type': 'e-type'}]

    assert new_entities == expected
    assert count == 0

    calls = [call(e) for e in expected]

    if not json:
        zmon_client.add_entity.assert_has_calls(calls, any_order=True)
    else:
        zmon_client.add_entity.assert_not_called()


def test_add_new_entities_exception(monkeypatch):
    zmon_client = MagicMock()
    zmon_client.add_entity.side_effect = HTTPError

    exception = MagicMock()
    monkeypatch.setattr('zmon_aws_agent.main.logger.exception', exception)

    existing_ids = ['1', '2', '3']
    current_ids = ['2', '3', '4', '5']

    existing_entities = [{'id': i, 'type': 'e-type'} for i in existing_ids]
    all_current_entities = [{'id': i, 'type': 'e-type'} for i in existing_ids + current_ids]

    new_entities, count = add_new_entities(all_current_entities, existing_entities, zmon_client)

    expected = [{'id': '4', 'type': 'e-type'}, {'id': '5', 'type': 'e-type'}]
    assert new_entities == expected
    assert count == 2

    exception.assert_called()


def test_remove_missing_entities_exception(monkeypatch):
    zmon_client = MagicMock()
    zmon_client.delete_entity.side_effect = HTTPError

    exception = MagicMock()
    monkeypatch.setattr('zmon_aws_agent.main.logger.exception', exception)

    existing_ids = ['1', '2', '3']
    current_ids = ['2', '3']

    to_be_removed_ids, count = remove_missing_entities(existing_ids, current_ids, zmon_client)

    assert to_be_removed_ids == ['1']
    assert count == 1

    exception.assert_called()
