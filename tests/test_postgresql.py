from mock import MagicMock

import zmon_aws_agent.postgresql as postgresql


def test_get_databases_from_clusters():
    pgclusters = [
        {
            'id': 'test-1',
            'dnsname': 'test-1.db.zalan.do'
        }
    ]
    acc = 'aws:1234567890'
    region = 'eu-xxx-1'

    postgresql.list_postgres_databases = MagicMock()
    postgresql.list_postgres_databases.return_value = ['db1', 'db2']

    databases = postgresql.get_databases_from_clusters(pgclusters, acc, region,
                                                       'pguser', 'pgpass')
    assert databases == [
        {
            'id': 'db1-test-1.db.zalan.do[aws:1234567890:eu-xxx-1]',
            'type': 'postgresql_database',
            'created_by': 'agent',
            'infrastructure_account': acc,
            'region': region,
            'postgresql_cluster': 'test-1',
            'database_name': 'db1',
            'shards': {
                'db1': 'test-1.db.zalan.do:5432/db1'
            }
        },
        {
            'id': 'db2-test-1.db.zalan.do[aws:1234567890:eu-xxx-1]',
            'type': 'postgresql_database',
            'created_by': 'agent',
            'infrastructure_account': acc,
            'region': region,
            'postgresql_cluster': 'test-1',
            'database_name': 'db2',
            'shards': {
                'db2': 'test-1.db.zalan.do:5432/db2'
            }
        }
    ]
