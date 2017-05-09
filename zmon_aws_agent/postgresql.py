import logging
import psycopg2


logger = logging.getLogger(__name__)

POSTGRESQL_DEFAULT_PORT = 5432


def list_postgres_databases(*args, **kwargs):
    logger.info("Trying to list DBs on host: {}".format(kwargs.get('host')))
    try:
        conn = psycopg2.connect(*args, **kwargs)
        cur = conn.cursor()
        cur.execute("""
            SELECT datname
              FROM pg_database
             WHERE datname NOT IN('postgres', 'template0', 'template1')
        """)
        return [row[0] for row in cur.fetchall()]
    except:
        logger.exception("Failed to list DBs!")
        return []


def get_databases_from_clusters(pgclusters, postgresql_user, postgresql_pass):
    entities = []

    for pg in pgclusters:
        dbnames = list_postgres_databases(host=pg['dnsname'],
                                          port=POSTGRESQL_DEFAULT_PORT,
                                          user=postgresql_user,
                                          password=postgresql_pass,
                                          dbname='postgres',
                                          sslmode='require')
        for db in dbnames:
            entity = {
                'id': '{}-{}'.format(db, pg['id']),
                'type': 'postgresql_database',
                'created_by': 'agent',
                'infrastructure_account': pg['infrastructure_account'],
                'region': pg['region'],

                'postgresql_cluster': pg['id'],
                'database_name': db,
                'shards': {
                    db: '{}:{}/{}'.format(pg['dnsname'], POSTGRESQL_DEFAULT_PORT, db)
                }
            }
            entities.append(entity)

    return entities
