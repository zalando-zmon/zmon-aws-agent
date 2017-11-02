import logging
import psycopg2

# better move that one to common?
from .aws import entity_id


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
    except Exception:
        logger.exception("Failed to list DBs!")
        return []


def get_databases_from_clusters(pgclusters, infrastructure_account, region,
                                postgresql_user, postgresql_pass):
    entities = []

    try:
        for pg in pgclusters:
            dnsname = pg['dnsname']
            dbnames = list_postgres_databases(host=dnsname,
                                              port=POSTGRESQL_DEFAULT_PORT,
                                              user=postgresql_user,
                                              password=postgresql_pass,
                                              dbname='postgres',
                                              sslmode='require')
            for db in dbnames:
                entity = {
                    'id': entity_id('{}-{}[{}:{}]'.format(db, dnsname, infrastructure_account, region)),
                    'type': 'postgresql_database',
                    'created_by': 'agent',
                    'infrastructure_account': infrastructure_account,
                    'region': region,

                    'postgresql_cluster': pg['id'],
                    'database_name': db,
                    'shards': {
                        db: '{}:{}/{}'.format(dnsname, POSTGRESQL_DEFAULT_PORT, db)
                    }
                }
                entities.append(entity)
    except Exception:
        logger.exception("Failed to make Database entities for PostgreSQL clusters!")

    return entities
