import logging
from abc import ABC
from monstr.event.persist import DeleteMode, ARelayEventStoreInterface, RelayEventStoreInterface, \
    ASQLEventStore, SQLEventStore
from monstr.db.db import PostgresDatabase
from monstr.event.event import Event

CREATE_SQL_BATCH = [
    {
        'sql': """
                   create table events( 
                       id SERIAL PRIMARY KEY,  
                       event_id text UNIQUE,  
                       pubkey varchar(128),  
                       created_at int,  
                       kind int,  
                       tags text,  
                       content text,  
                       sig varchar(128),  
                       d_tag text,
                       deleted int)
               """
    },
    {
        'sql': """
                   create table event_tags(
                       id int,  
                       type varchar(32),  
                       value text)
               """
    },
    # create a function that we'll use as trigger when events are deleted
    {
        'sql': """
            CREATE FUNCTION event_tag_delete() RETURNS TRIGGER AS $_$
                BEGIN
                    DELETE FROM event_tags WHERE event_tags.id = OLD.id;
                    RETURN OLD;
                END $_$ LANGUAGE 'plpgsql';
        """
    },
    # now link trigger of event delete with that function
    {
        'sql': """
            CREATE TRIGGER event_delete
                BEFORE DELETE ON events 
                FOR EACH ROW 
                EXECUTE PROCEDURE event_tag_delete();
        """
    }
]


class RelayPostgresEventStore(SQLEventStore, RelayEventStoreInterface, ABC):
    """
        postgres version of event store implementing method required by relay
    """
    def __init__(self,
                 db_name: str,
                 user: str,
                 password: str,
                 is_nip16=True,
                 is_nip33=True,
                 delete_mode=DeleteMode.flag):

        # basic db connection stuff
        self._db_name = db_name
        self._user = user
        self._password = password
        self._db = PostgresDatabase(db_name=db_name,
                                    user=user,
                                    password=password)

        # init underlying store
        SQLEventStore.__init__(self,
                               db=self._db,
                               delete_mode=delete_mode,
                               is_nip16=is_nip16,
                               is_nip33=is_nip33)

        logging.debug(f'RelayPostgresEventStore::__init__ db: {db_name} user: {user}')

    def create(self):
        try:
            import psycopg2
        except:
            raise Exception('RelayPostgresEventStore::destroy missing lib psycopg2')

        # db create needs to be done at postgres db
        c = psycopg2.connect(f'dbname=postgres user={self._user} password={self._password}')
        c.autocommit = True
        cur = c.cursor()
        cur.execute(
            """
                CREATE DATABASE "%s"
                    WITH 
                    OWNER = postgres
                    ENCODING = 'UTF8'
                    LC_COLLATE = 'en_GB.UTF-8'
                    LC_CTYPE = 'en_GB.UTF-8'
                    TABLESPACE = pg_default
                    CONNECTION LIMIT = -1;
            """ % self._db_name
        )

        # now create the tables
        self._db.execute_batch(CREATE_SQL_BATCH)

    def exists(self):
        ret = False
        try:
            self._db.select_sql('select 1')
            ret = True
        except Exception as e:
            pass
        return ret

    def destroy(self):
        try:
            import psycopg2
        except:
            raise Exception('RelayPostgresEventStore::destroy missing lib psycopg2')

        # kill any running tasks, again needs to be at postgres db
        c = psycopg2.connect(f'dbname=postgres user={self._user} password={self._password}')
        c.autocommit = True
        cur = c.cursor()
        cur.execute(
            f"""
            SELECT
            pg_terminate_backend (pg_stat_activity.pid)
            FROM
                pg_stat_activity
            WHERE
            pg_stat_activity.datname = '{self._db_name}';
            """
        )
        cur.execute(f'DROP DATABASE IF EXISTS "{self._db_name}"')
