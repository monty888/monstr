"""
    database access for sqllite and postgres
    postges not fully implmented or tested very well

"""

import logging
from abc import abstractmethod, ABC
from asyncio.locks import Lock
try:
    import sqlite3
except Exception as e:
    sqlite3 = None

try:
    import aiosqlite
except Exception as e:
    aiosqlite = None

try:
    import psycopg2
except:
    psycopg2 = None

# probably get rid of are use of Dataset and replace with whatever name/col style we can get from the db
# eventually
from monstr.data.data import DataSet


class Database:

    @abstractmethod
    def execute_sql(self, sql, args=None):
        """
            execute some SQL, currently we'll just fall over on
            errors
        """

    @abstractmethod
    def executemany_sql(self, sql, args=None):
        """
            execute some SQL, returns True/False on success if catch_err is False
            then errors will raise an exception
        """

    @abstractmethod
    def execute_batch(self, batch):
        """
        :param batch: array of {
            'sql' : str,
            'args' : [] optional
        }
        :return: True on success
        """

    @abstractmethod
    def select_sql(self, sql, args=None) -> DataSet:
        """
        excutes query against database con
        :param sql: query str
        :param args: query args
        :return: results as DataSet
        """

    @property
    def placeholder(self):
        pass


class ADatabase:

    @abstractmethod
    async def execute_sql(self, sql, args=None):
        """
            execute some SQL, currently we'll just fall over on
            errors
        """

    @abstractmethod
    async def executemany_sql(self, sql, args=None):
        """
            execute some SQL, returns True/False on success if catch_err is False
            then errors will raise an exception
        """

    @abstractmethod
    async def execute_batch(self, batch):
        """
        :param batch: array of {
            'sql' : str,
            'args' : [] optional
        }
        :return: True on success
        """

    @abstractmethod
    async def select_sql(self, sql, args=None) -> DataSet:
        """
        excutes query against database con
        :param sql: query str
        :param args: query args
        :return: results as DataSet
        """

    @property
    def placeholder(self):
        pass


class SQLiteDatabase(Database, ABC):
    """
        blocking access to sqlite server
    """
    def __init__(self, f_name):
        if sqlite3 is None:
            raise Exception('SQLiteDatabase:: sqlite lib is missing?!')

        self._f_name = f_name

    @property
    def file(self):
        return self._f_name

    def execute_sql(self, sql, args=None):
        if args is None:
            args = []

        with sqlite3.connect(self._f_name) as c:
            logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                          args))

            # if [[]] then use executemany, same sql with mutiple data
            if args and isinstance(args[0], list):
                c.executemany(sql, args)
            else:
                c.execute(sql, args)

            c.commit()

    def executemany_sql(self, sql, args=None):
        raise Exception('add back in when we use!!!!')
        # """
        #     execute some SQL, returns True/False on success if catch_err is False
        #     then errors will raise an exception
        # """
        # ret = False
        # if args is None:
        #     args = []
        #
        # # e only local
        # was_err = None
        # with self._lock:
        #     try:
        #         c = self._get_con()
        #         c.executemany(sql,args)
        #         c.commit()
        #         ret = True
        #     except Error as e:
        #         logging.debug('Database::executemany_sql error %s' % e)
        #         was_err = e
        #     finally:
        #         if c:
        #             c.close()
        #
        # if not catch_err and was_err:
        #     raise was_err

        #return ret

    def execute_batch(self, batch):
        """
        :param batch: array of {
            'sql' : str,
            'args' : [] optional
        }
        :return: True on success
        """
        with sqlite3.connect(self._f_name) as c:
            curs = c.cursor()
            curs.execute('begin')
            for c_cmd in batch:
                args = []
                sql = c_cmd['sql']
                if 'args' in c_cmd:
                    args = c_cmd['args']
                logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                              args))
                # as execute_sql - if [[]] then use executemany, same sql with mutiple data
                if args and isinstance(args[0], list):
                    curs.executemany(sql, args)
                else:
                    curs.execute(sql, args)

            c.commit()
            curs.close()
        logging.debug('Database::execute_batch commit done')

    def select_sql(self, sql, args=None) -> DataSet:
        """
        excutes query against database con
        :param sql: query str
        :param args: query args
        :return: results as DataSet
        """
        logging.debug('Database::select_sql - SQL: %s \n ARGS: %s' % (sql,args))

        if args is None:
            args = []

        with sqlite3.connect(self._f_name) as c:
            rs = c.execute(sql, args)
            # extract the heads
            heads = []
            for c_h in rs.description:
                # col name in 0 the rest are always None and contain no useful info for us
                heads.append(c_h[0])

            # now extract the data
            data = []
            for c_r in rs:
                # we change to [] as there are some places where being a turple will be a problem
                data.append(list(c_r))

        # now return as a dataset
        return DataSet(heads, data)

    def _insert_tbl(self, t_name, data: DataSet):
        # nothing to insert
        if not data:
            return
        sql = 'insert into %s ' % t_name
        pcount = ['?'] * len(data.Heads)
        fields = '(%s) values (%s)' % (','.join(data.Heads),
                                       ','.join(pcount))

        self.execute_sql(sql+fields,data.Data)

    @property
    def placeholder(self):
        return '?'


class ASQLiteDatabase(ADatabase, ABC):
    """
        sqlite via async access
    """
    def __init__(self, f_name):
        if aiosqlite is None:
            raise Exception('SQLiteDatabase:: aiosqlite lib is missing?!')

        self._f_name = f_name
        # as SQLite locks the entire db at some point during any update we try and manage writes
        # so we block ourself and make it less likely to get db locked error...
        # of course if another instance is being used or another python the db could still end up locked and we'd fail
        # :(. We only put the locks around writes, reads will leave to fail for the caller to deal with...
        self._lock = Lock()

    @property
    def file(self):
        return self._f_name

    async def execute_sql(self, sql, args=None):
        if args is None:
            args = []

        async with self._lock:
            async with aiosqlite.connect(self._f_name) as c:
                logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                              args))

                # if [[]] then use executemany, same sql with mutiple data
                if args and isinstance(args[0], list):
                    await c.executemany(sql, args)
                else:
                    await c.execute(sql, args)

                await c.commit()

    async def executemany_sql(self, sql, args=None):
        raise Exception('add back in when we use!!!!')
        # """
        #     execute some SQL, returns True/False on success if catch_err is False
        #     then errors will raise an exception
        # """
        # ret = False
        # if args is None:
        #     args = []
        #
        # # e only local
        # was_err = None
        # with self._lock:
        #     try:
        #         c = self._get_con()
        #         c.executemany(sql,args)
        #         c.commit()
        #         ret = True
        #     except Error as e:
        #         logging.debug('Database::executemany_sql error %s' % e)
        #         was_err = e
        #     finally:
        #         if c:
        #             c.close()
        #
        # if not catch_err and was_err:
        #     raise was_err

        # return ret

    async def execute_batch(self, batch):
        """
        :param batch: array of {
            'sql' : str,
            'args' : [] optional
        }
        :return: True on success
        """
        async with self._lock:
            async with aiosqlite.connect(self._f_name) as c:
                curs = await c.cursor()
                await curs.execute('begin')
                try:
                    for c_cmd in batch:
                        args = []
                        sql = c_cmd['sql']
                        if 'args' in c_cmd:
                            args = c_cmd['args']
                        logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                                      args))
                        # as execute_sql - if [[]] then use executemany, same sql with mutiple data
                        if args and isinstance(args[0], list):
                            await curs.executemany(sql, args)
                        else:
                            await curs.execute(sql, args)
                    await c.commit()
                    await curs.close()
                except Exception as e:
                    print(e)
                    try:
                        await c.rollback()
                    except Exception as ee:
                        pass

            logging.debug('Database::execute_batch commit done')

    async def select_sql(self, sql, args=None) -> DataSet:
        """
        excutes query against database con
        :param sql: query str
        :param args: query args
        :return: results as DataSet
        """
        logging.debug('Database::select_sql - SQL: %s \n ARGS: %s' % (sql,args))

        if args is None:
            args = []

        async with aiosqlite.connect(self._f_name) as c:
            rs = await c.execute(sql, args)

            # extract the heads
            heads = []
            for c_h in rs.description:
                # col name in 0 the rest are always None and contain no useful info for us
                heads.append(c_h[0])

            # now extract the data
            data = []
            async for c_r in rs:
                # we change to [] as there are some places where being a turple will be a problem
                data.append(list(c_r))

        # now return as a dataset
        return DataSet(heads, data)

    def _insert_tbl(self, t_name, data: DataSet):
        # nothing to insert
        if not data:
            return
        sql = 'insert into %s ' % t_name
        pcount = ['?'] * len(data.Heads)
        fields = '(%s) values (%s)' % (','.join(data.Heads),
                                       ','.join(pcount))

        self.execute_sql(sql+fields,data.Data)

    @property
    def placeholder(self):
        return '?'


class PostgresDatabase(Database, ABC):
    """
        Same for Postgres using psycopg2
        unfortunetly  psycopg2 and sqlite3 cons so for now have just re-implemented the same methods


    """
    def __init__(self, db_name, user, password):
        self._name = db_name
        self._user = user
        self._password = password

    def _get_con(self):
        return psycopg2.connect("dbname=%s user=%s password=%s" % (self._name,
                                                                   self._user,
                                                                   self._password))

    def execute_sql(self, sql, args=None):
        with self._get_con() as c:
            with c.cursor() as cur:
                logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                              args))
                cur.execute(sql, args)
                c.commit()

    def executemany_sql(self, sql, args=None):
        raise Exception('not implemented!')

    def execute_batch(self, batch):
        with self._get_con() as c:
            with c.cursor() as cur:
                for c_cmd in batch:
                    args = []
                    sql = c_cmd['sql']
                    if 'args' in c_cmd:
                        args = c_cmd['args']
                    logging.debug('Database::execute_batch SQL: %s\n ARGS: %s' % (sql,
                                                                                  args))
                    cur.execute(sql, args)

                c.commit()

    def select_sql(self, sql, args=None) -> DataSet:
        with self._get_con() as c:
            with c.cursor() as cur:
                cur.execute(sql, args)
                # get heads
                heads = [h.name for h in cur.description]

                # and data
                rows = cur.fetchall()
                data = []
                for c_r in rows:
                    data.append(list(c_r))

        return DataSet(heads, data)

    @property
    def placeholder(self):
        return '%s'


class QueryFromFilter:
    OR_JOIN = 'OR'
    AND_JOIN = 'AND'

    def __init__(self, select_sql:str, filter={}, placeholder='?', alias={}, def_join='OR'):
        self._sql_base = select_sql
        self._filter = filter
        if isinstance(self._filter,dict):
            self._filter = [self._filter]
        self._placeholder = placeholder
        self._alias = alias
        self._join = ' where '
        if ' where ' in select_sql:
            self._join = ' or '

        self._def_join = def_join


    def _construct(self):

        sql_arr = [self._sql_base]
        args = []

        def _add_filter(c_filter):
            opened = False
            for k in c_filter:
                if not opened:
                    sql_arr.append(self._join)
                    sql_arr.append(' (')
                    opened = True
                _add_for_field(c_filter, k)

            if opened:
                sql_arr.append(') ')
                self._join = self._def_join

        def _add_for_field(c_filter, f_name):
            nonlocal args

            values = c_filter[f_name]
            db_field = f_name
            if f_name in self._alias:
                db_field = self._alias[db_field]

            if not hasattr(values, '__iter__') or isinstance(values, str):
                values = [values]

            sql_arr.append(
                ' %s in (%s) ' % (db_field,
                                     ','.join([self._placeholder] * len(values)))
            )

            args = args + values

        for f in self._filter:
            if isinstance(f, dict):
                _add_filter(f)
            if isinstance(f, str):
                self._join = ' %s ' % f

        return {
            'sql': ''.join(sql_arr),
            'args': args,
            'join': self._join
        }

    def get_query(self):
        return self._construct()







