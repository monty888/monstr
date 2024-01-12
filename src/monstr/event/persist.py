from abc import ABC, abstractmethod
from enum import Enum
from monstr.event.event import Event
from monstr.db.db import ADatabase, Database, ASQLiteDatabase, SQLiteDatabase, PostgresDatabase
from monstr.data.data import DataSet
from monstr.util import util_funcs, NIPSupport
"""
    Interfaces for storing events, actual implementations now split into persist_<store_type>.py files
"""

class DeleteMode(Enum):
    # action taken on recieveing a delete event

    # delete any events we can from db - note that once deleted there is no check that it's not reposted, which
    # anyone would be able to do... not just the creator.
    delete = 1
    # mark as deleted any events from db - to client this would look exactly same as DEL_DELETE
    flag = 2
    # nothing, ref events will still be returned to clients
    no_action = 3


class StoreNIPSupport(NIPSupport):
    """
        Nip support modified with the nips that are relevant to how we're storing
    """
    def __init__(self,
                 delete_mode=DeleteMode.no_action,
                 nip16: bool = False,
                 nip33: bool = False):

        self._delete_mode = delete_mode
        super().__init__(
            nip09=delete_mode != DeleteMode.no_action,
            nip16=nip16,
            nip33=nip33
        )

    @property
    def delete_mode(self):
        return self._delete_mode

    def is_replaceable(self, evt: Event) -> bool:
        return evt.is_replacable() and self.NIP16

    def is_ephemeral(self, evt: Event) -> bool:
        return evt.is_ephemeral() and self.NIP16

    def is_parameter_replaceable(self, evt: Event) -> bool:
        return evt.is_parameter_replacable() and self.NIP33


class SortDirection(Enum):
    natural = 1
    newest_first = 2
    oldest_first = 3


def clean_relay_names(relay_names: [str]) ->[str]:

    def _do_clean(r_name: str):
        ret = None
        r_name = r_name.lower().lstrip()
        if (r_name.startswith('wss://') or r_name.startswith('ws://')) \
                and 'localhost' not in r_name:
            ret = r_name

        return ret

    ret = []
    for c_r in relay_names:
        name = _do_clean(c_r)
        if name is not None:
            ret.append(name)
    return ret


class GenericSQL:
    """
        common sql - this should work across dbs
    """
    @staticmethod
    def make_sql_filter(filters,
                        placeholder='?',
                        custom=None,
                        sort_direction=SortDirection.natural):
        """
        creates the sql to select events from a db given monstr filter
        :param filter:
        :return:
        """

        def _add_range(sql: str, limit=None, offset=None):
            if limit is not None:
                sql += ' limit %s' % limit
            if offset is not None:
                sql += ' offset %s' % offset

            return sql

        def _add_sort(sql: str, sort_direction, col_name=None):
            # nothing to do
            if sort_direction == SortDirection.natural:
                return sql

            if col_name is None:
                col_name = 'created_at'

            if sort_direction.newest_first:
                sql += ' order by %s desc' % col_name
            else:
                sql += ' order by %s' % col_name
            return sql

        def for_single_filter(filter):
            def _do_tags(tag_type):
                nonlocal args
                t_filter = filter['#' + tag_type]
                if not isinstance(t_filter, list):
                    t_filter = [str(t_filter)]
                e_sql = """
                   %s id in 
                       (
                           select id from event_tags where type = '%s' and value in(%s)
                       )
                                   """ % (join,
                                          tag_type,
                                          ','.join([placeholder] * len(t_filter)))
                sql_arr.append(e_sql)
                args = args + t_filter

            # deleted isnull to filter deleted if in flag delete mode
            sql_arr = ["""
                   select 
                       e.event_id as id,
                       e.pubkey, 
                       e.created_at,
                       e.kind,
                       e.tags,
                       e.content,
                       e.sig
                   from events e where deleted isnull
               """]
            # join not really required anymore because its always and
            join = 'and'
            args = []
            if 'since' in filter:
                sql_arr.append(' %s created_at>=%s' % (join, placeholder))
                args.append(filter['since'])
            if 'until' in filter:
                sql_arr.append(' %s created_at<=%s' % (join, placeholder))
                args.append(filter['until'])
            # FIXME - if field exits e.g kinds, authors but is empty [] then we ignore
            #  possible we should error the query instead, and then don't run query and return nothing?
            if 'kinds' in filter:
                kind_arr = filter['kinds']
                if kind_arr:
                    if not hasattr(kind_arr, '__iter__') or isinstance(kind_arr, str):
                        kind_arr = [kind_arr]
                    arg_str = ','.join([placeholder] * len(kind_arr))
                    sql_arr.append(' %s kind in(%s)' % (join, arg_str))
                    args = args + kind_arr
            if 'authors' in filter:
                # do_authors()
                auth_arr = filter['authors']
                if auth_arr:
                    if not hasattr(auth_arr, '__iter__') or isinstance(auth_arr, str):
                        auth_arr = [auth_arr]

                    arg_str = 'or '.join(['pubkey like ' + placeholder] * len(auth_arr))
                    sql_arr.append(' %s (%s)' % (join, arg_str))
                    for c_arg in auth_arr:
                        args.append(c_arg + '%')

            if 'ids' in filter:
                ids_arr = filter['ids']
                if ids_arr:
                    if not hasattr(ids_arr, '__iter__') or isinstance(ids_arr, str):
                        ids_arr = [ids_arr]

                    arg_str = ' or '.join(['event_id like ' + placeholder] * len(ids_arr))
                    sql_arr.append(' %s (%s)' % (join, arg_str))
                    for c_arg in ids_arr:
                        args.append(c_arg + '%')

            # generic tags start with #, also included here are p and e tags as they're done in same way
            for c_name in filter:
                # its an event tag
                if c_name[0] == '#':
                    _do_tags(c_name[1:])
                    join = 'and'

            if custom is not None:
                # where custom queries are of the form select id from
                # only for non standard query additions, currently content by the client
                # if something standard ever replaces should be moved into the make construction here
                # assuming it can be done in a non db specifc way...
                custom_queries = custom(filter, join)
                for c_cust_q in custom_queries:
                    sql_arr.append(c_cust_q['sql'])
                    args.append(c_cust_q['args'])

            return {
                'sql': ''.join(sql_arr),
                'args': args
            }

        # only been passed a single, put into list
        if isinstance(filters, dict):
            filters = [filters]

        sql = ''
        args = []
        # added support for filter limit and result now sorted by given create_at date
        # only the largest limit is taken where there is a limit on more than one filter
        limit = None
        # added support for offset, only the first offset found is used
        offset = None

        for c_filter in filters:
            q = for_single_filter(c_filter)
            if sql:
                sql += ' union '
            sql = sql + q['sql']
            args = args + q['args']
            if 'limit' in c_filter:
                if limit is None or c_filter['limit'] > limit:
                    limit = c_filter['limit']
            if offset is None and 'offset' in c_filter:
                offset = c_filter['offset']

        sql = _add_sort(sql, sort_direction)
        sql = _add_range(sql, limit, offset)

        return {
            'sql': sql,
            'args': args
        }

    @staticmethod
    def get_delete_batch(store, evt: Event, batch=None):
        if batch is None:
            batch = []

        if store.delete_mode == DeleteMode.no_action or evt.kind != evt.KIND_DELETE:
            return batch

        to_delete = evt.e_tags

        # only flag as deleted
        if store.delete_mode == DeleteMode.flag:
            batch.append({
                'sql': 'update events set deleted=true where event_id in (%s) and kind<>?' %
                       ','.join(['?'] * len(to_delete)),
                'args': to_delete + [Event.KIND_DELETE]

            })
        # actually delete
        elif store.delete_mode == DeleteMode.delete:
            batch = [
                {
                    'sql': 'delete from events where event_id in (%s) and kind<>?' % ','.join(['?'] * len(to_delete)),
                    'args': to_delete + [Event.KIND_DELETE]
                }
            ]

        return batch

    @staticmethod
    def get_add_batch(the_store, evts: [Event], batch_size, db_placeholder):

        def _do_update(evt: Event):
            """
            go ahead and put this event into the db?
            only ephemeral backs out as we let the db deal with the rest i.e. ignore if it already exists
            """
            ret = True
            if the_store.is_ephemeral(evt):
                return False
            return ret

        def _prepare_replacements(evt: Event):
            """
                adds a delete of any but the most recent for NIP16, NIP33 if required
                note this is done after we added, in case what we added is not the topmost event it gets deleted
                straigh away!
            """

            # nip16, basic event treament
            if the_store.is_replaceable(evt):
                batch.append({
                    'sql': f"""
                            delete from events where id in(
                                select id from events where kind={db_placeholder} and pubkey={db_placeholder} and id not in(
                                    select id from events where kind={db_placeholder} and pubkey={db_placeholder} 
                                    order by created_at desc limit 1
                                )
                            );
                            """,
                    'args': [
                        evt.kind, evt.pub_key,
                        evt.kind, evt.pub_key
                    ]
                })
            elif the_store.is_parameter_replaceable(evt):
                d_tag = evt.get_tag_value_pos('d', default='')
                batch.append({
                    'sql': f"""
                            delete from events where id in(
                                select id from events 
                                    where kind={db_placeholder} and 
                                            pubkey={db_placeholder} and 
                                            d_tag={db_placeholder} 
                                        and id not in(
                                            select id from events 
                                                where kind={db_placeholder} and 
                                                pubkey={db_placeholder} and 
                                                d_tag = {db_placeholder}
                                            order by created_at desc limit 1
                                        )
                            );
                            """,
                    'args': [
                        evt.kind, evt.pub_key, d_tag,
                        evt.kind, evt.pub_key, d_tag
                    ]
                })



        def _prepare_add_event_batch(evt: Event):
            add_sql = f"""
                insert into events(event_id, pubkey, created_at, kind, tags, content,sig, d_tag)
                values(
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder},
                    {db_placeholder}
                )
            """

            # for NIP33 para replacements, we add d_tag at top level even if not in nip33 mode
            d_tag = evt.get_tag_value_pos('d', default='')

            batch.append({
                'sql': add_sql,
                'args': [
                    evt.id, evt.pub_key, evt.created_at_ticks,
                    evt.kind, str(evt.tags), evt.content, evt.sig,
                    d_tag
                ]
            })

            # currently we only put in the tags table the bits needed to suport query [2:] could go in an extra field
            # but as we already have the full info in events tbl probably don't need
            for c_tag in evt.tags:
                if len(c_tag) >= 2:
                    tag_type = c_tag[0]
                    tag_value = c_tag[1]

                    # hashtag became t, se we can get all on same query we'll change the type in event_tags
                    # what we store in event tbl stays as we received so can still be validated
                    if tag_type.lower() == 'hashtag':
                        tag_type = 't'

                    batch.append({
                        # 'sql': 'insert into event_tags SELECT last_insert_rowid(),?,?',
                        'sql': """
                                                    insert into event_tags values (
                                                    (select id from events where event_id=%s),
                                                    %s,
                                                    %s)
                                                """.replace('%s', db_placeholder),
                        'args': [evt.id, tag_type, tag_value]
                    })

            # add any required sql for replacable events
            _prepare_replacements(evt)

            if evt.kind == Event.KIND_DELETE:
                GenericSQL.get_delete_batch(store=the_store,
                                            evt=evt,
                                            batch=batch)

        # make sure []
        if not hasattr(evts, '__iter__'):
            evts = [evts]

        for c_chunk in util_funcs.chunk(evts, batch_size):
            batch = []
            for c_evt in c_chunk:
                if _do_update(c_evt):
                    _prepare_add_event_batch(c_evt)
            yield batch


class EventStoreInterface(ABC, StoreNIPSupport):

    @abstractmethod
    def add_event(self, evt: Event):
        """
        add given event to store should throw NostrCommandException if can't for some reason
        e.g. duplicate event, already newer contact/meta, or db insert err etc.

        :param evt: monstr.Event
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    def do_delete(self, evt: Event):
        """
        :param evt: the delete event
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    def get_filter(self, filter) -> [{}]:
        """
        :param filter: [{filter}...] monstr filter
        :return: all evts in store that passed the filter
        """

class RelayEventStoreInterface(EventStoreInterface):
    """
        extra methods added specifically for a relay -
        is_NIP09 moved to EventStoreInterface so nothing anymore...
    """


class ClientEventStoreInterface(EventStoreInterface):
    """
        extra methods added specifically for a client
    """
    @abstractmethod
    def add_event_relay(self, evt: Event, relay_url: str):
        """
        clients can recieve the same event from multiple souces so the store has an extra tbl that tracks that
        if you just call add_event no info on whre the event came from will be stored

        :param evt: monstr.Event
        :param relay_url:
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    def get_newest(self, for_relay, filter):
        """
        return ticks of the newest event we have for given relay for use in since filter
        filter is just a single monstr filter {}
        currently we're only the kind filter is used

        :param for_relay:
        :return:
        """

    @abstractmethod
    def get_oldest(self, for_relay, filter):
        """
        return ticks of the oldest event we have for given relay for use in since filter
        filter is just a single monstr filter {}
        currently we're only the kind filter is used

        :param for_relay:
        :return:
        """

    @abstractmethod
    def event_relay(self, event_id: str) -> [str]:
        """
        :param event_id: monstr event_id
        :return: [str] relay_urls
        """

    @abstractmethod
    def direct_messages(self, pub_k: str) -> DataSet:
        """
        :param pub_k:
        :return:  DataSet containing event_id, pub_k, created_at of direct messages for this user
        order newest to oldest, one row per pub_k messaging the event_id, created_at is for the newest record we have
        """

    @abstractmethod
    def relay_list(self, pub_k: str = None) -> []:
        """
        :param pub_k: if given relays surgested by contacts for this pub_k will be listed first
        :return: [relay_urls]
        """


class AEventStoreInterface(ABC, StoreNIPSupport):
    """
        async version of EventStoreInterface - Note as we've used the same method names rather
        than say add_event -> aadd_event the same class can't implement both interfaces
        in places where you might use either you'll probably need to do an instance check on the obj you get

        e.g. in event_handler do_event -

        if isinstance(self._store, AEventStoreInterface):
            await self._store.add_event(evt)
        else:
            self._store.add_event(evt)
    """
    @abstractmethod
    async def add_event(self, evt: Event):
        """
        add given event to store should throw NostrCommandException if can't for some reason
        e.g. duplicate event, already newer contact/meta, or db insert err etc.

        :param evt: monstr.Event
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    async def do_delete(self, evt: Event):
        """
        :param evt: the delete event
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    async def get_filter(self, filter) -> [{}]:
        """
        :param filter: [{filter}...] monstr filter
        :return: all evts in store that passed the filter
        """


class ARelayEventStoreInterface(AEventStoreInterface):
    """
        no addtional methods for the same reason as RelayEventStoreInterface doesn't have any
    """


class AClientEventStoreInterface(AEventStoreInterface):
    """
        extra methods added specifically for a client
    """
    @abstractmethod
    async def add_event_relay(self, evt: Event, relay_url: str):
        """
        clients can recieve the same event from multiple souces so the store has an extra tbl that tracks that
        if you just call add_event no info on whre the event came from will be stored

        :param evt: monstr.Event
        :param relay_url:
        :return: None, as long as it returns it should have been success else it should throw
        """

    @abstractmethod
    async def get_newest(self, for_relay, filter):
        """
        return ticks of the newest event we have for given relay for use in since filter
        filter is just a single monstr filter {}
        currently we're only the kind filter is used

        :param for_relay:
        :return:
        """

    @abstractmethod
    async def get_oldest(self, for_relay, filter):
        """
        return ticks of the oldest event we have for given relay for use in since filter
        filter is just a single monstr filter {}
        currently we're only the kind filter is used

        :param for_relay:
        :return:
        """

    @abstractmethod
    async def event_relay(self, event_id: str) -> [str]:
        """
        :param event_id: monstr event_id
        :return: [str] relay_urls
        """

    @abstractmethod
    async def direct_messages(self, pub_k: str) -> DataSet:
        """
        :param pub_k:
        :return:  DataSet containing event_id, pub_k, created_at of direct messages for this user
        order newest to oldest, one row per pub_k messaging the event_id, created_at is for the newest record we have
        """

    @abstractmethod
    async def relay_list(self, pub_k: str = None) -> []:
        """
        :param pub_k: if given relays surgested by contacts for this pub_k will be listed first
        :return: [relay_urls]
        """


class SQLEventStore(EventStoreInterface, StoreNIPSupport):
    """
        sync sql event store
    """
    def __init__(self,
                 db: Database,
                 delete_mode=DeleteMode.flag,
                 is_nip16=True,
                 is_nip33=True,
                 sort_direction=SortDirection.newest_first,
                 batch_size=500):

        StoreNIPSupport.__init__(self,
                                 delete_mode=delete_mode,
                                 nip16=is_nip16,
                                 nip33=is_nip33)

        self._sort_direction = sort_direction
        self._db = db
        self._batch_size = batch_size

    def add_event(self, evt: Event):
        for c_batch in GenericSQL.get_add_batch(the_store=self,
                                                evts=evt,
                                                batch_size=self._batch_size,
                                                db_placeholder=self._db.placeholder):
            self._db.execute_batch(c_batch)

    def get_filter(self, filter, custom=None, sort_direction=None) -> [{}]:
        """
        from database returns events that match filter/s
        doesn't do #e and #p filters yet (maybe never)
        also author and ids are currently exact only, doesn't support prefix
        :param filter: {} or [{},...] or filters
        :return:
        """
        if sort_direction is None:
            sort_direction = self._sort_direction

        filter_query = GenericSQL.make_sql_filter(filter,
                                                  placeholder=self._db.placeholder,
                                                  custom=custom,
                                                  sort_direction=sort_direction)

        # print(filter_query['sql'], filter_query['args'])

        data = self._db.select_sql(sql=filter_query['sql'],
                                   args=filter_query['args'])

        return data.as_arr(True)

    def do_delete(self, evt: Event):
        """
        Not sure if this method is useful...probably add_event of a delete event is better?
        though maybe there are somecases where you'd want to delete like this without persiting the delete event itself?
        could also add delete mode flag here so that caller can override the stores base delete mode
        Note unlike add_event this currently only supports a single event coming in - though that can ref mutipl events
        to be deleted so doesn't seem a problem?
        :param evt:
        :return:
        """
        batch = GenericSQL.get_delete_batch(store=self,
                                            evt=evt)
        self._db.execute_batch(batch)

    @property
    def DB(self):
        return self._db

class ASQLEventStore(AEventStoreInterface, StoreNIPSupport):
    """
        async base sql store
    """
    def __init__(self,
                 db: ADatabase,
                 delete_mode=DeleteMode.flag,
                 is_nip16=True,
                 is_nip33=True,
                 sort_direction=SortDirection.newest_first,
                 batch_size=500):
        self._sort_direction = sort_direction
        self._db = db
        self._batch_size = batch_size

        StoreNIPSupport.__init__(self,
                                 delete_mode=delete_mode,
                                 nip16=is_nip16,
                                 nip33=is_nip33)

    async def add_event(self, evt: Event):
        for c_batch in GenericSQL.get_add_batch(the_store=self,
                                                evts=evt,
                                                batch_size=self._batch_size,
                                                db_placeholder=self._db.placeholder):
            await self._db.execute_batch(c_batch)

    async def get_filter(self, filter, custom=None, sort_direction=None) -> [{}]:
        """
        from database returns events that match filter/s
        doesn't do #e and #p filters yet (maybe never)
        also author and ids are currently exact only, doesn't support prefix
        :param filter: {} or [{},...] or filters
        :return:
        """
        if sort_direction is None:
            sort_direction = self._sort_direction

        filter_query = GenericSQL.make_sql_filter(filter,
                                                  placeholder=self._db.placeholder,
                                                  custom=custom,
                                                  sort_direction=sort_direction)

        # print(filter_query['sql'], filter_query['args'])

        data = await self._db.select_sql(sql=filter_query['sql'],
                                         args=filter_query['args'])

        return data.as_arr(True)

    async def do_delete(self, evt: Event):
        """
        Not sure if this method is useful...probably add_event of a delete event is better?
        though maybe there are somecases where you'd want to delete like this without persiting the delete event itself?
        could also add delete mode flag here so that caller can override the stores base delete mode
        Note unlike add_event this currently only supports a single event coming in - though that can ref mutipl events
        to be deleted so doesn't seem a problem?
        :param evt:
        :return:
        """
        batch = GenericSQL.get_delete_batch(store=self,
                                            evt=evt)
        await self._db.execute_batch(batch)

    @property
    def DB(self):
        return self._db

# class ClientSQLiteEventStore(ClientEventStoreInterface, ABC):
#     """
#         sqlite version of event store implementing method required by client
#     """
#     def __init__(self,
#                  db_file,
#                  full_text=True,
#                  batch_size=500):
#
#         self._db_file = db_file
#         self._db = SQLiteDatabase(self._db_file)
#         self._event_store = SQLEventStore(
#             db=self._db,
#             sort_direction=SortDirection.newest_first,
#             batch_size=batch_size
#         )
#
#         self._full_text = full_text
#         logging.debug('Experimental client sqllite fulltext search: %s' % self._full_text)
#
#     def add_event(self, evt: Event):
#         self._event_store.add_event(evt)
#
#     def do_delete(self, evt: Event):
#         self._event_store.do_delete(evt)
#
#     def get_filter(self, filter) -> [{}]:
#         return self._event_store.get_filter(filter)
#
#     def is_NIP16(self) -> bool:
#         return self._event_store.is_NIP16()
#
#     @property
#     def delete_mode(self):
#         return self._event_store.delete_mode
#
#     async def add_event_relay(self, evt: Event, relay_url: str):
#         pass
#
#     async def get_newest(self, for_relay, filter):
#         pass
#
#     async def get_oldest(self, for_relay, filter):
#         pass
#
#     async def event_relay(self, event_id: str) -> [str]:
#         pass
#
#     async def direct_messages(self, pub_k: str) -> DataSet:
#         pass
#
#     async def relay_list(self, pub_k: str = None) -> []:
#         pass
#
#     def create(self):
#         self._db.execute_batch(SQLiteSQL.get_create_relay_db())
#
#     def exists(self):
#         return Path(self._db.file).is_file()
#
#     def destroy(self):
#         os.remove(self._db.file)


