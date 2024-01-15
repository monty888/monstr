import logging
import os
from pathlib import Path
from abc import ABC
from monstr.event.persist import DeleteMode, ARelayEventStoreInterface, RelayEventStoreInterface, \
    ASQLEventStore, SQLEventStore
from monstr.db.db import ASQLiteDatabase, SQLiteDatabase
from monstr.event.event import Event

CREATE_SQL_BATCH = [
    {
        'sql':
            """
            create table events( 
                id INTEGER PRIMARY KEY,  
                event_id UNIQUE ON CONFLICT IGNORE,  
                pubkey text,  
                created_at int,  
                kind int,  
                tags text,  
                content text,  
                sig text,  
                d_tag text,
                deleted int)
            """
    },
    {
        'sql':
            """
            create table event_tags(
                id int,  
                type text,  
                value text collate nocase,
                UNIQUE(id, type, value) ON CONFLICT IGNORE    
            )
            """
    },
    # triggers to keep things in sync
    {
        'sql': """
    CREATE TRIGGER event_tags_ad AFTER DELETE ON events BEGIN
      DELETE from event_tags where id=old.id;
    END;
    """
    }

]


class RelaySQLiteEventStore(SQLEventStore, RelayEventStoreInterface,ABC):
    """
        sqlite version of event store implementing method required by relay
    """
    def __init__(self,
                 db_file,
                 is_nip16=True,
                 is_nip33=True,
                 delete_mode=DeleteMode.flag):
        self._db_file = db_file
        self._db = SQLiteDatabase(self._db_file)

        SQLEventStore.__init__(self,
                               db=self._db,
                               delete_mode=delete_mode,
                               is_nip16=is_nip16,
                               is_nip33=is_nip33)

        logging.debug('RelaySQLiteEventStore::__init__ file: %s' % self._db_file)

    # def add_event(self, evt: Event):
    #     self._event_store.add_event(evt)
    #
    # def do_delete(self, evt: Event):
    #     self._event_store.do_delete(evt)
    #
    # def get_filter(self, filter) -> [{}]:
    #     return self._event_store.get_filter(filter)
    #
    # def is_NIP16(self) -> bool:
    #     return self._event_store.is_NIP16()
    #
    # @property
    # def delete_mode(self):
    #     return self._event_store.delete_mode
    #
    # def is_NIP09(self):
    #     return self.delete_mode in (DeleteMode.flag, DeleteMode.delete)

    def create(self):
        self._db.execute_batch(CREATE_SQL_BATCH)

    def exists(self):
        return Path(self._db.file).is_file()

    def destroy(self):
        os.remove(self._db.file)


class ARelaySQLiteEventStore(ASQLEventStore, ARelayEventStoreInterface, ABC):
    """
        async sqlite version of event store implementing method required by relay
    """
    def __init__(self,
                 db_file,
                 is_nip16=True,
                 is_nip33=True,
                 delete_mode=DeleteMode.flag):
        self._db_file = db_file
        self._db = ASQLiteDatabase(self._db_file)
        ASQLEventStore.__init__(self,
                                db=self._db,
                                delete_mode=delete_mode,
                                is_nip16=is_nip16,
                                is_nip33=is_nip33)

        logging.debug('ARelaySQLiteEventStore::__init__ file: %s' % self._db_file)

    async def create(self):
        await self._db.execute_batch(CREATE_SQL_BATCH)

    def exists(self):
        return Path(self._db.file).is_file()

    def destroy(self):
        os.remove(self._db.file)

#
# class AClientSQLiteEventStore(AClientEventStoreInterface, ABC):
#     """
#         async sqlite version of event store implementing method required by client
#     """
#     def __init__(self,
#                  db_file,
#                  full_text=True,
#                  batch_size=500):
#
#         self._db_file = db_file
#         self._db = ASQLiteDatabase(self._db_file)
#         self._event_store = ASQLEventStore(
#             db=self._db,
#             sort_direction=SortDirection.newest_first,
#             batch_size=batch_size
#         )
#
#         self._full_text = full_text
#         logging.debug('Experimental client sqllite fulltext search: %s' % self._full_text)
#
#     async def add_event(self, evt: Event):
#         await self._event_store.add_event(evt)
#
#     async def do_delete(self, evt: Event):
#         await self._event_store.do_delete(evt)
#
#     async def get_filter(self, filter) -> [{}]:
#         return await self._event_store.get_filter(filter)
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
#     async def create(self):
#         await self._db.execute_batch(CREATE_SQL_BATCH)
#
#     def exists(self):
#         return Path(self._db.file).is_file()
#
#     def destroy(self):
#         os.remove(self._db.file)


