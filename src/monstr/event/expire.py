import inspect
import logging
import asyncio
from datetime import datetime
from abc import ABC, abstractmethod
from monstr.db.db import Database, ADatabase
from monstr.util import NIPSupport, util_funcs
from monstr.event.persist import EventStoreInterface, AEventStoreInterface
from monstr.event.persist_memory import MemoryEventStore
from monstr.event.event import Event


class AExpirerInterface(ABC, NIPSupport):

    def __init__(self, interval: int = 60):
        self._run = False
        self._interval = interval
        NIPSupport.__init__(self, nip40=True)

    async def run(self):
        self._run = True
        while self._run is True:
            try:
                await self.do_expires()
            except Exception as e:
                logging.debug(f'AExpirer::do_expires - {e}')

            await asyncio.sleep(self._interval)


    def stop(self):
        self._run = False

    @property
    def running(self):
        return self._run

    @abstractmethod
    async def do_expires(self):
        pass


class ASQLiteNIP40Expirer(AExpirerInterface):
    """
        does the basic expiration tag expiration for a given SQLite db, the db can be either
        async or sync as we test in the do_expires method
        unfortunately we need to do more work for postgres because we'll need to cast the value
        field and deal if that doesn't work... Probably best done with a func
    """
    def __init__(self, db: Database, interval: int = 60):
        self._db = db
        super().__init__(
            interval=interval
        )

        self._expire_sql = f"""
            delete from events where id in (
                select id
                    from event_tags where
                        type = 'expiration' and value <= {self._db.placeholder}
                )        
        """

    async def do_expires(self):
        if isinstance(self._db, ADatabase):
            await self._db.execute_sql(sql=self._expire_sql,
                                       args=[util_funcs.date_as_ticks(datetime.now())])
        else:
            self._db.execute_sql(sql=self._expire_sql,
                                 args=[util_funcs.date_as_ticks(datetime.now())])


class MemoryNIP40Expirer(AExpirerInterface):
    """
        basic NIP40 expiration for memory store
    """
    def __init__(self, store: MemoryEventStore, interval: int = 60):
        self._store = store
        super().__init__(
            interval=interval
        )

    async def do_expires(self):
        expire_time = util_funcs.date_as_ticks(datetime.now())
        to_del = []
        for id, data in self._store._events.items():
            c_evt: Event = data['evt']
            expire_tags = c_evt.get_tags_value('expiration')
            if expire_tags:
                try:
                    if expire_time >= int(expire_tags[0]):
                        to_del.append(id)
                # maybe should just delete events with bad expiration tags?
                except ValueError as ve:
                    pass

        # now do aby deletes
        for c_id in to_del:
            del self._store._events[c_id]


async def make_expire_test_events(use_store: EventStoreInterface):
    """
        for testing makes some 10 events that should expire and 10 that shouldn't
        check use_store and calls either async or sync
    """
    from monstr.encrypt import Keys
    from monstr.event.event import Event
    use_k = Keys()
    # add events not to be expired
    for i in range(0, 10):
        n_evt = Event(kind=Event.KIND_TEXT_NOTE,
                      content=f'no_expire {i}',
                      pub_key=use_k.public_key_hex())
        n_evt.sign(use_k.private_key_hex())

        if inspect.iscoroutinefunction(use_store.add_event):
            await use_store.add_event(n_evt)
        else:
            use_store.add_event(n_evt)

    # add events that should expire
    expire_at = util_funcs.date_as_ticks(datetime.now()) + 5
    for i in range(0, 10):
        n_evt = Event(kind=Event.KIND_TEXT_NOTE,
                      content=f'to expire {i}',
                      tags=[
                          ['expiration', expire_at]
                      ],
                      pub_key=use_k.public_key_hex())
        n_evt.sign(use_k.private_key_hex())
        if inspect.iscoroutinefunction(use_store.add_event):
            await use_store.add_event(n_evt)
        else:
            use_store.add_event(n_evt)

async def test_expire_sql():
    # test SQL type stores, has the added create and destroy for those dbs
    from monstr.event.persist_sqlite import ARelaySQLiteEventStore
    from monstr.event.persist_postgres import RelayPostgresEventStore
    from monstr.event.persist_memory import MemoryEventStore

    from pathlib import Path
    from datetime import datetime
    from monstr.util import util_funcs
    from monstr.encrypt import Keys

    WORK_DIR = f'{Path.home()}/.nostrpy/'
    DB = f'{WORK_DIR}test_expire.db'

    my_store = ARelaySQLiteEventStore(db_file=DB)

    # for testing postgres... though we dont have a postgres expirer yet as it requires a bit
    # more work db side, can just use same SQL :(
    # my_store = RelayPostgresEventStore(db_name='test_expire',
    #                                    user='postgres',
    #                                    password='password')

    if not my_store.exists():
        if inspect.iscoroutinefunction(my_store.create):
            await my_store.create()
        else:
            my_store.create()

    # start the expirer, interval only 1sec
    my_expire = ASQLiteNIP40Expirer(db=my_store.DB, interval=1)
    asyncio.create_task(my_expire.run())

    # make the test events
    await make_expire_test_events(my_store)

    # now hang around long enough that events should be expired
    await asyncio.sleep(10)

    try:
        assert len(await my_store.get_filter({})) == 10
        print('LOOKS GOOD...')
    except Exception as e:
        print('IS BAD!!!')

    my_store.destroy()


async def test_expire_memory():
    from monstr.event.persist_memory import MemoryEventStore

    my_store = MemoryEventStore()

    # start the expirer, interval only 1sec
    my_expire = MemoryNIP40Expirer(store=my_store, interval=1)
    asyncio.create_task(my_expire.run())

    # make the test events
    await make_expire_test_events(my_store)

    # now hang around long enough that events should be expired
    await asyncio.sleep(10)

    try:
        assert len(my_store.get_filter({})) == 10
        print('LOOKS GOOD...')
    except Exception as e:
        print(e)
        print('IS BAD!!!')



if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    # asyncio.run(test_expire_memory())
    # asyncio.run(test_expire_sql())
    print(util_funcs.date_as_ticks(datetime.now()))


