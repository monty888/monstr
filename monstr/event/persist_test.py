import logging
import asyncio
from datetime import datetime
from pathlib import Path
from monstr.event.persist import RelayEventStoreInterface, ClientEventStoreInterface
from monstr.event.persist_sqlite import ARelaySQLiteEventStore, RelaySQLiteEventStore
from monstr.event.persist_memory import RelayMemoryEventStore
from monstr.util import util_funcs
from monstr.event.event import Event
from monstr.encrypt import Keys

# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'


def make_events(kind: int, count: int, use_key: Keys, d_tag=None) -> [Event]:
    ret = []
    at_date = util_funcs.date_as_ticks(datetime.now())
    tags = None
    if d_tag:
        tags = [['d', d_tag]]

    for i in range(0, count):
        n_evt = Event(
            kind=kind,
            content=f'event {i}',
            pub_key=use_key.public_key_hex(),
            created_at=at_date,
            tags=tags
        )
        at_date += 1
        n_evt.sign(use_key.private_key_hex())

        ret.append(n_evt)
    return ret


def run_store_tests(store: RelayEventStoreInterface):
    use_k = Keys()
    count = 10

    # make a few normal events, then query see that we get them back
    store.add_event(make_events(kind=Event.KIND_TEXT_NOTE,
                                count=count,
                                use_key=use_k))

    assert len(store.get_filter({'kinds': Event.KIND_TEXT_NOTE})) == count
    print('basic events add OK')

    # test for basic replaceable events NIP16
    store.add_event(make_events(kind=10000,
                                count=count,
                                use_key=use_k))

    # count depends on if store is supporting NIP16, either 1 or count
    event_count = len(store.get_filter({'kinds': 10000}))
    if store.NIP16:
        assert event_count == 1
        print('basic replacable events for NIP16=true add OK')
    else:
        assert event_count == count
        print('basic replacable events for NIP16=false add OK')

    # test for param replacable events NIP33
    store.add_event(make_events(kind=30000,
                                count=count,
                                use_key=use_k,
                                d_tag='d1'))
    store.add_event(make_events(kind=30000,
                                count=count,
                                use_key=use_k,
                                d_tag='d2'))

    # if store is supporting NIP33 then only 2 event should ever exist, else should==count*2
    event_count = len(store.get_filter({'kinds': 30000}))
    if store.NIP33:
        assert event_count == 2
        print('para replacable events for NIP33=true add OK')
    else:
        assert event_count == count * 2
        print('para replacable events for NIP33=false add OK')


    # assert len(await store.get_filter({'kind': Event.KIND_TEXT_NOTE})) == count
    # print('basic events add OK')


async def arun_store_tests(store: RelayEventStoreInterface):
    use_k = Keys()
    count = 10

    # make a few normal events, then query see that we get them back
    await store.add_event(make_events(kind=Event.KIND_TEXT_NOTE,
                                      count=count,
                                      use_key=use_k))

    assert len(await store.get_filter({'kinds': Event.KIND_TEXT_NOTE})) == count
    print('basic events add OK')

    # test for basic replaceable events NIP16
    await store.add_event(make_events(kind=10000,
                                      count=count,
                                      use_key=use_k))

    # count depends on if store is supporting NIP16, either 1 or count
    event_count = len(await store.get_filter({'kinds': 10000}))
    if store.NIP16:
        assert event_count == 1
        print('basic replacable events for NIP16=true add OK')
    else:
        assert event_count == count
        print('basic replacable events for NIP16=false add OK')

    # test for param replacable events NIP33
    await store.add_event(make_events(kind=30000,
                                      count=count,
                                      use_key=use_k,
                                      d_tag='d1'))
    await store.add_event(make_events(kind=30000,
                                      count=count,
                                      use_key=use_k,
                                      d_tag='d2'))

    # if store is supporting NIP33 then only 2 event should ever exist, else should==count*2
    event_count = len(await store.get_filter({'kinds': 30000}))
    if store.NIP33:
        assert event_count == 2
        print('para replacable events for NIP33=true add OK')
    else:
        assert event_count == count * 2
        print('para replacable events for NIP33=false add OK')


    # assert len(await store.get_filter({'kind': Event.KIND_TEXT_NOTE})) == count
    # print('basic events add OK')


async def atest_sqlite_relay():
    test_file = f'{WORK_DIR}store_test.db'
    nip16 = True
    nip33 = True

    store = ARelaySQLiteEventStore(db_file=test_file,
                                   is_nip16=nip16,
                                   is_nip33=nip33)
    if store.exists():
        store.destroy()
        store = ARelaySQLiteEventStore(db_file=test_file,
                                       is_nip16=nip16,
                                       is_nip33=nip33)
    await store.create()
    await arun_store_tests(store=store)


def test_sqlite_relay():
    test_file = f'{WORK_DIR}store_test.db'
    nip16 = True
    nip33 = True

    store = RelaySQLiteEventStore(db_file=test_file,
                                  is_nip16=nip16,
                                  is_nip33=nip33)
    if store.exists():
        store.destroy()
        store = RelaySQLiteEventStore(db_file=test_file,
                                      is_nip16=nip16,
                                      is_nip33=nip33)
    store.create()
    run_store_tests(store=store)


def test_memory_relay():
    nip16 = True
    nip33 = True

    store = RelayMemoryEventStore(is_nip16=nip16,
                                  is_nip33=nip33)
    run_store_tests(store=store)


async def arun_all_tests():
    print('runnning all async tests')
    await atest_sqlite_relay()


def run_all_tests():
    print('runnning all sync tests')
    test_memory_relay()
    test_sqlite_relay()

if __name__ == '__main__':
    asyncio.run(arun_all_tests())
    # run_all_tests()