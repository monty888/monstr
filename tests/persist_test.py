# import logging
# import asyncio
# from datetime import datetime, timedelta
# from pathlib import Path
# from monstr.util import util_funcs
# from monstr.client.client import Client
# from monstr.event.event import Event
# from monstr.event.event_handlers import StoreEventHandler
# from monstr.event.persist import RelaySQLiteEventStore, ARelaySQLiteEventStore, SQLEventStore, AEventStoreInterface
# from monstr.encrypt import Keys
#
# # working directory it'll be created it it doesn't exist
# WORK_DIR = '%s/.nostrpy/' % Path.home()
# # and db we'll use
# DB_FILE = WORK_DIR+'persist_test.db'
#
#
# async def test_publish():
#     k = Keys()
#     last_msg = datetime.now()
#
#     def my_ok(the_client: Client, event_id, success, msg):
#         nonlocal last_msg
#         last_msg = datetime.now()
#
#     async with Client('ws://localhost:8888', on_ok=my_ok) as c:
#         for i in range(0, 1000):
#             n_evt = Event(kind=1,
#                           content='this is event %s for %s ' % (i,
#                                                                 k.private_key_hex()),
#                           pub_key=k.public_key_hex())
#             n_evt.sign(k.private_key_hex())
#             c.publish(n_evt)
#
#         while (datetime.now() - last_msg).seconds < 2:
#             await asyncio.sleep(0.1)
#
# async def test_events():
#     my_persist = StoreEventHandler(ARelaySQLiteEventStore(DB_FILE))
#     # my_persist = StoreEventHandler(SQLEventStore(SQLiteDatabase(DB_FILE)))
#     async with Client('ws://localhost:8888') as c:
#         evts = await c.query(
#             filters={
#                 'kinds': [Event.KIND_TEXT_NOTE],
#                 'limit': 100
#             },
#             do_event=my_persist.do_event
#         )
#         for c_evt in evts:
#             print(c_evt)
#         await my_persist.wait_tasks()
#
# async def test_delete():
#     store = ARelaySQLiteEventStore(DB_FILE)
#     # no need to sign as we're just doing through store
#     delete_event = Event(
#         kind=Event.KIND_DELETE,
#         tags=[
#             ['e', '06a443c4e9428908504cd23c3c84861378fb21cd4f0936dc1639d01fa38d35f5'],
#             ['e', '898c0b8c40974bf10860afbd103e275d6183709cc813104c0fe97c591cc92c89']
#         ]
#     )
#     if isinstance(store, AEventStoreInterface):
#         await store.do_delete(delete_event)
#     else:
#         store.do_delete(delete_event)
#
#
# async def test_query():
#     store = ARelaySQLiteEventStore(DB_FILE)
#     filter = {
#         'authors': ['00000000827ffaa94bfea288c3dfce4422c794fbb96625b6b31e9049f729d700']
#     }
#
#     if isinstance(store, AEventStoreInterface):
#         evts = await store.get_filter(filter)
#     else:
#         evts = store.get_filter(filter)
#
#     print(len(evts))
#
# if __name__ == "__main__":
#     logging.getLogger().setLevel(logging.DEBUG)
#     util_funcs.create_sqlite_store(DB_FILE)
#     asyncio.run(test_events())
#     # asyncio.run(test_events())
#     # asyncio.run(test_delete())
#     # asyncio.run(test_query())