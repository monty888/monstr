"""
start of some code to rebroadcast events, it was actually written to rebroadcast an old contact event after
contacts had been set empty by some client so is only written upto that currently but could easily be extended into
a proper rebroadcaster

"""

import logging
import asyncio
from datetime import datetime
from pathlib import Path
from monstr.event.persist import ClientSQLiteEventStore
from monstr.event.event import Event
from monstr.client.client import Client
from monstr.util import util_funcs

WORK_DIR = '%s/.nostrpy/' % Path.home()
DB = WORK_DIR+'test_env.db'


async def do_republish():
    # get the events we want to replubish, here hardcode to store... this should be option
    # could be from other relay, file or db etc.
    # this events should alredy be signed
    source_db = DB
    my_store = ClientSQLiteEventStore(DB)
    evts = my_store.get_filter({
        'kinds': [Event.KIND_CONTACT_LIST],
        'authors': ['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f']
    })

    def my_connect(the_client):
        print('connected')



    def my_notice(the_client, msg):
        print(msg)

    def my_ok(the_client, evt_id, success, msg):
        print(msg)

    # now do the republishing...
    async with Client(relay_url='wss://nostr-pub.wellorder.net',
                      on_notice=my_notice,
                      on_ok=my_ok,
                      on_connect=my_connect) as c:
        for c_evt in evts:
            print('publishing %s' % c_evt)
            c_evt = Event.from_JSON(c_evt)

            # the old event existed but had been replaced with empty contacts
            # so we needed to up time and resign
            c_evt.created_at = util_funcs.date_as_ticks(datetime.now())
            # c_evt.sign()

            c.publish(c_evt)

    # hack, we should really register and look for oks from the client or similar
    await asyncio.sleep(10)
    print('done')

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(do_republish())