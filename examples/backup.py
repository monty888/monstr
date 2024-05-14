"""
    backup events for a given npub
"""
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from monstr.event.persist_sqlite import ARelaySQLiteEventStore
from monstr.event.event import Event
from monstr.client.client import ClientPool, Client
from monstr.util import util_funcs
from monstr.encrypt import Keys

WORK_DIR = f'{Path.home()}/.nostrpy/'
# SOURCE_URL = 'wss://nos.lol,wss://nostr.land/'.split(',')
SOURCE_URL = 'wss://nos.lol'
FOR_NPUB = 'npub1t39l8e2gdq7kr7mjhe053skl7r84ryqmnhvca6xmz780u53wxf0swj0fey'

# 3 years...!
UNTIL = util_funcs.date_as_ticks(datetime.now() - timedelta(days=365*3))

async def do_backup():
    # keys we're backing up
    k = Keys.get_key(FOR_NPUB)

    # where we're storing, make a name from npub and current time
    f_name = f'npub{util_funcs.str_tails(FOR_NPUB[4:],spacer="_")}_{util_funcs.date_as_ticks(datetime.now())}'
    full_file = f'{WORK_DIR}/{f_name}'

    store = ARelaySQLiteEventStore(db_file=full_file)
    await store.create()

    count = 0
    async with Client(SOURCE_URL) as c:

        evts = await c.query_until(until_date=datetime.now(),
                                   filters={
                                       'authors': [k.public_key_hex()]
                                   })

        await store.add_event(evts)
        count += len(evts)
    print(f'backed up {count} events to {full_file}')


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(do_backup())