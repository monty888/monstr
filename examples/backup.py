"""
    backup events for a given npub
"""
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from monstr.event.persist_sqlite import ARelaySQLiteEventStore
from monstr.event.event import Event
from monstr.client.client import Client
from monstr.util import util_funcs
from monstr.encrypt import Keys

WORK_DIR = f'{Path.home()}/.nostrpy/'
SOURCE_URL = 'wss://nos.lol'
FOR_NPUB = 'npub1t39l8e2gdq7kr7mjhe053skl7r84ryqmnhvca6xmz780u53wxf0swj0fey'

# 3 years...!
UNTIL = util_funcs.date_as_ticks(datetime.now() - timedelta(days=365*3))

async def do_backup():
    # keys we're backing up
    k = Keys.get_key(FOR_NPUB)

    # where we're storing, make a name from npub and current time
    f_name = f'npub{util_funcs.str_tails(FOR_NPUB[4:],spacer="_")}_{util_funcs.date_as_ticks(datetime.now())}'

    store = ARelaySQLiteEventStore(db_file=f'{WORK_DIR}/{f_name}')
    await store.create()
    print(f'doing backup of events for {k.public_key_bech32()} from {SOURCE_URL}')

    """
        move this into client as it's probably quite common to want to scan/page over events like this
        basically we're querying back until until_date and we'll exit when
            - no more results returned
            - we get an event with created at prior to until date (this event will be dropped)
        it might be also useful to scan forward to a since date
        
        
        how to mod to work in ClientPool? should work fine when emulate single, but for the interleaved 
        style it probably requires some extra work...
    """
    async def query_until(the_client: Client, base_query: dict, until_date: int) -> [Event]:
        if isinstance(base_query, dict):
            base_query = [base_query]

        ret = []
        done = False
        old_event = None

        while done is False:
            c_evts = await c.query(base_query)

            # run out of events
            if not c_evts:
                done = True
            else:
                # events should be ordered from relay but just incase....
                c_evts.sort()

                # cut any events upto and including anylast old event if we had one
                if old_event:
                    for back_seek in range(0, len(c_evts)):
                        # the cut off event - last oldest should be the newest in this set
                        if c_evts[back_seek].id == old_event.id:
                            # cut any events before we reach the id of last event
                            c_evts = c_evts[back_seek+1:]
                            break

                if not c_evts:
                    done = True
                else:
                    # the oldest date of any event we got
                    old_event = c_evts[len(c_evts) - 1]
                    oldest_date = old_event.created_at_ticks

                    if oldest_date < until_date:
                        ret = ret + c_evts
                        # mod each filter in base query to have an until date
                        for c_f in base_query:
                            c_f['until'] = oldest_date

                    # add all event < until date and set done True
                    else:
                        done = True
                        for c_evt in c_evts:
                            if c_evt.created_at_ticks < until_date:
                                ret.append(c_evt)
                            else:
                                break

        ret = ret + c_evts

        return ret

    async with Client(SOURCE_URL) as c:

        evts = await query_until(the_client=c,
                                 base_query={
                                     'authors': [k.public_key_hex()]
                                 },
                                 until_date=util_funcs.date_as_ticks(datetime.now()))


        await store.add_event(evts)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(do_backup())