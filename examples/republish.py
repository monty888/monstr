"""
    adds a subscription and then republish events seen on source relay to dest relay
    could use ClientPool for dest/source if wanting to attach to mutiple
"""
import logging
import asyncio
from datetime import datetime
from monstr.client.event_handlers import LastEventHandler, RepostEventHandler
from monstr.client.client import Client
from monstr.util import util_funcs


SOURCE_URL = "wss://nos.lol"
DEST_URL = "ws://localhost:8080"
# events that we'll be republishing from the one relay to the other
COPY_FILTER = {
    'kinds': [1]
}

async def do_republish():
    # attach to dest relay
    dest_r = Client(relay_url=DEST_URL)
    asyncio.create_task(dest_r.run())

    # keeps track of date of must recent event, if we drop connect will use this to set the since date
    my_last = LastEventHandler()

    # actually does the republish
    my_repub = RepostEventHandler(to_client=dest_r)

    since = util_funcs.date_as_ticks(datetime.now())


    def on_connect(the_client: Client):
        since = my_last.get_last_event_dt(the_client)
        if since:
            COPY_FILTER['since'] = since

        # start the subscription
        the_client.subscribe(
            handlers=[
                my_last, my_repub
            ],
            filters=COPY_FILTER
        )

    # now do the republishing...
    async with Client(relay_url=SOURCE_URL,
                      on_connect=on_connect) as source_r:

        # wait forever
        while True:
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(do_republish())