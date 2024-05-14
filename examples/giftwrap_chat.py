"""
    example of chatting using giftwraps (NIP59)
    tested chatting to 0xChat
"""

import asyncio
import signal
import sys
import datetime
from datetime import timedelta
import logging
from monstr.client.client import Client, ClientPool
from monstr.client.event_handlers import DeduplicateAcceptor
import aioconsole
from monstr.event.event import Event
from monstr.util import util_funcs
from monstr.signing import BasicKeySigner
from monstr.encrypt import NIP4Encrypt, Keys, NIP44Encrypt
from monstr.giftwrap import GiftWrap


AS_K = 'nsec1yh5z0a4l7zpqca586a0n4heujgs6cpgs9a4quwh8598d78eqeh6qtu468c'
TO_K = 'npub1fsuwqy83qq7km0308ye8qtqqxjypxal66x094f7t7376dp5haxnq4y542u'

tail = util_funcs.str_tails


async def listen_notes(url):

    # nip59 gift wrapper
    my_k = Keys(AS_K)
    my_gift = GiftWrap(BasicKeySigner(my_k))
    send_k = Keys(pub_k=TO_K)

    print(f'running as npub{tail(my_k.public_key_bech32()[4:])}, messaging npub{tail(send_k.public_key_bech32()[4:])}')

    # q before printing events
    print_q = asyncio.Queue()

    # as we're using a pool we'll see the same events multiple times
    # DeduplicateAcceptor is used to ignore them
    my_dd = DeduplicateAcceptor()


    # used for both eose and adhoc
    def my_handler(the_client: Client, sub_id: str, evt: Event):
        print_q.put_nowait(evt)

    def on_connect(the_client: Client):
        # oxchat seems to use a large date jitter... think 8 days is enough
        since = util_funcs.date_as_ticks(datetime.datetime.now() - timedelta(hours=24*8))

        the_client.subscribe(handlers=my_handler,
                             filters=[
                                # can only get events for us from relays, we need to store are own posts
                                {
                                    'kinds': [Event.KIND_GIFT_WRAP],
                                    '#p': [my_k.public_key_hex()]
                                }
                             ]
                             )


    def on_auth(the_client: Client, challenge):
        print('auth requested')


    # create the client and start it running
    c = ClientPool(url,
                   on_connect=on_connect,
                   on_auth=on_auth,
                   on_eose=my_handler)
    asyncio.create_task(c.run())

    def sigint_handler(signal, frame):
        print('stopping...')
        c.end()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    async def output():
        while True:
            events: [Event] = await print_q.get()
            # because we use from both eose and adhoc, when adhoc it'll just be single event
            # make [] to simplify code
            if isinstance(events, Event):
                events = [events]

            events = [await my_gift.unwrap(evt) for evt in events]
            # can't be sorted till unwrapped
            events.sort(reverse=True)

            for c_event in events:
                print(c_event.created_at, c_event.content)
                # print(c_event.event_data())


    asyncio.create_task(output())

    msg_n = ''
    while msg_n != 'exit':
        msg = await aioconsole.ainput('')
        # msg_n = msg.lower().replace(' ', '')


        send_evt = Event(content=msg,
                         tags=[
                             ['p', send_k.public_key_hex()]
                         ])

        wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                  to_pub_k=send_k.public_key_hex())
        c.publish(wrapped_evt)

        # this version is for us.. this seems to be the way oxchat does it I think but you could
        # just store locally though it'd be a pain getting your events on different instance
        await asyncio.sleep(0.2)
        wrapped_evt, trans_k = await my_gift.wrap(send_evt,
                                                  to_pub_k=my_k.public_key_hex())
        c.publish(wrapped_evt)


        # if msg_n != '' and msg_n != 'exit':
        #     tags = []
        #     if to_user:
        #         tags = [['p', to_user.public_key_hex()]]
        #
        #     n_event = Event(kind=Event.KIND_TEXT_NOTE,
        #                     content=msg,
        #                     pub_key=as_user.public_key_hex(),
        #                     tags=tags)
        #     n_event.sign(as_user.private_key_hex())
        #     client.publish(n_event)

    print('stopping...')
    c.end()

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    # url = ['wss://relay.0xchat.com','wss://relay.damus.io']
    # this relay seems to work the best with these kind of anon published events, atleast for now
    # others it seems to be a bit of hit and miss...
    url = ['wss://nostr.oxtr.dev']
    asyncio.run(listen_notes(url))