"""
    Running this will start up a local relay
        if you supply some pub keys then it'll

"""
import logging
import signal
import asyncio
from datetime import datetime
from monstr.relay.relay import Relay, event_route, filter_route, view_profile_route
from monstr.event.persist_sqlite import ARelaySQLiteEventStore
from monstr.client.client import Client
from monstr.event.event import Event
from monstr.ident.profile import ContactList
from monstr.util import util_funcs
from aiohttp import web
from pathlib import Path

COPY_RELAY = 'wss://nos.lol'
OUR_RELAY_URL = 'localhost'
OUR_RELAY_PORT = 8080
WORK_DIR = f'{Path.home()}/.nostrpy/'
DB = f'{WORK_DIR}test_env.db'


async def run_relay(at_host, at_port):

    r = Relay(store=ARelaySQLiteEventStore(DB),
              max_sub=10)
    # add some extra http methods to the relay so we can browse the data a little
    extra_routes = [
        web.get('/e', event_route(r)),
        web.get('/req', filter_route(r)),
        web.get('/view_profile', view_profile_route(r))
    ]

    await r.start(host=at_host,
                  port=at_port,
                  routes=extra_routes,
                  block=False)
    return r


async def populate_relay(pub_ks, dest_url: str, src_url):
    print('populating relay with data from pub_ks %s from relay: %s to %s' % (pub_ks,
                                                                              src_url,
                                                                              dest_url))
    if isinstance(pub_ks, str):
        pub_ks = [pub_ks]

    # get the metas
    async with Client(src_url, query_timeout=None, ping_timeout=None) as src_client:
        # get all dat from this author
        for c_chunk in util_funcs.chunk(pub_ks, 10):
            chunk_evts = await src_client.query(filters={
                'kinds': [Event.KIND_META,
                          Event.KIND_CONTACT_LIST,
                          Event.KIND_TEXT_NOTE],
                'authors': c_chunk
            })
            await populate_events(evts=chunk_evts,
                                  dest_url=dest_url)


async def import_follows(pub_ks, dest_url: str, src_url):

    # the pub_ks that we're getting follows of should already have been imported
    # so we use the dest relay
    async with Client(src_url, query_timeout=None) as src_relay:
        contact_evts = await src_relay.query(filters={
            'kinds': [Event.KIND_CONTACT_LIST],
            'authors': pub_ks
        })

        contact_evts = Event.latest_events_only(contact_evts, kind=Event.KIND_CONTACT_LIST)
        lists = [ContactList.from_event(c_evt) for c_evt in contact_evts]
        c_l: ContactList

        follow_ks = set()
        for c_l in lists:
            for c_k in c_l.follow_keys():
                follow_ks.add(c_k)

        await populate_relay(pub_ks=list(follow_ks),
                             dest_url=dest_url,
                             src_url=src_url)
        print('import follows done...')


async def populate_events(evts, dest_url:str):
    c_evt: Event
    # now we'll post them into our own local relay which so it has some real data

    last_msg = datetime.now()

    def my_ok(the_client: Client, event_id, success, msg):
        nonlocal last_msg
        last_msg = datetime.now()

    async with Client(dest_url, on_ok=my_ok) as dest_client:
        for c_meta in Event.latest_events_only(evts, kind=Event.KIND_META):
            dest_client.publish(c_meta)
        for c_contact in Event.latest_events_only(evts, kind=Event.KIND_CONTACT_LIST):
            dest_client.publish(c_contact)
        for c_text in [c_evt for c_evt in evts if c_evt.kind == Event.KIND_TEXT_NOTE]:
            dest_client.publish(c_text)

        while (datetime.now() - last_msg).seconds < 5:
            print('waiting...')
            await asyncio.sleep(0.1)


async def run(import_relay, relay_host, relay_port, **kargs):
    relay: Relay = await run_relay(at_host=relay_host,
                                   at_port=relay_port)

    import_tasks = []

    # import these pub keys
    if 'import_keys' in kargs:
        print('importing: %s' % kargs['import_keys'])

        import_tasks.append(asyncio.create_task(populate_relay(src_url=import_relay,
                                                               pub_ks=kargs['import_keys'],
                                                               dest_url=relay.url)))
    #
    # import any profiles in most recent follow list of these profiles
    if 'import_follows' in kargs:
        print('importing follows of: %s' % kargs['import_follows'])
        import_tasks.append(asyncio.create_task(import_follows(src_url=import_relay,
                                                               pub_ks=kargs['import_follows'],
                                                               dest_url=relay.url)))

    # do the imports if any
    if import_tasks:
        done, _ = await asyncio.wait(import_tasks,
                                     return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            try:
                task.result()
            except Exception as e:
                print(e)

    while True:
        await asyncio.sleep(0.1)

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        relay.end()

    signal.signal(signal.SIGINT, sigint_handler)


async def relay_basic():
    from monstr.relay.accept_handlers import CreateAtAcceptor, AuthenticatedAcceptor
    from monstr.encrypt import Keys
    acceptors = [
        CreateAtAcceptor(max_before=10,
                         max_after=10),
        AuthenticatedAcceptor([
            Keys.get_key('npub1nsdyr8qrv6yeymh6ayhwltrjzxpcyjeqavpw896ja9rnu6c2vc9sexxuwu').public_key_hex(),
            '5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'
        ])
        # AuthenticatedAcceptor(authorised_keys=None)
    ]

    r = Relay(accept_req_handler=acceptors, request_auth=True)

    await r.start(port=8888)


async def post_basic():
    from monstr.encrypt import Keys
    from monstr.client.client import Client

    use_key = Keys()
    from datetime import timedelta

    n_evt = Event(kind=Event.KIND_TEXT_NOTE,
                  content='accept me',
                  pub_key=use_key.public_key_hex(),
                  created_at=util_funcs.date_as_ticks((datetime.now()+timedelta(minutes=6))))
    n_evt.sign(use_key.private_key_hex())

    def my_notice(err_txt):
        print(err_txt)

    async with Client(relay_url='ws://localhost:8081',
                      on_notice=my_notice) as c:
        c.publish(n_evt)
        await asyncio.sleep(1)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    util_funcs.create_sqlite_store(DB)

    asyncio.run(run(import_relay=COPY_RELAY,
                    relay_host=OUR_RELAY_URL,
                    relay_port=OUR_RELAY_PORT,
                    import_keys=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'],
                    import_follows=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f']))
    # asyncio.run(relay_basic())
    # asyncio.run(post_basic())