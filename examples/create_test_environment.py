"""
    Running this will start up a local relay
        if you supply some pub keys then it'll

"""
import logging
import signal
import asyncio
from monstr.relay.relay import Relay, event_route, filter_route, view_profile_route
from monstr.event.persist import RelayMemoryEventStore
from monstr.client.client import Client
from monstr.event.event import Event
from monstr.ident.profile import ContactList
from monstr.util import util_funcs
from aiohttp import web


async def run_relay():

    r = Relay(store=RelayMemoryEventStore(), enable_nip15=True)
    # add some extra http methods to the relay so we can browse the data a little
    extra_routes = [
        web.get('/e', event_route(r)),
        web.get('/req', filter_route(r)),
        web.get('/view_profile', view_profile_route(r))
    ]


    await r.start_background(port=8888, routes=extra_routes)

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
    async with Client(dest_url) as dest_client:
        for c_meta in Event.latest_events_only(evts, kind=Event.KIND_META):
            dest_client.publish(c_meta)
        for c_contact in Event.latest_events_only(evts, kind=Event.KIND_CONTACT_LIST):
            dest_client.publish(c_contact)
        for c_text in [c_evt for c_evt in evts if c_evt.kind == Event.KIND_TEXT_NOTE]:
            dest_client.publish(c_text)


async def run(**kargs):
    relay: Relay = await run_relay()

    import_relay = 'wss://nostr-pub.wellorder.net'
    if 'import_relay' in kargs:
        import_relay = kargs['import_relay']


    import_tasks = []

    # import these pub keys
    if 'import_keys' in kargs:
        print('importing: %s' % kargs['import_keys'])

        import_tasks.append(asyncio.create_task(populate_relay(src_url=import_relay,
                                                               pub_ks=kargs['import_keys'],
                                                               dest_url=relay.url)))

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


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    import_relay = 'wss://nostr-pub.wellorder.net'
    asyncio.run(run(import_relay=import_relay,
                    import_keys=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'],
                    import_follows=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f']))