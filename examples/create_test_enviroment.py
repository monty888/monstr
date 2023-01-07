"""
    Running this will start up a local relay
        if you supply some pub keys then it'll

"""
from gevent import monkey
# important else greenlets may never get to run
monkey.patch_all()
import logging
import time
import signal
from monstr.relay.relay import Relay, event_route, filter_route, view_profile_route
from monstr.event.persist import RelayMemoryEventStore
from monstr.client.client import Client
from monstr.event.event import Event
from monstr.ident.profile import ContactList
from monstr.util import util_funcs
from threading import Thread


def run_relay():
    def start():
        r.start(port=8888)

    def stop():
        r.end()

    r = Relay(store=RelayMemoryEventStore(), enable_nip15=True)

    # adds a helper route so we can get events over http by id
    r.app.route('/e', callback=event_route(r))
    # more flexible req like route
    r.app.route('/req', callback=filter_route(r))
    # very basic profile view
    r.app.route('/view_profile', callback=view_profile_route(r))

    Thread(target=start).start()

    while r.started is False:
        time.sleep(0.1)
        print('wait start')

    return r


def populate_relay(pub_ks, dest_url: str, src_url: str='wss://nostr-dev.wellorder.net'):
    print('populating relay with data from pub_ks %s from relay: %s to %s' % (pub_ks,
                                                                              src_url,
                                                                              dest_url))
    if isinstance(pub_ks, str):
        pub_ks = [pub_ks]

    # get the metas
    with Client(src_url) as src_client:
        # get all dat from this author
        for c_chunk in util_funcs.chunk(pub_ks, 10):
            got_data = False
            while got_data is False:
                try:
                    all_evts = src_client.query(filters={
                        'kinds': [Event.KIND_META,
                                  Event.KIND_CONTACT_LIST,
                                  Event.KIND_TEXT_NOTE],
                        'authors': c_chunk
                    })
                    got_data = True
                except Exception as e:
                    pass

            populate_events(evts=all_evts,
                            dest_url=dest_url)


def import_follows(pub_ks, dest_url: str, src_url='wss://nostr-dev.wellorder.net'):

    # the pub_ks that we're getting follows of should already have been imported
    # so we use the dest relay
    with Client(dest_url) as dest_relay:
        contact_evts = dest_relay.query(filters={
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

        populate_relay(pub_ks=list(follow_ks),
                       dest_url=dest_url,
                       src_url=src_url)


def populate_events(evts, dest_url:str):
    c_evt: Event
    # now we'll post them into our own local relay which so it has some real data
    with Client(dest_url) as dest_client:
        dest_client.wait_connect()
        for c_meta in Event.latest_events_only(evts, kind=Event.KIND_META):
            dest_client.publish(c_meta)
        for c_contact in Event.latest_events_only(evts, kind=Event.KIND_CONTACT_LIST):
            dest_client.publish(c_contact)
        for c_text in [c_evt for c_evt in evts if c_evt.kind == Event.KIND_TEXT_NOTE]:
            dest_client.publish(c_text)


def run(**kargs):
    print('starting relay...')
    relay: Relay = run_relay()

    # import these pub keys
    if 'import_keys' in kargs:
        print('importing: %s' % kargs['import_keys'])
        populate_relay(pub_ks=kargs['import_keys'],
                       dest_url=relay.url)

    # import any profiles in most recent follow list of these profiles
    if 'import_follows' in kargs:
        print('importing follows of: %s' % kargs['import_follows'])
        import_follows(pub_ks=kargs['import_follows'],
                       dest_url=relay.url)

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        relay.end()
    signal.signal(signal.SIGINT, sigint_handler)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    run(import_keys=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'],
        import_follows=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'])