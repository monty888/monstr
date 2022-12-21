"""
    Running this will start up a local relay
        if you supply some pub keys then it'll

"""
import logging
import time
import signal
from nostr.relay.relay import Relay, event_route, filter_route
from nostr.event.persist import RelayMemoryEventStore
from nostr.client.client import Client
from nostr.event.event import Event
from nostr.ident.profile import ContactList
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

    Thread(target=start).start()

    while r.started is False:
        time.sleep(0.1)
        print('wait start')

    return r


def populate_relay(pub_ks, dest_relay: str, src_relay='wss://relay.damus.io'):
    print('populating relay with data from pub_ks %s from relay: %s to %s' % (pub_ks,
                                                                              src_relay,
                                                                              dest_relay))
    if isinstance(pub_ks, str):
        pub_ks = [pub_ks]

    def do_events():
        print('wtf')

    # get the metas
    with Client(src_relay) as src_client:
        # get all dat from this author
        all_evts = src_client.query(filters={
            'kinds': [Event.KIND_META,
                      Event.KIND_CONTACT_LIST,
                      Event.KIND_TEXT_NOTE],
            'authors': pub_ks
        })

    populate_events(evts=all_evts,
                    dest_relay=dest_relay)


def import_follows(pub_ks, dest_relay: str, src_relay='wss://relay.damus.io'):

    # the pub_ks that we're getting follows of should already have been
    # so we use the dest relay
    with Client(dest_relay) as dest_client:
        contact_evts = dest_client.query(filters={
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
                   dest_relay=dest_relay,
                   src_relay=src_relay)


def populate_events(evts, dest_relay:str):
    c_evt: Event
    # now we'll post them into our own local relay which so it has some real data
    with Client(dest_relay) as dest_client:
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
                       dest_relay=relay.url)

    # import any profiles in most recent follow list of these profiles
    if 'import_follows' in kargs:
        print('importing follows of: %s' % kargs['import_follows'])
        import_follows(pub_ks=kargs['import_follows'],
                       dest_relay=relay.url)

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        relay.end()
    signal.signal(signal.SIGINT, sigint_handler)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    run(import_keys=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'],
        import_follows=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'])