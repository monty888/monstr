"""
    Running this will start up a local relay
        if you supply some pub keys then it'll

"""
import logging
import time
import signal

from nostr.relay.relay import Relay, event_route
from nostr.event.persist import RelayMemoryEventStore
from nostr.client.client import Client
from nostr.event.event import Event
from threading import Thread


def run_relay():
    def start():
        r.start(port=8888)

    def stop():
        r.end()

    r = Relay(store=RelayMemoryEventStore())
    r.app.route('/e', callback=event_route(r))

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
        # get meta/profile data for given pub_ks
        metas = src_client.query(filters={
            'kinds': [Event.KIND_META],
            'authors': pub_ks
        })

    # contacts
    with Client(src_relay) as src_client:
        # get meta/profile data for given pub_ks
        contacts = src_client.query(filters={
            'kinds': [Event.KIND_CONTACT_LIST],
            'authors': pub_ks
        })

    # test note
    with Client(src_relay) as src_client:
        # get meta/profile data for given pub_ks
        notes = src_client.query(filters={
            'kinds': [Event.KIND_TEXT_NOTE],
            'authors': pub_ks
        })

    # now we'll post them into our own local relay which so it has some real data
    with Client(dest_relay) as dest_client:
        dest_client.wait_connect()
        for c_meta in metas:
            dest_client.publish(c_meta)
        for c_contact in Event.latest_events_only(contacts, kind=Event.KIND_CONTACT_LIST):
            dest_client.publish(c_contact)
        for c_text in notes:
            dest_client.publish(c_text)


def run(**kargs):
    print('starting relay...')
    relay: Relay = run_relay()

    print('ready to do shit')
    if 'import_keys' in kargs:
        populate_relay(pub_ks=kargs['import_keys'],
                       dest_relay=relay.url)

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        relay.end()
    signal.signal(signal.SIGINT, sigint_handler)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    run(import_keys=['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'])