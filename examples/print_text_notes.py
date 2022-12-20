"""
    get the last 10 text notes for a given public key and print to the console,
    then print new events as they come in

"""
import sys
from nostr.client.client import Client
from nostr.client.event_handlers import EventHandler
from nostr.event.event import Event
from nostr.util import util_funcs
from nostr.encrypt import Keys

def get_notes(for_key, relay='ws://localhost:8888/'):
    print('getting text(1) kind notes for key: %s from %s' % (for_key,
                                                              relay))

    # track last since so that if we reconnect we don't ask for everything again
    last_since = None
    sub_id = None

    class PrintHandler(EventHandler):
        def do_event(self, sub_id, evt, relay):
            print_event('ON_EVENT', evt)

    my_handler = PrintHandler()

    # called whenever we connect, if the connection is lost and we reconnect it'll be called again
    def on_connect(the_client: Client):
        nonlocal sub_id
        print('connected to relay: %s' % the_client.url)

        # add a sub to get text notes
        filter = {
            'kinds': [Event.KIND_TEXT_NOTE],
            'authors': [for_key],
            'limit': 10
        }
        if last_since:
            filter['since'] = last_since

        # sub_id will be rnd asigned but we'll keep it the same from then on
        sub_id = the_client.subscribe(filters=filter,
                                      sub_id=sub_id,
                                      handlers=my_handler)


    # this will do the store events on first connect or reconnect after some time
    def on_eose(the_client: Client, sub_id:str, events: [Event]):
        # so newest events come in at the bottom
        Event.sort(events, inplace=True, reverse=False)
        for evt in events:
            print_event('EOSE', evt)

    def print_event(rec_type:str, evt: Event):
        print('%s-%s:: %s - %s' % (evt.created_at.date(),
                                   rec_type,
                                   util_funcs.str_tails(evt.id),
                                   evt.content))

    c = Client(relay_url=relay,
               on_connect=on_connect,
               on_eose=on_eose)
    c.start()


if __name__ == "__main__":
    for_key = '5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'
    args = sys.argv[1:]
    if len(args):
        for_key = args[0]
        for_key = Keys.get_key(for_key)
        if for_key:
            for_key = for_key.public_key_hex()
        else:
            print('key looks incorrect - %s' % args[0])
            sys.exit(2)

        print('using supplied key: %s' % for_key)
    else:
        print('no key supplied using example default: %s' % for_key)

    get_notes(for_key)