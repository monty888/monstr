import logging
import asyncio
from datetime import datetime
from monstr.client.client import Client, ClientPool
from monstr.client.event_handlers import EventHandler,DeduplicateAcceptor
from monstr.event.event import Event
from monstr.encrypt import Keys, NIP4Encrypt
from monstr.util import util_funcs

# default relay if not otherwise given
# DEFAULT_RELAY = 'wss://nostr-pub.wellorder.net,wss://nos.lol'
DEFAULT_RELAY = 'ws://localhost:8080'
# DEFAULT_RELAY = 'wss://nos.lol'
# bot account priv_k - to remove hardcode
USE_KEY = 'nsec1fnyygyh57chwf7zhw3mwmrltc2hatfwn0hldtl4z5axv4netkjlsy0u220'


def get_args():
    return {
        'relays': DEFAULT_RELAY,
        'bot_account': Keys(USE_KEY)
    }


class BotEventHandler(EventHandler):

    def __init__(self, as_user: Keys, clients: ClientPool):
        self._as_user = as_user
        self._clients = clients

        # to encrypt replies if nip4
        self._nip4_enc = NIP4Encrypt(self._as_user)

        # track count times we replied to each p_pub_k
        self._replied = {}

        # TODO - we should if check the events is for us in do_event or use an acceptor to do the same
        # currently we're just relying on the filter being currect (and the relay ofcourse...)
        super().__init__(event_acceptors=[DeduplicateAcceptor()])

    def _make_reply_tags(self, src_evt: Event) -> []:
        """
            minimal tagging just that we're replying to sec_evt and tag in the creater pk so they see our reply
        """
        return [
            ['p', src_evt.pub_key],
            ['e', src_evt.id, 'reply']
        ]

    def do_event(self, the_client: Client, sub_id, evt: Event):
        # replying to ourself would be bad! also call accept_event
        # to stop us replying mutiple times if we see the same event from different relays
        if evt.pub_key == self._as_user.public_key_hex() or \
                self.accept_event(the_client, sub_id, evt) is False:
            return

        logging.debug('BotEventHandler::do_event - received event %s' % evt)
        prompt_text, response_text = self.get_response_text(evt)
        logging.debug('BotEventHandler::do_event - prompt = %s' % prompt_text)
        logging.debug('BotEventHandler::do_event - response = %s' % response_text)

        # create and send
        response_event = Event(
            kind=evt.kind,
            content=response_text,
            tags=self._make_reply_tags(evt),
            pub_key=self._as_user.public_key_hex()
        )

        if response_event.kind == Event.KIND_ENCRYPT:
            response_event = self._nip4_enc.encrypt_event(response_event,
                                                          to_pub_k=evt.pub_key)

        response_event.sign(self._as_user.private_key_hex())

        self._clients.publish(response_event)

    def get_response_text(self, the_event):
        # possible parse this text also before passing onm
        prompt_text = the_event.content
        if the_event.kind == Event.KIND_ENCRYPT:
            prompt_text = self._nip4_enc.decrypt(payload=prompt_text,
                                                 for_pub_k=the_event.pub_key)

        # do whatever to get the response
        pk = the_event.pub_key
        reply_n = self._replied[pk] = self._replied.get(pk, 0)+1
        reply_name = util_funcs.str_tails(pk)

        response_text = f'hey {reply_name} this is reply {reply_n} to you'

        return prompt_text, response_text


async def main(args):
    # just the keys, change to profile?
    as_user = args['bot_account']

    # relays we'll watch
    relays = args['relays']

    # the actually clientpool obj
    my_clients = ClientPool(clients=relays.split(','))

    # do_event of this class is called on recieving events that match teh filter we reg for
    my_handler = BotEventHandler(as_user=as_user,
                                 clients=my_clients)

    # called on first connect and any reconnects, registers our event listener
    def on_connect(the_client: Client):
        the_client.subscribe(sub_id='bot_watch',
                             handlers=[my_handler],
                             filters={
                                 'kinds': [Event.KIND_ENCRYPT,
                                           Event.KIND_TEXT_NOTE],
                                 '#p': [as_user.public_key_hex()],
                                 'since': util_funcs.date_as_ticks(datetime.now())
                             })
    # add the on_connect
    my_clients.set_on_connect(on_connect)

    # start the clients
    print(f'monitoring for events from or to account {as_user.public_key_bech32()} on relays {relays}')
    await my_clients.run()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(main(get_args()))


