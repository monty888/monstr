from gevent import monkey
# important else greenlets may never get to run
monkey.patch_all()
import sys
import logging
import signal
import bottle
from datetime import datetime
from cachetools import TTLCache
from gevent.pywsgi import WSGIServer
from bottle import Bottle, request
from monstr.client.client import ClientPool, Client
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.ident.profile import Profile

class ServerError(Exception):
    pass


class NetworkedProfileEventHandler:
    """
        simplified profile handler to replace what we have in ident/event_handlers
    """
    def __init__(self,
                 client: Client,
                 cache=None):
        self._client = client
        self._cache = cache

    def do_event(self, the_client: Client, sub_id: str, evts: Event):
        if self._cache is None:
            return

        if isinstance(evts, Event):
            evts = [evts]
        evts = Event.latest_events_only(evts, kind=Event.KIND_META)
        c_evt: Event
        p: Profile
        for c_evt in evts:
            p = Profile.from_event(c_evt)
            if p.public_key not in self._cache or\
                    (p.public_key in self._cache and
                     self._cache[p.public_key].update_at < p.update_at):
                self._cache[p.public_key] = p
                logging.info('NetworkedProfileEventHandler::do_event cache updated pub_k - %s' % p.public_key)

    def get_profile(self, pub_k):
        if self._cache is not None and pub_k in self._cache:
            ret = self._cache[pub_k]
        else:
            ret = self._client.query(
                filters={
                    'kinds': [Event.KIND_META],
                    'authors': [pub_k]
                },
                do_event=self.do_event,
                # note this means data will be return as quick as your slowest relay...
                emulate_single=True)

            if ret:
                # do_event will update cache as required
                Event.latest_events_only(ret, kind=Event.KIND_META)
                ret = Profile.from_event(ret[0])
            else:
                ret = Profile(pub_k=pub_k,
                              update_at=datetime(1970, 1, 1),
                              attrs={
                                  'name': 'not found'
                              })
                # will have to manually put this fake in... It's just there
                # so we don't keep going to the network for meta that doesn't exist
                self._cache[pub_k] = ret

        return ret


class MetaServer:

    def __init__(self,
                  client: ClientPool):

        self._server: WSGIServer = None
        self._client = client
        self._app = Bottle()
        self._my_peh = NetworkedProfileEventHandler(client=self._client,
                                                    cache=TTLCache(maxsize=1000,
                                                                   ttl=60*30))

        def _get_err_wrapped(method):
            def _wrapped(**kargs):
                try:
                    return method(**kargs)
                except ServerError as se:
                    return {
                        'error': str(se)
                    }
            return _wrapped

        self._app.route('/view_profile', callback=_get_err_wrapped(self.view_profile_route))

    def view_profile_route(self):
        pub_k = request.query.pub_k
        if not Keys.is_hex_key(pub_k):
            raise ServerError('%s - doesn\'t look like a monstr pub_k' % pub_k)

        p = self._my_peh.get_profile(pub_k)
        return p.as_dict()

    def start(self, host='localhost', port=8080):
        logging.debug('started web server at %s port=%s' % (host, port))
        self._server = WSGIServer((host, port), self._app)
        self._server.serve_forever()

    def end(self):
        self._server.close()


def start_server(relays):

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        c.end()
        meta_server.end()
    signal.signal(signal.SIGINT, sigint_handler)

    # connection to relays
    # c = Client(relays[0])
    c = ClientPool(relays)
    c.start()
    print('client pool started')

    meta_server = MetaServer(client=c)
    meta_server.start()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    relays = ['ws://localhost:8888/']
    args = sys.argv[1:]
    if args:
        relays = args[0].split(',')

    start_server(relays)
