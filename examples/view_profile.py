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
from monstr.ident.event_handlers import NetworkedProfileEventHandler

class ServerError(Exception):
    pass

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
            raise ServerError('%s - doesn\'t look like a nonstr pub_k' % pub_k)

        ret = {
            'pub_k': pub_k,
            'error': 'not found'
        }
        p = self._my_peh.get_profile(pub_k)
        if p:
            ret = p.as_dict()
        return ret

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
    relays = ['wss://nostr-pub.wellorder.net']
    args = sys.argv[1:]
    if args:
        relays = args[0].split(',')

    start_server(relays)
