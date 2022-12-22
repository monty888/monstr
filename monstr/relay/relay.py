from bottle import request, Bottle, abort
import logging
from gevent.pywsgi import WSGIServer
from gevent import Greenlet
from geventwebsocket import WebSocketError
from geventwebsocket.handler import WebSocketHandler
from geventwebsocket.websocket import WebSocket
from gevent.lock import BoundedSemaphore
import json
from json import JSONDecodeError
from monstr.event.event import Event
from monstr.event.persist import RelayEventStoreInterface
# from monstr.relay.persist import RelayStoreInterface
from monstr.relay.accept_handlers import AcceptReqHandler
from monstr.exception import NostrCommandException
from monstr.encrypt import Keys
from sqlite3 import IntegrityError
try:
    import psycopg2.errors as pg_errors
except:
    pass
from monstr.util import util_funcs


class Relay:
    """
        implements monstr relay protocol
        NIP-01      -   basic protocol
                        https://github.com/fiatjaf/nostr/blob/master/nips/01.md
        NIP-02      -   contact list
                        https://github.com/fiatjaf/nostr/blob/master/nips/02.md
        NIP-09      -   event deletions depends on the store
                        delete_mode=DeleteMode.DEL_FLAG probbably best option as this will mark the event as deleted
                        but also it won't be possible to repost.
                        https://github.com/fiatjaf/nostr/blob/master/nips/09.md
        NIP-11      -   TODO: Relay Information Document
                        https://github.com/fiatjaf/nostr/blob/master/nips/11.md
        NIP-12          generic querie tags, todo but should be easy.... test with shared
                        https://github.com/fiatjaf/nostr/blob/master/nips/12.md

        NIP-15      -   send 'EOSE' msg after sending the final event for a subscription
                        https://github.com/nostr-protocol/nips/blob/master/15.md

        NIP-16      -   ephemeral and replaceable events, depends on the store
                        https://github.com/nostr-protocol/nips/blob/master/16.md

        for NIPS n,n... whats actually being implemented will be decided by the store/properties it was created with
        e.g. delete example....
        For NIP-12 the relay will check with the store for those NIPs

        TODO: write some test code for each NIP...

    """
    VALID_CMDS = ['EVENT', 'REQ', 'CLOSE']

    def __init__(self, store: RelayEventStoreInterface,
                 accept_req_handler=None,
                 max_sub=3,
                 name: str = None,
                 description: str = None,
                 pubkey: str = None,
                 contact: str = None,
                 enable_nip15=False):
        self._app = Bottle()
        # self._web_sockets = {}

        # single lock for accessing shared resource
        self._lock = BoundedSemaphore()
        # corrently connected ws
        self._ws = {}
        self._store = store

        # max subs allowed per websocket
        self._max_sub = max_sub

        # enable support for nip15, probably this will be removed and just be default on in future
        # as apart from extra msg it shouldn't cause any issues
        self._enable_nip15 = enable_nip15

        # by default when we recieve requests as long as the event has a valid sig we accept
        # (Prob we should also have a future timestamp requirement, it'd probably have to be 12hr+ as
        # there is no timezone info with create_at)
        # but in real world relay will probably want to protect itself more e.g. set max length on
        # event content, restrict to set kinds or even only allow set pubkeys to posts
        # self._accept_req can be a single class or [] of handlers that are called and the event will
        # it'll throw and return a NOTICE evt if msg not accepted (maybe we'd want option to just drop and do nothing?)
        self._accept_req = accept_req_handler
        if self._accept_req is None:
            # accepts everything
            self._accept_req = [AcceptReqHandler()]
        # convert to array of only single class handed in
        if not hasattr(self._accept_req, '__iter__'):
            self._accept_req = [self._accept_req]

        logging.info('Relay::__init__ maxsub=%s '
                     'EOSE enabled(NIP15)=%s, Deletes(NIP9)=%s, Event treatment(NIP16)=%s' % (self._max_sub,
                                                                                              self._enable_nip15,
                                                                                              self._store.is_NIP09(),
                                                                                              self._store.is_NIP16()))
        # this is the server that we run as, it's created after calling start()
        # default is localhost:8080
        self._server: WSGIServer = None
        # end point to connect ws after host://port:end_point default /
        self._end_point = None

        if pubkey is not None and not Keys.is_key(pubkey):
            raise Exception('given contact pubkey is not correct: %s' % pubkey)

        nips = [1, 2, 11]
        if self._enable_nip15:
            nips.append(15)
        if self._store.is_NIP09():
            nips.append(9)
        if self._store.is_NIP16():
            nips.append(16)

        nips.sort()

        self._relay_information = {
            'software': 'https://github.com/monty888/nostrpy',
            'version': '0.1',
            'supported_nips': nips
        }
        if name:
            self._relay_information['name'] = name
        if description:
            self._relay_information['description'] = description
        if contact:
            self._relay_information['contact'] = contact
        if pubkey is not None:
            if Keys.is_key(pubkey):
                raise Exception('given contact pubkey is not correct: %s' % pubkey)
            self._relay_information['pubkey'] = pubkey

    def start(self, host='localhost', port=8080, end_point='/'):
        """
        runs within own gevent.pywsgi.WSGIServer
        probably to expose _app so that it can be run in any WSGI server by caller

        :param host:
        :param port:
        :param end_point:
        http://host:port/endpoint
        :return:
        """
        logging.info('Relay::start %s:%s%s' % (host, port, end_point))
        self._app.route(end_point, callback=self._handle_websocket)
        self._end_point = end_point
        self._server = WSGIServer((host, port), self._app, handler_class=WebSocketHandler)
        self._server.serve_forever()

    @property
    def url(self):
        return 'ws://%s:%s%s' % (self._server.server_host,
                                 self._server.server_port,
                                 self._end_point)

    @property
    def store(self):
        return self._store

    @property
    def app(self):
        return self._app

    @property
    def started(self):
        ret = False
        if self._server is not None:
            ret = self._server.started
        return ret

    def end(self):
        # note to call this you'd have to have called start in a thread or similar
        self._server.stop()

    def _handle_websocket(self):
        logging.debug('Websocket opened')
        ws = request.environ.get('wsgi.websocket')

        if not ws:
            # abort(400, 'Expected WebSocket request.')
            return self._NIP11_relay_info_route()

        # set up place to store subs for ws
        self._ws[ws] = {
            'subs': {
            },
            'send_lock': BoundedSemaphore()
        }

        while True:
            try:
                self._do_request(ws, ws.receive())
            except WebSocketError:
                break

    def _do_request(self, ws: WebSocket, req_str):
        # passed nothing? nothing to do
        if not req_str:
            return

        try:
            as_json = json.loads(req_str)
            if not as_json:
                raise NostrCommandException('No command received')
            cmd = as_json[0]
            if cmd not in Relay.VALID_CMDS:
                raise NostrCommandException('unsupported command %s' % cmd)

            # a post of an event
            if cmd == 'EVENT':
                self._do_event(as_json, ws)
            # register a subscription
            elif cmd == 'REQ':
                self._do_sub(as_json, ws)
            elif cmd == 'CLOSE':
                self._do_unsub(as_json, ws)

        except JSONDecodeError as je:
            err = ['NOTICE', 'unable to decode command string']
            ws.send(json.dumps(err))
        except NostrCommandException as ne:
            err = ['NOTICE', str(ne)]
            ws.send(json.dumps(err))

    def _do_event(self, req_json, ws: WebSocket):
        if len(req_json) <= 1:
            raise NostrCommandException('EVENT command missing event data')
        evt = Event.from_JSON(req_json[1])
        # check event sig matches pub_key
        if not evt.is_valid():
            raise NostrCommandException('invalid event, pubkey doesn\'t match sig')

        # pass evt through all AcceptReqHandlers, if any are not happy they'll raise
        # NostrCommandException otherwise we should be good to go
        for c_accept in self._accept_req:
            c_accept.accept_post(ws, evt)

        try:
            self._store.add_event(evt)
            logging.debug('Relay::_do_event event sent to store %s ' % evt)
            if evt.kind == Event.KIND_DELETE:
                logging.debug('Relay::_do_event doing delete events - %s ' % evt.e_tags)
                self._store.do_delete(evt)

            self._check_subs(evt)

        except (IntegrityError, pg_errors.UniqueViolation) as ie:
            msg = str(ie).lower()
            if 'event_id' in msg and 'unique' in msg:
                raise NostrCommandException.event_already_exists(evt.id)

    def _clean_ws(self):
        """
            this cleans old websockets and thier subs
            TODO: add close handler to the web sockets we get so that we do the clean up then,
            when done this most likely can go...
        """
        to_rem = []
        for ws in self._ws:
            if ws.closed:
                to_rem.append(ws)

        if to_rem:
            with self._lock:
                for c_rem in to_rem:
                    del self._ws[c_rem]

    def _check_subs(self, evt:Event):
        """
        go through all our filters and send the event to any clients who have registered subs
        with filters that the new event passes.
        Note done sequentially through our subs, if we ever had a large numbers of subscribers
        this would probably be problematic, also likely a problem if one blocked or closed etc..
        TODO: convert the send to use ayncio - actually probably have to use threadpool
        see https://stackoverflow.com/questions/51050315/using-asyncio-for-non-async-functions-in-python
        or maybe look at gevent that websocket is already using

        :param evt:
        :return:
        """


        # this will remove any old sockets that already got closed
        self._clean_ws()

        # we should probably still catch websocket closed errs here, they can be clean next hit

        def get_send(ws, sub_id, evt, lock):
            def do_send():
                try:
                    self._send_event(ws, sub_id, evt,lock)
                except:
                    print('mofo!!!!')
            return do_send

        for ws in self._ws:
            for c_sub_id in self._ws[ws]['subs']:
                the_sub = self._ws[ws]['subs'][c_sub_id]
                # event passes sub filter
                if evt.test(the_sub['filter']):
                    Greenlet(get_send(ws, c_sub_id, evt.event_data(), self._ws[ws]['send_lock'])).start()

    def _do_sub(self, req_json, ws: WebSocket):
        logging.info('subscription requested')
        # get sub_id and filter fro the json
        if len(req_json) <= 1:
            raise NostrCommandException('REQ command missing sub_id')
        sub_id = req_json[1]
        # if we don't get a filter default to {} rather than error?
        # did this because loquaz doesnt supply so assuming this is permited
        filter = {}
        if len(req_json) > 2:
            filter = req_json[2:]
            # raise NostrCommandException('REQ command missing filter')

        # this user already subscribed under same sub_id
        if sub_id in self._ws[ws]['subs']:
            raise NostrCommandException('REQ command for sub_id that already exists - %s' % sub_id)
        # this sub would put us over max for this socket
        sub_count = len(self._ws[ws]['subs'])
        if sub_count >= self._max_sub:
            raise NostrCommandException('REQ new sub_id %s not allowed, already at max subs=%s' % (sub_id, self._max_sub))

        self._ws[ws]['subs'][sub_id] = {
            'id': sub_id,
            'filter': filter
        }

        logging.info('Relay::_do_sub subscription added %s (%s)' % (sub_id, filter))

        # post back the pre existing
        evts = self._store.get_filter(filter)
        def get_sub_func(ws, sub_id, lock, evts):
            def my_func():
                [self._send_event(ws, sub_id, c_evt, lock)
                 for c_evt in evts]

                # NIP15 support
                if self._enable_nip15:
                    self._send_eose(ws, sub_id, lock)

            return my_func

        # unsafe -?? make it safe
        Greenlet(get_sub_func(ws, sub_id, self._ws[ws]['send_lock'], evts)).start()

        # for c_evt in evts:
        #     self._send_event(ws, sub_id, c_evt, self._ws[ws]['send_lock'])

    def _do_unsub(self, req_json, ws: WebSocket):
        logging.info('un-subscription requested')
        if len(req_json) <= 1:
            raise NostrCommandException('REQ command missing sub_id')

        # get sub_id from json
        sub_id = req_json[1]
        # user isn't subscribed anyhow, nothing to do
        if sub_id not in self._ws[ws]['subs']:
            raise NostrCommandException('CLOSE command for sub_id that not subscribed to, nothing to do - %s' % sub_id)

        # remove the sub
        del self._ws[ws]['subs'][sub_id]
        # not actual exception but this will send notice back that sub_id has been closed, might be useful to client?
        raise NostrCommandException('CLOSE command for sub_id %s - success' % sub_id)

    def _do_send(self, ws: WebSocket, data, lock: BoundedSemaphore):
        try:
            with lock:
                ws.send(json.dumps(data))
        except Exception as e:
            logging.info('Relay::_do_send error: %s' % e)

    def _send_event(self, ws: WebSocket, sub_id, evt, lock: BoundedSemaphore):
        self._do_send(ws=ws,
                      data=[
                          'EVENT',
                          sub_id,
                          evt
                      ],
                      lock=lock)


    def _send_eose(self, ws: WebSocket, sub_id, lock: BoundedSemaphore):
        """
        NIP15 send end of stored events notice
        https://github.com/nostr-protocol/nips/blob/master/15.md
        """
        self._do_send(ws=ws,
                      data=[
                          'EOSE', sub_id
                      ],
                      lock=lock)

    def _NIP11_relay_info_route(self):
        """
        as https://github.com/nostr-protocol/nips/blob/master/11.md
        :return:
        """
        return self._relay_information

#    below are some routes that can be added to the monstr relay and give methods to access data via standard url in the
#    webbrowser. Useful for testing, maybe also for other things?
#    the can be added by doing relay.app.route('/route_url', callback=route_method(relay))


def event_route(r: Relay):
    """
        adds a route to access events by id for example:

            relay.app.route('/e', callback=route_method(relay))
            http://host:port/e?id=<event_id> will now return events
    """
    def the_route():
        id = request.params.id
        try:
            if id == '':
                raise ValueError('id field is required')
            elif not Event.is_event_id(id):
                raise ValueError('id: %s is not a valid event id' % id)
            else:
                ret = {}
                evts = r.store.get_filter({
                    'ids': id
                })
                if evts:
                    ret = evts[0]

        except ValueError as ve:
            ret = str(ve)

        return ret

    return the_route


def filter_route(r: Relay):
    """
        similar to the id route but more flexible with a small subset of
        monstr filter availabe as if doing a REQ to the relay directly

            relay.app.route('/req', callback=route_method(relay))
            http://host:port/req?kinds=0?authors=some_key
    """
    def the_route():

        def _get_param(name: str, mutiple=False, numeric=False):

            def _make_numeric(val):
                n_val = None
                try:
                    n_val = int(val)
                except Exception as e:
                    pass

                return n_val

            field_vals = None
            if name in request.query:
                r_val = request.query[name]
                if mutiple:
                    r_val = r_val.split(',')
                else:
                    r_val = [r_val]

                if numeric:
                    r_val = [_make_numeric(r_val) for r_val in r_val if _make_numeric(r_val) is not None]

                if r_val:
                    if mutiple:
                        field_vals = r_val
                    else:
                        field_vals = r_val[0]

            return field_vals

        limit = _get_param('limit', mutiple=False, numeric=True)
        if limit is None or limit > 100:
            limit = 100

        authors = _get_param('authors', mutiple=True, numeric=False)
        kinds = _get_param('kinds', mutiple=True, numeric=True)
        ids = _get_param('ids', mutiple=True, numeric=False)

        filter = {
            'limit': limit
        }
        if authors:
            filter['authors'] = authors
        if kinds:
            filter['kinds'] = kinds
        if ids:
            filter['ids'] = ids

        evts = r.store.get_filter(filter)
        ret = None
        if evts:
            ret = {
                'events': evts
            }

        return ret

    return the_route