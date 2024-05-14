"""
    web socket netork stuff for our monstr client

    TODO: change timers to check the actual time that has passed

"""
from __future__ import annotations

import copy
# from typing import Callable
import logging
import aiohttp
try:
    from aiohttp_socks import SocksConnector
except:
    pass
import asyncio
import json
from typing import Callable
from json import JSONDecodeError
from datetime import datetime
from monstr.util import util_funcs
from monstr.event.event import Event
from monstr.signing import SignerInterface, BasicKeySigner
from monstr.encrypt import Keys


class QueryTimeoutException(Exception):
    pass


class QueryLostConnectionException(Exception):
    pass


class Client:
    """
        rewrite of client using asyncio
    """
    def __init__(self,
                 relay_url: str,
                 on_connect: Callable = None,
                 on_status: Callable = None,
                 on_eose: Callable = None,
                 on_notice: Callable = None,
                 on_ok: Callable = None,
                 on_auth: Callable = None,
                 read: bool = True,
                 write: bool = True,
                 timeout: int = 5,
                 ping_timeout: int = 30,
                 query_timeout: int = 10,
                 eose_timeout: int = 10,
                 ssl=None):

        # url of relay to connect
        self._url = relay_url

        # open subscriptions
        self._subs = {}

        # read, subs will return events
        self._read = read
        # writes, calls to publish will do sends
        self._write = write

        # NIP11 info for the relay we're connected to
        self._relay_info = None
        # this will force self._relay_info to be populated...
        # if this fails we just set as {} currently... probably we should do better

        # functions called at various points in life cycle of connection

        # connect and on reconnect
        self._on_connect = on_connect
        # change in connection state, e.g. lost con or ping update...
        self._on_status = on_status
        # on recieveng the eose event
        self._on_eose = on_eose
        # on recieving any notice events from the relay
        self._on_notice = on_notice
        # nip-20 command infos
        self._on_ok = on_ok
        # nip42 authentication
        self._on_auth = on_auth

        # set true if we're currently connected
        self._is_connected = False
        # incremented on each connect
        self._connected_count = 0
        # incremented each time we fail to connect, set back to 0 on successful connection
        self._fail_count = 0
        # set on failure to connect and set to none when connected ok
        self._last_err = None
        # time that we last connected
        self._last_connect = None

        # queue for postings, events and sub requests are put on here before being sent
        self._publish_q: asyncio.Queue = asyncio.Queue()

        # set True once run() method is called
        self._run = False

        # default times TODO: check what happens if None... assume in most cases this would be indefinate?
        # used for open_timeout/close_timeout of websockets.connect
        self._timeout = timeout

        # as aiohttp see https://docs.aiohttp.org/en/stable/client_reference.html
        # set False to disable SSL verification checks
        # default is None where ssl.create_default_context() by aiohttp
        self._ssl = ssl

        # ping_interval and ping_timeout of websockets.connect set to this
        self._ping_timeout = ping_timeout
        # timeout default for query method
        self._query_timeout = query_timeout
        # if we didn't get an eose after this time we'll force it ourself and over
        # events will be recieved as on_event, set None if you don't want this
        # should set this higher than any resonable period you'd expect for your queries
        self._eose_timeout = eose_timeout

    async def run(self):
        self._run = True
        reconnect_delay = 1
        while self._run:
            try:
                if self._relay_info is None:
                    await self.get_relay_information()
                async with aiohttp.ClientSession(connector=self._get_tor_connector(self.url)) as my_session:
                    async with my_session.ws_connect(self._url,
                                                     timeout=self._timeout,
                                                     heartbeat=self._ping_timeout,
                                                     ssl=self._ssl) as ws:

                        self._is_connected = True
                        self._connected_count += 1
                        self._last_err = None
                        self._fail_count = 0
                        self._last_connect = datetime.now()

                        reconnect_delay = 1
                        logging.debug('Client::run connected %s' % self._url)
                        if self._on_connect:
                            self._on_connect(self)

                        self._do_status()

                        consumer_task = asyncio.create_task(self._my_consumer(ws))
                        producer_task = asyncio.create_task(self._my_producer(ws))
                        terminate_task = asyncio.create_task(self.my_terminate(ws))

                        done, pending = await asyncio.wait([consumer_task,
                                                           producer_task,
                                                           terminate_task],
                                                           return_when=asyncio.FIRST_EXCEPTION)

                        # clean up
                        for task in pending:
                            task.cancel()

            except ConnectionError as ce:
                self._last_err = str(ce)
                logging.debug('Client::run %s' % ce)
            except Exception as e:
                self._last_err = str(e)
                logging.debug('Client::run %s' % e)

            self._fail_count += 1
            self._is_connected = False
            self._do_status()

            await asyncio.sleep(reconnect_delay)
            reconnect_delay = reconnect_delay * 2
            if reconnect_delay > 60:
                reconnect_delay = 60

    def _do_status(self):
        if self._on_status:
            try:
                self._on_status(self.status)
            except Exception as e:
                logging.debug('Client::_do_status - %s' % e)

    async def wait_connect(self, timeout=None):
        # note that if this timeouts it doesn't stop the underlying run method, so we'll continue to try to
        # establish a connection unless you end the client (or your're using with where it'll be ended automatically)
        wait_time = 0
        while not self.connected:
            await asyncio.sleep(0.1)
            wait_time += 0.1
            if timeout and int(wait_time) >= timeout:
                raise ConnectionError('Client::wait_connect timed out waiting for connection after %ss' % timeout)

    async def _my_consumer(self, ws: aiohttp.ClientWebSocketResponse):
        while True:
            self._on_message(await ws.receive_json())
        # raise ConnectionError('Client::_my_consumer - server has closed the websocket')

    def _on_message(self, message):
        # null/None message?
        if not message:
            return

        type = message[0]
        if type == 'EVENT':
            if len(message) >= 1:
                sub_id = message[1]
                if self._read:
                    self._do_events(sub_id, message)
            else:
                logging.debug(f'Client::_on_message - not enough data in EVENT message - {message}')

        elif type == 'NOTICE':
            if len(message) >= 1:
                err_text = message[1]
                # check what other relays do... maybe they'll be some standard that gives more info
                # as is can't do that much unless we want to look at the text and all realys might have different
                # text for the same thing so...
                logging.debug(f'NOTICE!! {err_text}')
                if self._on_notice:
                    self._on_notice(self, err_text)
            else:
                logging.debug(f'Client::_on_message - not enough data in NOTICE message - {message}')
        elif type == 'OK':
            self._do_command(message)
        elif type == 'EOSE':
            if len(message) >= 1:
                sub_id = message[1]
                self._do_eose(sub_id)
            else:
                logging.debug(f'Client::_on_message - not enough data in EOSE message - {message}')
        elif type == 'AUTH':
            if len(message) >= 1:
                challenge = message[1]
                if self._on_auth is not None:
                    self._do_auth(challenge)
                else:
                    logging.debug('Client::_on_message - recieved AUTH but no on_auth handler ')
            else:
                logging.debug(f'Client::_on_message - not enough data in AUTH message - {message}')

        else:
            logging.debug(f'Network::_on_message unexpected type {type}')

    def _do_command(self, message):
        try:
            if self._on_ok:
                if len(message) < 3:
                    raise Exception(f'Client::_do_command - not enough data in OK message - {message}')

                event_id = message[1]
                if not Event.is_event_id(event_id):
                    raise Exception(f'Client::_do_command - OK message with invalid event_id - {message}')

                success = message[2]
                if not isinstance(success, bool):
                    raise Exception(f'Client::_do_command - OK message success not valid value - {message}')

                msg = message[3]
                self._on_ok(self, event_id, success, msg)
            else:
                logging.debug(f'Client::_do_command - OK message - {message}')
        except Exception as e:
            logging.debug(f'Client::_do_command error sending message {e}')

    def _do_events(self, sub_id, message):
        the_evt: Event
        if not self.have_sub(sub_id):
            logging.debug(
                'Client::_on_message event for subscription with no handler registered subscription : %s\n event: %s' % (
                    sub_id, message))
            return

        if self.have_sub(sub_id):
            the_sub = self._subs[sub_id]
            the_evt = Event.load(message[2])
            # bad json??
            if the_evt is None:
                return
            # still receiving stored events
            if the_sub['is_eose'] is False:
                the_sub['events'].append(the_evt)
                the_sub['last_event'] = datetime.now()

            # receiving adhoc events
            else:
                try:
                    for c_handler in the_sub['handlers']:
                        try:

                            if callable(c_handler):
                                c_handler(self, sub_id, the_evt)
                            # should be a class with do_event defined (e.g. extends client.event_handlers.EventHandler)
                            else:
                                c_handler.do_event(self, sub_id, the_evt)

                        except Exception as e:
                            logging.debug(f'Client::_do_events in handler {c_handler} - {e}')

                except Exception as e:
                    logging.debug(f'Client::_do_events error {e}')

    def _do_eose(self, sub_id):
        # maybe it took to long and we already force eose or else sub that already got unsubscribed?
        if not self.have_sub(sub_id):
            logging.debug('Client::_on_message EOSE event for unknown sub_id?!??!! - %s' % sub_id)
            # self.unsubscribe(sub_id)
        else:
            the_sub = self._subs[sub_id]
            if the_sub['is_eose'] is True and (self._on_eose or the_sub['eose_func']):
                logging.debug(f'end of stored events for {sub_id} - already seen, maybe it was force timedout?')
            else:
                # call the EOSE func if any
                # sub has its own eose
                try:
                    if the_sub['eose_func'] is not None:
                        the_sub['eose_func'](self, sub_id, the_sub['events'])
                    # client level EOSE
                    elif self._on_eose:
                        self._on_eose(self, sub_id, the_sub['events'])
                except Exception as e:
                    logging.debug(f'Client::_on_eose - error in eose func {e}')

                logging.debug(f'end of stored events for {sub_id} - {len(the_sub["events"])} events received')

                # clear cause we won't need any longer
                self._subs[sub_id]['events'] = []
                # mark the eose as haveing taken place
                self._subs[sub_id]['is_eose'] = True

    def _do_auth(self, challenge: str):
        try:
            self._on_auth(self, challenge)
        except Exception as e:
            print(e)
            logging.debug(f'Client::_do_auth - error {e}')

    async def _my_producer(self, ws: aiohttp.ClientWebSocketResponse):
        while True:
            cmd = await self._publish_q.get()
            await ws.send_str(cmd)
            # TODO - here we could add an event that message got sent for example in case of event we'd know that
            #  it'd been senf at this point

    async def my_terminate(self, ws: aiohttp.ClientWebSocketResponse):
        ws_closed = False
        while not ws_closed:
            await asyncio.sleep(0.1)
            if self._run is False:
                await ws.close()
                ws_closed = True

    def end(self):
        self._run = False

    @property
    def running(self) -> bool:
        return self._run

    def publish(self, evt: Event):
        if self._write:
            logging.debug('Client::publish - %s', evt.data())
            self._publish_q.put_nowait(
                json.dumps([
                    'EVENT', evt.data()
                ])
            )

    async def auth(self, signer: SignerInterface | Keys, challenge: str):
        # better to use signer but if we just got keys we'll turn into a BasicKeySigner
        if isinstance(signer, Keys):
            signer = BasicKeySigner(signer)

        auth_event = Event(kind=Event.KIND_AUTH,
                           tags=[
                               ['relay', self.url],
                               ['challenge', challenge]
                           ],
                           pub_key=await signer.get_public_key())

        await signer.sign_event(auth_event)

        self._publish_q.put_nowait(
            json.dumps([
                'AUTH', auth_event.data()
            ])
        )

    async def query(self,
                    filters: object = None,
                    do_event: callable = None,
                    timeout=None,
                    wait_connect=False,
                    **kargs) -> [Event]:
        """
        do simple one off queries to a given relay
        :param timeout:
        :rtype: object
        :param filters:
        :param do_event:
        :param wait_connect:
        :return:
        """
        is_done = False
        ret = None
        total_time = 0


        # fix up filters
        if filters is None:
            filters = []
        elif isinstance(filters, dict):
            filters = [filters]

        # use default timeout for client
        if timeout is None:
            timeout = self._query_timeout

        def my_done(the_client: Client, sub_id: str, events: [Event]):
            nonlocal is_done
            nonlocal ret
            ret = events
            if do_event is not None:
                do_event(self, sub_id, events)
            is_done = True

        def cleanup():
            self.unsubscribe(sub_id)

        # if not connected don't even bother trying to sub
        if not self.connected:
            if wait_connect and 'fail_count' in self.status and self.status['fail_count'] > 0:
                raise QueryLostConnectionException(f'Client::query - not connected to relay {self.url}')

            # we'll give it 1s to connect...
            await self.wait_connect(1)
            total_time = 1

        sub_id = self.subscribe(filters=filters, eose_func=my_done)

        sleep_time = 0.1
        while is_done is False and self._run is True:
            if not self.connected:
                raise QueryLostConnectionException(f'Client::query - lost connection during query {self.url}')
            if ret is None and timeout and total_time >= timeout:
                cleanup()
                raise QueryTimeoutException(f'Client::query timeout- {self.url}')

            await asyncio.sleep(sleep_time)
            total_time += sleep_time

        cleanup()
        return ret

    async def query_until(self,
                          until_date: datetime | int,
                          filters: object = None,
                          do_event: callable = None,
                          timeout=None,
                          wait_connect=False,
                          **kargs) -> [Event]:
        """
            query as above except that it'll scan back until until_date
            it's possible that it might also be useful to scan forward but to keep thing simple backward only
            (if you supply a since in the query it'll be back from that point)
        """

        # fix filters
        if filters is None:
            filters = []
        elif isinstance(filters, dict):
            filters = [filters]

        # because we're going to mod
        filters = copy.deepcopy(filters)

        # make sure until_date is int
        if isinstance(until_date, datetime):
            until_date = util_funcs.date_as_ticks(until_date)

        ret = []
        done = False
        old_event = None

        while done is False:
            c_evts = await self.query(filters)

            # run out of events
            if not c_evts:
                done = True
            else:
                # events should be ordered from relay but just incase....
                c_evts.sort()

                # cut any events upto and including anylast old event if we had one
                if old_event:
                    for back_seek in range(0, len(c_evts)):
                        # the cut off event - last oldest should be the newest in this set
                        if c_evts[back_seek].id == old_event.id:
                            # cut any events before we reach the id of last event
                            c_evts = c_evts[back_seek + 1:]
                            break

                # if no events then we're done
                if not c_evts:
                    done = True
                else:
                    # set an oldest event for next query
                    old_event = c_evts[len(c_evts) - 1]
                    oldest_date = old_event.created_at_ticks

                    # if oldest date is lest then until date then we'll query again
                    if oldest_date < until_date:
                        # all dates are valid to ret
                        ret = ret + c_evts
                        # mod each filter in base query to have an until date
                        for c_f in filters:
                            c_f['until'] = oldest_date

                    # oldest date us after until, append only event before until date
                    else:
                        done = True
                        for c_evt in c_evts:
                            if c_evt.created_at_ticks < until_date:
                                ret.append(c_evt)
                            else:
                                break

        return ret

    def subscribe(self, sub_id=None, handlers=None, filters={}, eose_func=None):
        """
        :param sub_id: if none a rndish 4digit hex sub_id will be given
        :param handler: single or [] of handlers that'll get called for events on sub
        :param filters: filter to be sent to relay for matching events were interested in
        see https://github.com/fiatjaf/nostr/blob/master/nips/01.md
        :return: sub_id
        """

        the_req = ['REQ']

        # no sub given, ok we'll generate one
        if sub_id is None:
            sub_id = util_funcs.get_rnd_hex_str(4)
        the_req.append(sub_id)
        if isinstance(filters, dict):
            filters = [filters]
        the_req = the_req + filters

        the_req = json.dumps(the_req)
        logging.debug(f'Client::subscribe - {the_req}')

        # make sure handler is list
        if handlers is None:
            handlers = []
        # added ClientPool else we end up itering over Clients and thinking they're handlers!
        elif not hasattr(handlers, '__iter__') or isinstance(handlers, ClientPool):
            handlers = [handlers]

        # if same id already exists its just overidden
        self._subs[sub_id] = {
            'handlers': handlers,
            # confusingly this is false whilst we're doing the eose and is set true once its done
            # anyway, if no eose func or self._on_eose then it'll be set True straight away
            # and we go straight to events coming in as received
            'is_eose': eose_func is None and self._on_eose is None,
            'eose_func': eose_func,
            'events': [],
            'start_time': datetime.now(),
            'last_event': None
        }

        self._publish_q.put_nowait(the_req)

        async def eose_timeout():
            await asyncio.sleep(self._eose_timeout)
            if self.have_sub(sub_id) and self._subs[sub_id]['is_eose'] is False:
                self._do_eose(sub_id)

        # start eose timeout if needed, it'll force eose if we didn't see EOSE from relay
        if self._eose_timeout and self._subs[sub_id] is False:
            asyncio.create_task(eose_timeout())


        return sub_id

    def unsubscribe(self, sub_id):
        if not self.have_sub(sub_id):
            return
        self._publish_q.put_nowait(json.dumps(['CLOSE', sub_id]))

        # remove ths sub our side...we may recieve events for this sub for some time
        # but they'll be ignored
        del self._subs[sub_id]

    def have_sub(self, sub_id: str):
        return sub_id in self._subs

    @property
    def url(self):
        return self._url

    @property
    def connected(self):
        return self._is_connected

    @property
    def connected_count(self):
        return self._connected_count

    @property
    def fail_count(self):
        return self._fail_count

    @property
    def last_connect(self):
        self._last_connect

    @property
    def last_err(self):
        return self._last_err

    @property
    def status(self):
        return {
            'connected': self.connected,
            'connected_count': self.connected_count,
            'fail_count': self.fail_count,
            'last_connect': self.last_connect,
            'last_err': self.last_err
        }

    def _get_tor_connector(self, url) -> 'SocksConnector':
        """
        if tor onion then we need to use a connector, for now we just hope that tor service proxy
        is running at default location
        raise err requesting pip install aiohttp_socks
        """
        ret = None
        if url.lower().replace('/', '').endswith('.onion'):
            try:
                ret = SocksConnector.from_url('socks5://localhost:9050', rdns=True)
            except NameError as e:
                raise ModuleNotFoundError(
                    f'requested connection to onion {url} but can\'t create SocksConnector - try pip install aiohttp_socks')

        return ret

    async def get_relay_information(self):
        info_url = self._url.replace('ws:', 'http:').replace('wss:', 'https:')

        async with aiohttp.ClientSession(headers={
            'Accept': 'application/nostr+json'
        }, connector=self._get_tor_connector(info_url)) as session:
            try:
                async with session.get(info_url, ssl=self._ssl) as response:
                    if response.status == 200:
                        try:
                            self._relay_info = json.loads(await response.text())
                        except JSONDecodeError as je:
                            logging.debug(f'Client::get_relay_information bad response:{response.content}')
            except Exception as e:
                # note we just continue without relay specific info... maybe do some better fullback
                logging.debug(f'Client::get_relay_information connection problem: {e}')

    @property
    def relay_information(self):
        return self._relay_info

    # @property
    # def relay_supports_eose(self):
    #     # assumed False if we haven't been able to get relay info
    #     ret = False
    #     if self._relay_info:
    #         ret = 'supported_nips' in self._relay_info \
    #               and 15 in self._relay_info['supported_nips']
    #     return ret

    @property
    def read(self) -> bool:
        return self._read

    @read.setter
    def read(self, is_read:bool):
        self._read = is_read

    @property
    def write(self) -> bool:
        return self._write

    @read.setter
    def read(self, is_write: bool):
        self._write = is_write

    def set_on_status(self, on_status: Callable):
        self._on_status = on_status

    def set_on_eose(self, on_eose: Callable):
        self._on_eose = on_eose

    def set_on_connect(self, on_connect: Callable):
        self._on_connect = on_connect

    def set_on_notice(self, on_notice: Callable):
        self._on_notice = on_notice

    def set_on_ok(self, on_ok: Callable):
        self._on_ok = on_ok

    def set_on_auth(self, on_auth: Callable):
        self._on_auth = on_auth

    async def __aenter__(self):
        asyncio.create_task(self.run())
        try:
            await self.wait_connect(timeout=self._timeout)
        except Exception as e:
            # never got running! we need to call end else it'll linger in the background
            # as a zombie forever trying to connect as __aexit__ won't get called
            # because of the exception
            self.end()
            raise e
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.end()


class ClientPool:
    """
        a collection of Clients so we can subscribe/post to a number of relays with single call
        can pass in
            [relay_url,...]     -   Client objs created for each url
            [Client,...]        -   alrady created objs
            [
                {
                    client : relay_url,
                    read : bool
                    write : bool
                }
            ]
            also mix of the above
            where read/write not passed in they'll be True

    """

    def __init__(self,
                 clients: str | Client,
                 on_connect: Callable = None,
                 on_status: Callable = None,
                 on_eose: Callable = None,
                 on_notice: Callable = None,
                 on_auth: Callable = None,
                 timeout: int = None,
                 min_connect: int = 1,
                 error_min_con_fail: bool=False,
                 **kargs
                 ):

        # Clients (Relays) we connecting to
        self._clients = {}

        # subscription event handlers keyed on sub ids
        self._handlers = {}

        # we just set all the clients methods to whatever we have - except on status where ClientPool
        # actually does status over all Clients - is it worth keeping these local refs when we never use
        # ourself?
        self._on_connect = on_connect
        self._on_eose = on_eose
        self._on_notice = on_notice
        self._on_auth = on_auth

        # set true once run gets called
        self._run = False

        # merge of status from pool, for example a single client connected means we consider connected to be True
        # last con will be newest of any relay we have etc....
        # indivdual relay status also stored here keyed on url
        self._status = {
            'connected': False,
            'relays': {}
        }
        # if want to listen for status changes from this group of relays
        self._on_status = on_status

        # for whatever reason using pool but only a single client handed in
        if isinstance(clients, str):
            clients = [clients]

        # ssl if disabled - will be disabled for all clients
        # if created from url str
        self._ssl = None
        if 'ssl' in kargs:
            self._ssl = kargs['ssl']

        for c_client in clients:
            try:
                self.add(c_client)
            except Exception as e:
                logging.debug('ClientPool::__init__ - %s' % e)

        # connection timeout values for wait_connect - these are always used if using context
        # can be overridden using wait_connect manually

        # max wait to estabish connection
        self._timeout = timeout
        # min n of clients we consider connected
        self._min_connect = min_connect
        # raise an error if we didn't reach min n cons or accept anynumber after timeout
        self._error_min_con_fail = error_min_con_fail

    def add(self, client, auto_start=False) -> Client:
        """
        :param auto_start: start the client if the pool is started
        :param client: client, url str or {
            'client': url
            read: true/false
            write: true/false
        }
        :return: Client
        """
        the_client: Client = None
        run_task = None

        if isinstance(client, str):
            # read/write default True
            the_client = Client(client,
                                on_connect=self._on_connect,
                                on_eose=self._on_eose,
                                on_notice=self._on_notice,
                                on_auth=self._on_auth,
                                ssl=self._ssl)
        elif isinstance(client, Client):
            the_client = client
            the_client.set_on_connect(self._on_connect)
            the_client.set_on_notice(self._on_notice)
            the_client.set_on_eose(self._on_eose)
            the_client.set_on_auth(self._on_auth)

        elif isinstance(client, dict):
            # read/write mode for client
            read = True
            if 'read' in client:
                read = client['read']
            write = True
            if 'write' in client:
                write = client['write']

            # unless defined ssl will be as pool as a whole - usually should be None for verifying
            ssl = self._ssl
            if 'ssl' in client:
                ssl = client['ssl']

            client_url = client['client']

            the_client = Client(client_url,
                                on_connect=self._on_connect,
                                on_eose=self._on_eose,
                                on_notice=self._on_notice,
                                on_auth=self._on_auth,
                                read=read,
                                write=write,
                                ssl=ssl)

        if the_client.url in self._clients:
            raise Exception(f'ClientPool::add - {the_client.url} attempted to add Client that already exists')

        # TODO: here we should go through handlers and add any subscriptions if they have be added via subscribe
        #  method. Need to change the subscrbe to keep a copy of the filter.. NOTE that normally it's better
        #  to do subscriptions in the on connect method anyhow when using a pool

        # we're started so start the new client, only happens if the pool is running
        if auto_start is True and self._run:
            # starts it if not already running, if it's started and we're not should we do anything?
            run_task = asyncio.create_task(the_client.run())

        # for monitoring the relay connection
        def get_on_status(relay_url):
            def on_status(status):
                self._on_pool_status(relay_url, status)
            return on_status

        the_client.set_on_status(get_on_status(the_client.url))

        self._clients[the_client.url] = {
            'client': the_client,
            'task': run_task
        }

    def remove(self, client_url: str, auto_stop=True):
        if client_url not in self._clients:
            raise Exception('ClientPool::remove attempt to remove client that hasn\'t been added')

        the_client: Client = self._clients[client_url]
        if auto_stop:
            the_client.end()

        with self._clients_lock:
            the_client.set_status_listener(None)
            del self._status['relays'][client_url]
            del self._clients[client_url]

        self._update_pool_status()
        if self._on_status:
            self._on_status(self._status)

        return the_client

    def set_read_write(self, client_url, read=None, write=None):
        if client_url not in self._clients:
            raise Exception('ClientPool::remove attempt to set read/write for client that hasn\'t been added')

        the_client: Client = self._clients[client_url]
        if read is not None:
            the_client.read = read
        if write is not None:
            the_client.write = write

        self._update_pool_status()
        if self._on_status:
            self._on_status(self._status)

        return the_client

    def set_on_connect(self, on_connect: Callable):
        self._on_connect = on_connect
        for c_client in self.clients:
            c_client.set_on_connect(on_connect)

    def set_on_eose(self, on_eose: Callable):
        self._on_eose = on_eose
        for c_client in self.clients:
            c_client.set_on_eose(on_eose)

    def set_on_notice(self, on_notice: Callable):
        self._on_notice = on_notice
        for c_client in self.clients:
            c_client.set_on_notice(on_notice)

    def set_on_auth(self, on_auth: Callable):
        self._on_auth = on_auth
        for c_client in self.clients:
            c_client.set_on_auth(on_auth)

    def _on_pool_status(self, relay_url, status):
        # the status we return gives each individual relay status at ['relays']
        self._status['relays'][relay_url] = status
        self._update_pool_status()
        if self._on_status:
            self._on_status(self._status)

    def _update_pool_status(self):
        # high level to mimic single relay, any single relay connected counts as connected
        # we also add a count/connected count for use by caller
        n_status = {
            # n of n - don't exist in individual relay status
            'relay_count': 0,
            'connect_count': 0,
            # emulating single... as long as a single client is connected all will look ok unless
            # you take the effort to look through each individual relay
            'connected': False,
            # in this case this is some of all clients n connection count
            'connected_count': 0,
            'last_connect': None,
            'fail_count': None
        }

        c_relay: Client
        for c_relay in self.clients:
            n_status['relay_count'] += 1
            if c_relay.connected:
                n_status['connected'] = True
                n_status['fail_count'] = 0
                n_status['connect_count'] += 1
                n_status['connected_count'] += c_relay.connected_count
                n_status['last_err'] = None

            # only fill in err counts if we're not connected (wiped if we find we're connected later)
            # last_err comes from relay with highest fail_count
            if not n_status['connected']:
                if n_status['fail_count'] is None or c_relay.fail_count > n_status['fail_count']:
                    n_status['fail_count'] = c_relay.fail_count
                    n_status['last_err'] = c_relay.last_err

            # last connect taken as most recent relay we have a connection from
            if c_relay.last_connect:
                if n_status['last_connect'] is None or c_relay.last_connect > n_status['last_connect']:
                    n_status['last_connect'] = c_relay.last_connect

        self._status.update(n_status)

    def set_on_status(self, on_status):
        self._on_status = on_status

    @property
    def status(self):
        return self._status

    @property
    def connected(self):
        return self._status['connected']

    # methods work on all but we'll probably want to be able to name on calls
    async def run(self):
        if self._run:
            raise Exception('ClientPool::run - already running!')

        self._run = True

        # start async task for each client
        for url in self._clients:
            client_info = self._clients[url]
            if client_info['task'] is None:
                client_info['task'] = asyncio.create_task(client_info['client'].run())
                # await client_info['client'].wait_connect()


        # wait forever
        while self._run:
            await asyncio.sleep(0.1)

    def end(self):
        for c_client in self:
            c_client.end()
        self._run = False

    def subscribe(self, sub_id=None, handlers=None, filters={}):
        c_client: Client

        # same sub_id used for each client, where not given it'll be the generated id from the first client
        for c_client in self:
            sub_id = c_client.subscribe(sub_id, self, filters)

        # add handlers if any given - nothing happens on receiving events if not
        if handlers:
            if not hasattr(handlers, '__iter__'):
                handlers = [handlers]
            self._handlers[sub_id] = handlers
        return sub_id

    def unsubscribe(self, sub_id):
        c_client: Client

        if not self.have_sub(sub_id):
            return

        for c_client in self.clients:
            c_client.unsubscribe(sub_id)

        del self._handlers[sub_id]

    def have_sub(self, sub_id: str):
        return sub_id in self._handlers

    async def _query(self,
                     filters: [] = None,
                     do_event: callable = None,
                     wait_connect: bool = False,
                     emulate_single: bool = True,
                     timeout: int = None,
                     on_complete: callable = None,
                     until_date: int = None
                     ):
        """
        similar to the query func, if you don't supply a ret_func we try and act in the same way as a single
        client would but wait for all clients to return and merge results into a single result with duplicate
        events removed
        probably better to supply a ret func though in which case it'll be called with the client and that clients
        results as they come in

        :param on_complete:
        :param do_event:
        :param timeout:
        :param emulate_single:
        :param wait_connect:
        :param filters:
        :param ret_func:
        :return:
        """
        c_client: Client
        client_wait = 0
        ret = {}

        async def get_q(the_client: Client):
            nonlocal client_wait
            try:
                # no until date, only one query will be done and what we get might not be everything
                # as the relay most likely applies limits event if we don't request
                if until_date is None:
                    ret[the_client.url] = await the_client.query(filters,
                                                                 do_event=do_event,
                                                                 wait_connect=wait_connect,
                                                                 timeout=timeout)

                # with an until date, we'll try and get all event suntil until date
                # this most likely will be made of multiple fetches
                else:
                    ret[the_client.url] = await the_client.query_until(until_date=until_date,
                                                                       filters=filters,
                                                                       do_event=do_event,
                                                                       wait_connect=wait_connect,
                                                                       timeout=timeout)

                # ret_func(the_client, the_client.query(filters, wait_connect=False))
            except QueryTimeoutException as toe:
                logging.debug(f'ClientPool::query timout - {toe}')
            except Exception as e:
                logging.debug(f'ClientPool::query exception - {e}')
            client_wait -= 1

            # callback that the fetch has completed
            if client_wait == 0 and on_complete:
                on_complete(Event.merge(*ret.values()))

        c_client: Client
        query_tasks = []

        for c_client in self.clients:
            if c_client.read:
                client_wait += 1
                query_tasks.append(asyncio.create_task(get_q(c_client)))

        while client_wait > 0:
            await asyncio.sleep(0.1)
            if ret and not emulate_single:
                break

        return Event.merge(*ret.values())

    def query(self,
              filters: [] = None,
              do_event: callable = None,
              wait_connect: bool = False,
              emulate_single: bool = True,
              timeout: int = None,
              on_complete: callable = None):

        return self._query(filters=filters,
                           do_event=do_event,
                           wait_connect=wait_connect,
                           emulate_single=emulate_single,
                           timeout=timeout,
                           on_complete=on_complete)

    def query_until(self,
                    until_date: datetime | int,
                    filters: [] = None,
                    do_event: callable = None,
                    wait_connect: bool = False,
                    emulate_single: bool = True,
                    timeout: int = None,
                    on_complete: callable = None):
        """
            query with backscan till until date, note if you set emulate_single False
            then you'll probably want to supply an on_compete function
        """

        return self._query(until_date=until_date,
                           filters=filters,
                           do_event=do_event,
                           wait_connect=wait_connect,
                           emulate_single=emulate_single,
                           timeout=timeout,
                           on_complete=on_complete)


    def publish(self, evt: Event):
        logging.debug(f'ClientPool::publish - {evt.data()}')
        c_client: Client

        for c_client in self:
            # c_client = self._clients[c_client]
            if c_client.write:
                try:
                    c_client.publish(evt)
                except Exception as e:
                    logging.debug(e)

    async def wait_connect(self, timeout: int=None, min_connect: int=None, error_min_con_fail: bool=None):
        """
            wait for the ClientPool to be considered connected
            the default is no timeout and we're happy as long as a single relay connects...
            probably you'd atleast want to set a timeout

            TODO: allow wait options to be set in init to be used as defaults in init
        """
        # how long we'll wait to get connection
        if timeout is None:
            timeout = self._timeout

        # are we connected, we'll exit when this is True, we're connected if connect_count >= min_connect
        # if we timeout and error_if_min is False and we have any connection we'll also count that as connected
        connected = False

        # if min_connect is 0 then we'll set it to all count of all clients
        n_clients = len(self.clients)+1
        if min_connect is None:
            min_connect = self._min_connect
        if min_connect == 0 or min_connect > n_clients:
            min_connect = n_clients

        if error_min_con_fail is None:
            error_min_con_fail = self._error_min_con_fail

        # number of connections we currently have
        connect_count = 0

        # how long we've been waiting
        wait_time = 0

        while not connected:
            # get n relays curretly connected
            if 'connect_count' in self.status:
                connect_count = self.status['connected_count']

            if connect_count >= min_connect:
                connected = True
                continue

            await asyncio.sleep(0.1)
            wait_time += 0.1

            # reached timeout...
            if timeout and int(wait_time) >= timeout:
                # we have some connections and error_if_min is False so we're happy to go
                if connect_count and error_min_con_fail is False:
                    connected = True
                # we wanted all connections so we'll raise an error
                else:
                    raise ConnectionError(f'ClientPool::wait_connect timed out waiting for connection after {timeout}s')

    def do_event(self, client: Client, sub_id: str, evt):

        # shouldn't be possible...
        if client.url not in self._clients:
            raise Exception('ClientPool::do_event received event from unexpected relay - %s WTF?!?' % client.url)

        # only do anything if relay read is True
        if self._clients[client.url]['client'].read:
            # note no de-duplication is done here, you might see the same event from mutiple relays
            if sub_id in self._handlers:
                for c_handler in self._handlers[sub_id]:
                    try:
                        if callable(c_handler):
                            c_handler(client, sub_id, evt)
                        # should be a class with do_event defined (e.g. extends client.event_handlers.EventHandler)
                        else:
                            c_handler.do_event(client, sub_id, evt)
                    except Exception as e:
                        logging.debug('ClientPool::do_event, problem in handler - %s' % e)

            else:
                # supose this might happen if unsubscribe then evt comes in...
                logging.debug(
                    'ClientPool::do_event event for subscription with no handler registered subscription : %s\n event: %s' % (
                        sub_id, evt))

    @property
    def clients(self) -> [Client]:
        return [self._clients[url]['client'] for url in self._clients]

    @property
    def running(self) -> bool:
        return self._run

    def __repr__(self):
        return self._clients

    def __str__(self):
        ret_arr = []
        for url in self._clients:
            ret_arr.append(str(self._clients[url]['client']))

        return ', '.join(ret_arr)

    def __len__(self):
        return len(self._clients)

    def __iter__(self) -> Client:
        for url in self._clients:
            yield self._clients[url]['client']

    async def __aenter__(self, test=None):
        asyncio.create_task(self.run())
        await self.wait_connect(self._timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self
