"""
    web socket netork stuff for our monstr client

    TODO: change timers to check the actual time that has passed

"""
from __future__ import annotations
from typing import Callable
import logging
import aiohttp
import asyncio
import json
import random
from hashlib import md5
from json import JSONDecodeError
from datetime import datetime, timedelta
from monstr.util import util_funcs
from monstr.event.event import Event
from enum import Enum


class RunState(Enum):
    init = -1
    running = 0
    starting = 1
    stopping = 2
    stopped = 3
    failed = 4


class QueryTimeoutException(Exception):
    pass


class QueryLostConnectionException(Exception):
    pass


def _get_sub_id():
    """
    :return: creates a randomish 4digit hex to be used as sub_id if nothing supplied
    should be plenty as should only be using a few subs at most and relay will probbaly be
    restricting any more
    """
    ret = str(random.randrange(1, 1000)) + str(util_funcs.date_as_ticks(datetime.now()))
    ret = md5(ret.encode('utf8')).hexdigest()[:4]
    return ret


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
                 read: bool = True,
                 write: bool = True,
                 emulate_eose: bool = True,
                 timeout: int = 5,
                 ping_timeout: int = 30,
                 query_timeout: int = 10):

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
        # on recieveng the eose event or if emulate is true after emulation is done
        self._on_eose = on_eose
        # on recieving any notice events from the relay
        self._on_notice = on_notice
        # nip-20 command infos
        self._on_ok = on_ok
        # if relay doesn't support eose should we try and emulate it?
        # this is done by calling the eose func when we first recieve events for a sub
        # and then waiting for a delay (2s) after which we assume that is the end of stored events
        # for that sub
        self._emulate_eose = emulate_eose

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

        self._run = True

        # default times TODO: check what happens if None... assume in most cases this would be indefinate?
        # used for open_timeout/close_timeout of websockets.connect
        self._timeout = timeout

        # ping_interval and ping_timeout of websockets.connect set to this
        self._ping_timeout = ping_timeout
        # timeout default for query method
        self._query_timeout = query_timeout

    async def run(self):
        reconnect_delay = 1
        while self._run:
            try:
                if self._relay_info is None:
                    await self.get_relay_information()
                async with aiohttp.ClientSession() as my_session:
                    async with my_session.ws_connect(self._url,
                                                     timeout=self._timeout,
                                                     heartbeat=self._ping_timeout) as ws:

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
        raise ConnectionError('Client::_my_consumer - server has closed the websocket')

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
                logging.debug('Client::_on_message - not enough data in EVENT message - %s ' % message)

        elif type == 'NOTICE':
            if len(message) >= 1:
                err_text = message[1]
                # check what other relays do... maybe they'll be some standard that gives more info
                # as is can't do that much unless we want to look at the text and all realys might have different
                # text for the same thing so...
                logging.debug('NOTICE!! %s' % err_text)
                if self._on_notice:
                    self._on_notice(self, err_text)
            else:
                logging.debug('Client::_on_message - not enough data in NOTICE message - %s ' % message)
        elif type == 'OK':
            self._do_command(message)
        elif type == 'EOSE':
            if len(message) >= 1:
                sub_id = message[1]
                # if relay support nip15 you get this event after the relay has sent the last stored event
                # at the moment a single function but might be better to add as option to subscribe
                if not self.have_sub(sub_id):
                    logging.debug('Client::_on_message EOSE event for unknown sub_id?!??!! - %s' % sub_id)
                    self.unsubscribe(sub_id)

                # eose just for the func
                if self._subs[sub_id]['eose_func'] is not None:
                    self._subs[sub_id]['eose_func'](self, sub_id, self._subs[sub_id]['events'])

                # client level eose
                elif self._on_eose:
                    self._on_eose(self, sub_id, self._subs[sub_id]['events'])


                # no longer needed
                logging.debug('end of stored events for %s - %s events received' % (sub_id,
                                                                                    len(self._subs[sub_id]['events'])))
                self._subs[sub_id]['events'] = []
                self._subs[sub_id]['is_eose'] = True
            else:
                logging.debug('Client::_on_message - not enough data in EOSE message - %s ' % message)

        else:
            logging.debug('Network::_on_message unexpected type %s' % type)

    def _do_command(self, message):
        try:
            if self._on_ok:
                if len(message) < 3:
                    raise Exception('Client::_do_command - not enough data in OK message - %s ' % message)

                event_id = message[1]
                if not Event.is_event_id(event_id):
                    raise Exception('Client::_do_command - OK message with invalid event_id - %s ' % message)

                success = message[2]
                if not isinstance(success, bool):
                    raise Exception('Client::_do_command - OK message success not valid value - %s ' % message)

                msg = message[3]
                self._on_ok(self, event_id, success, msg)
            else:
                logging.debug('Client::_do_command - OK message - %s' % message)
        except Exception as e:
            logging.debug(str(e))

    def _do_events(self, sub_id, message):
        the_evt: Event
        if not self.have_sub(sub_id):
            logging.debug(
                'Client::_on_message event for subscription with no handler registered subscription : %s\n event: %s' % (
                    sub_id, message))
            return

        if self.have_sub(sub_id) and self._check_eose(sub_id, message):
            try:
                the_evt = Event.from_JSON(message[2])
                for c_handler in self._subs[sub_id]['handlers']:
                    try:
                        c_handler.do_event(self, sub_id, the_evt)
                    except Exception as e:
                        logging.debug('Client::_do_events in handler %s - %s' % (c_handler, e))

            except Exception as e:
                # TODO: add name property to handlers
                logging.debug('Client::_do_events %s' % (e))

    def _check_eose(self, sub_id, message):
        the_evt: Event
        ret = self._subs[sub_id]['is_eose']

        # these are stored events
        if ret is False:
            if self.relay_supports_eose or self._emulate_eose:
                self._subs[sub_id]['events'].append(Event.from_JSON(message[2]))
                self._subs[sub_id]['last_event'] = datetime.now()
            else:
                # eose not supported by relay and we're not emulating
                self._subs[sub_id]['is_eose'] = True
                ret = True

        return ret

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

    def publish(self, evt: Event):
        if self._write:
            logging.debug('Client::publish - %s', evt.event_data())
            self._publish_q.put_nowait(
                json.dumps([
                    'EVENT', evt.event_data()
                ])
            )

    async def query(self, filters: object = [],
                    do_event: object = None,
                    timeout=None, **kargs) -> [Event]:
        """
        do simple one off queries to a given relay
        :param timeout:
        :rtype: object
        :param filters:
        :param do_event:
        :return:
        """
        is_done = False
        ret = None
        if timeout is None:
            timeout = self._query_timeout

        def my_done(the_client: Client, sub_id: str, events: [Event]):
            nonlocal is_done
            nonlocal ret
            ret = events
            if do_event is not None:
                do_event(self, sub_id, events)
                # Greenlet(util_funcs.get_background_task(do_event, the_client, sub_id, events)).start_later(0)
            is_done = True

        def cleanup():
            self.unsubscribe(sub_id)

        # if not connected don't even bother trying to sub
        if not self.connected:
            raise QueryLostConnectionException('Client::query - not connected to relay')

        sub_id = self.subscribe(filters=filters, eose_func=my_done)

        sleep_time = 0.1
        total_time = 0
        con_count = self._connected_count

        while is_done is False:
            if con_count != self._connected_count:
                raise QueryLostConnectionException('Client::query - lost connection during query')
            if ret is None and timeout and total_time >= timeout:
                cleanup()
                raise QueryTimeoutException('Client::query timeout- %s' % self.url)

            await asyncio.sleep(sleep_time)
            total_time += sleep_time

        cleanup()
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
            sub_id = _get_sub_id()
        the_req.append(sub_id)
        if isinstance(filters, dict):
            filters = [filters]
        the_req = the_req + filters

        the_req = json.dumps(the_req)
        logging.debug('Client::subscribe - %s', the_req)

        # make sure handler is list
        if handlers is None:
            handlers = []
        # added ClientPool else we end up itering over Clients and thinking they're handlers!
        elif not hasattr(handlers, '__iter__') or isinstance(handlers, ClientPool):
            handlers = [handlers]

        self._subs[sub_id] = {
            'handlers': handlers,
            # a sub can have it's own eose, if it does it'll be called in place of the client level eose
            'is_eose': eose_func is None and self._on_eose is None,
            'eose_func': eose_func,
            'events': [],
            'start_time': datetime.now(),
            'last_event': None
        }
        # most relays support eose to hopefully this wouldn't ever be needed... it might happen
        # if we've be unable to get the relay information as we default to eose False as True
        # is worse if the relay doesn't support EOSE - we'd gather up events for an EOSE that'll never come
        if not self.relay_supports_eose and self._emulate_eose:
            logging.debug('emulating EOSE for sub_id %s' % sub_id)
            asyncio.create_task(self.eose_emulate(sub_id))
            # def my_emulate():
            #     is_wait = True
            #     from datetime import timedelta
            #     while is_wait:
            #         sub_info = self._subs[sub_id]
            #         now = datetime.now()
            #         if (sub_info['last_event'] is not None and now - sub_info['last_event'] > timedelta(seconds=2)) or \
            #                 (now - sub_info['start_time'] > timedelta(seconds=2)):
            #             is_wait = False
            #         time.sleep(1)
            #
            #     self._on_message(self._ws, json.dumps(['EOSE', sub_id]))
            # Thread(target=my_emulate).start()

        self._publish_q.put_nowait(the_req)
        return sub_id

    async def eose_emulate(self, sub_id):
        wait = True
        while wait:
            await asyncio.sleep(1)
            now = datetime.now()
            sub_info = self._subs[sub_id]
            if (sub_info['last_event'] is not None and now - sub_info['last_event'] > timedelta(seconds=2)) or \
                    (now - sub_info['start_time'] > timedelta(seconds=2)):
                wait = False

        # it's been some time since we saw a new event so fire the EOSE event
        self._on_message(['EOSE', sub_id])

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

    async def get_relay_information(self):
        async with aiohttp.ClientSession(headers={
            'Accept': 'application/nostr+json'
        }) as session:
            info_url = self._url.replace('ws:', 'http:').replace('wss:', 'https:')
            async with session.get(info_url) as response:
                if response.status == 200:
                    try:
                        self._relay_info = json.loads(await response.text())
                    except JSONDecodeError as je:
                        logging.debug('Client::get_relay_information bad response: %s' % response.content)

    @property
    def relay_information(self):
        return self._relay_info

    @property
    def relay_supports_eose(self):
        # assumed False if we haven't been able to get relay info
        ret = False
        if self._relay_info:
            ret = 'supported_nips' in self._relay_info \
                  and 15 in self._relay_info['supported_nips']
        return ret

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

    def set_on_status(self, on_status):
        self._on_status = on_status

    def set_on_eose(self, on_eose):
        self._on_eose = on_eose

    def set_on_connect(self, on_connect):
        self._on_connect = on_connect

    def set_on_notice(self, on_notice):
        self._on_notice = on_notice

    def set_on_ok(self, on_ok):
        self._on_ok = on_ok

    async def __aenter__(self):
        asyncio.create_task(self.run())
        await self.wait_connect(timeout=self._timeout)
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
                 timeout: int = None,
                 **kargs
                 ):

        # Clients (Relays) we connecting to
        self._clients = {}

        # subscription event handlers keyed on sub ids
        self._handlers = {}

        # any clients methods are just set to come back to us so these are the on_methods
        # that actually get called. Don't set the methods on the Clients directly
        self._on_connect = on_connect
        self._on_eose = on_eose
        self._on_notice = on_notice

        # our current run state
        self._state = RunState.init

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

        for c_client in clients:
            try:
                self.add(c_client)
            except Exception as e:
                logging.debug('ClientPool::__init__ - %s' % e)

        # this is the timeout used when using the with context manager, if
        # no client has connected after timeout then we'll error
        # if None we'll just wait forever until a client connects
        self._timeout = timeout

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
                                on_notice=self._on_notice)
        elif isinstance(client, Client):
            the_client = client
            the_client.set_on_connect(self._on_connect)
            the_client.set_on_eose(self._on_eose)
        elif isinstance(client, dict):
            read = True
            if 'read' in client:
                read = client['read']
            write = True
            if 'write' in client:
                write = client['write']

            client_url = client['client']
            the_client = Client(client_url,
                                on_connect=self._on_connect,
                                on_eose=self._on_eose,
                                read=read,
                                write=write)

        if the_client.url in self._clients:
            raise Exception('ClientPool::add - %s attempted to add Client that already exists' % the_client.url)

        # error if trying to add when we're stopped or stopping
        if self._state in (RunState.stopping, RunState.stopped):
            raise Exception('ClientPool::add - can\'t add new client to pool that is stopped or stoping url - %s' % the_client.url)

        # TODO: here we should go through handlers and add any subscriptions if they have be added via subscribe
        #  method. Need to change the subscrbe to keep a copy of the filter.. NOTE that normally it's better
        #  to do subscriptions in the on connect method anyhow when using a pool

        # we're started so start the new client
        if auto_start is True and self._state in (RunState.starting, RunState.running):
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

    def set_on_connect(self, on_connect):
        for c_client in self:
            c_client.set_on_connect(on_connect)

    def set_on_eose(self, on_eose):
        for c_client in self:
            c_client.set_on_eose(on_eose)

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
        if self._state != RunState.init:
            raise Exception('ClientPool::start - unexpected state, got %s expected %s' % (self._state,
                                                                                          RunState.init))

        self._state = RunState.starting
        # do starting of the clients
        for url in self._clients:
            client_info = self._clients[url]
            if client_info['task'] is None:
                client_info['task'] = asyncio.create_task(client_info['client'].run())
                # await client_info['client'].wait_connect()

        self._state = RunState.running
        # now just hang around until state is changed to stopping
        while self._state not in (RunState.stopping, RunState.stopped):
            await asyncio.sleep(0.1)

        self._state = RunState.stopped

    def end(self):
        self._state = RunState.stopping
        for c_client in self:
            c_client.end()
        self._state = RunState.stopped

    def subscribe(self, sub_id=None, handlers=None, filters={}):
        c_client: Client

        # same sub_id used for each client, wehere not given it'll be the generated id from the first client
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

    async def query(self, filters=[],
                    do_event=None,
                    wait_connect=False,
                    emulate_single=True,
                    timeout=None,
                    on_complete=None):
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
                ret[the_client.url] = await the_client.query(filters,
                                                             do_event=do_event,
                                                             wait_connect=wait_connect,
                                                             timeout=timeout)
                # ret_func(the_client, the_client.query(filters, wait_connect=False))
            except QueryTimeoutException as toe:
                logging.debug('ClientPool::query timout - %s ' % toe)
            except Exception as e:
                logging.debug('ClientPool::query exception - %s' % e)
            client_wait -= 1

            if client_wait == 0 and on_complete:
                on_complete()

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

    def publish(self, evt: Event):
        logging.debug('ClientPool::publish - %s', evt.event_data())
        c_client: Client

        for c_client in self:
            # c_client = self._clients[c_client]
            if c_client.write:
                try:
                    c_client.publish(evt)
                except Exception as e:
                    logging.debug(e)

    async def wait_connect(self, timeout=None):
        wait_time = 0
        while not self.connected:
            await asyncio.sleep(0.1)
            wait_time += 0.1
            if timeout and int(wait_time) >= timeout:
                raise ConnectionError('ClientPool::wait_connect timed out waiting for connection after %ss' % timeout)

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

    async def __aenter__(self):
        asyncio.create_task(self.run())
        await self.wait_connect(self._timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self
