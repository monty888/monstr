# monstr

Monstr: Python Nostr module. Python code for working with nostr.

* A basic relay implementation that can be used for testing, and can be easily extended.
* Client and ClientPool classes to manage access to one or multiple relays
* Keys for working with and converting between hex/npub/nsec
* Signer classes for abstacting use of keys so for example signing could be done via hardware
* Entities for encoding and decoding NIP19 nostr entities
* NIP4 and NIP44 implemented for payload encryption
* inbox for wrapping events (TODO look into nip for gift wrapped events)

# install
```sh
git clone https://github.com/monty888/monstr.git
cd monstr
python3 -m venv venv
source venv/bin/activate
pip install .
# probably required to run examples else nostr module won't be found
export PYTHONPATH="$PYTHONPATH:./"
```
to use postgres as store psycopg2 must be installed
```sh
# install wheel helper, if needed.
pip pip install wheel
# maybe required on linux
# sudo apt install postgresql automake pkg-config libtool
# maybe required on mac
# brew install postgresql automake pkg-config libtool libffi
# now actually install psycopg2
pip install psycopg2
```

Note: developed against python 3.10.12

# use 

### keys
```python
from monstr.encrypt import Keys

# generate new keys
k = Keys()

# import existing keys, where key_str is nsec, npub or hex - assumed public
k = Keys.get_key(key_str)

# import existing hex private key
k = Keys(priv_k=key_str)
```



### run local relay
```python
import asyncio
import logging
from monstr.relay.relay import Relay

async def run_relay():
    r = Relay()
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())
```
**_NOTE:_**  By default this relay will be running at ws://localhost:8080 and not storing events


### make a post  
The following shows code to post note to the above local relay. Normally you'd use a ClientPool 
rather than Client because it's normal to post to multiple relays. It should be possible to switch between 
Client/ClientPool without any other changes in most cases.
The code shows:  
  - basic note post
  - NIP4 encrypt post or NIP44 with code change as comment
  - basic note post using signer class
```python
import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys, NIP4Encrypt
from monstr.event.event import Event
from monstr.signing import BasicKeySigner

async def do_post(url, text):
    # rnd generate some keys
    n_keys = Keys()

    async with Client(url) as c:
        # basic kind one note 
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content=text,
                      pub_key=n_keys.public_key_hex())
        n_msg.sign(n_keys.private_key_hex())
        c.publish(n_msg)
        
        # to encrypt in needs to be for someone, use these keys
        to_k = Keys('nsec1znc5uy6e342rzn420l38q892qzmkvjz0hn836hhn8hl8wmkc670qp0lk9n')
        
        # kind 4 for nip4, nip44 has no set kind so will depend
        n_msg.kind = Event.KIND_ENCRYPT
        
        # same nip4 encrypted
        my_enc = NIP4Encrypt(n_keys)    # or NIP44Encrypt(n_keys)
        # returns event we to_p_tag and content encrypted
        n_msg = my_enc.encrypt_event(evt=n_msg,
                                     to_pub_k=to_k)

        n_msg.sign(n_keys.private_key_hex())
        c.publish(n_msg)

        # or using signer send text post - better this way
        
        my_signer = BasicKeySigner(key=Keys())

        n_msg = await my_signer.ready_post(Event(kind=Event.KIND_TEXT_NOTE,
                                                 content=text))
        c.publish(n_msg)
        
        # await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    text = 'hello'

    asyncio.run(do_post(url, text))
```

### query
basic one time query to above relay
```python
import logging
import asyncio
from monstr.client.client import Client, ClientPool

# default relay if not otherwise given
DEFAULT_RELAY = 'ws://localhost:8080'
FILTER = [{
    'limit': 100
}]


async def one_off_query_client_with(relay=DEFAULT_RELAY):
    # does a one off query to relay prints the events and exits    
    async with Client(relay) as c:
        events = await c.query(FILTER)
        for c_evt in events:
            print(c_evt)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(one_off_query_client_with())
```


### subscription
Listen to posts being made to the local relay above

```python
import asyncio
import logging
import sys
from monstr.client.client import Client, ClientPool
import signal
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.util import util_funcs

tail = util_funcs.str_tails


async def listen_notes(url):
    run = True

    # so we get a clean exit on ctrl-c
    def sigint_handler(signal, frame):
        nonlocal run
        run = False
    signal.signal(signal.SIGINT, sigint_handler)

    # create the client and start it running
    c = Client(url)
    asyncio.create_task(c.run())
    await c.wait_connect()

    # just use func, you can also use a class that has a do_event
    # with this method sig, e.g. extend monstr.client.EventHandler
    def my_handler(the_client: Client, sub_id: str, evt: Event):
        print(evt.created_at, tail(evt.content,30))

    # start listening for events
    c.subscribe(handlers=my_handler,
                filters={
                   'limit': 100
                })

    while run:
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"

    asyncio.run(listen_notes(url))
```

### NIP19 Entities

```python
from monstr.entities import Entities

def show_entities():
    # nip19 encoded profile
    n_profile = 'nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p'

    # extract data
    decoded = Entities.decode(n_profile)
    print(decoded)

    # re-encode
    print(Entities.encode('nprofile', decoded))

if __name__ == "__main__":
    show_entities()
```


further examples are in the /examples directory


# Contribute:

-- TODO
