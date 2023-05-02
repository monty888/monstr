# monstr

Monstr: Python Nostr module. Python code for working with nostr.

```sh
pip install monstr
```

* A basic relay implementation for testing against locally
* Client for working with a single relay
* ClientPool for working with multiple relays
* Keys for working with and converting between hex/npub/nsec

# install
```sh
$ git clone https://github.com/monty888/monstr.git
$ cd monstr
$ # may need to install postgres - FIXME - add import [postgres] as optional as mainly we don't use
$ # and correct code not to fail if psycog2 lib isn't available
$ # on linux
$ sudo apt install postgresql automake pkg-config libtool
$ # for mac? brew install postgresql automake pkg-config libtool libffi
$ python3 -m venv venv
$ source venv/bin/activate
$ # Updated pip version for most up-to-date package discovery
$ python3 -m pip install --upgrade pip
$ # install wheel helper, if needed.
$ pip install wheel
$ # pip install '.' points to the setup.py
$ # and installs the package with its requirements.
$ pip install -r requirements.txt or pip install '.'
$ # probably required to run examples else nostr module won't be found
$ export PYTHONPATH="$PYTHONPATH:./"
```

# test `monstr` package import
```py
# create a new python shell
python3
>> import monstr
>> from monstr.encrypt import Keys
>> test = Keys()
>> Keys.is_valid_key(test.private_key_hex())
True
>>
```

Note: developed against python 3.8

# use 

### basic queries with context manager
```python

    from monstr.client.client import Client

    async with Client(url) as c:
        events = await c.query({
            'limit': 100
        })

        for c_evt in events:
            print(c_evt)
```
### basic queries without context manager

```python

    from monstr.client.client import Client

    c = Client(url)
    asyncio.create_task(c.run())
    await c.wait_connect()
    events = await c.query({
        'limit': 100
    })

    for c_evt in events:
        print(c_evt)
    c.end()
```

for more see /monstr/examples

# Contribute:

-- TODO
