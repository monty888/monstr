# monstr

python code for working with nostr

* A basic relay implementation for testing against locally
* Client for working with a single relay
* ClientPool for working with multiple relays
* Keys for working with and converting between hex/npub/nsec

# install
```sh
$ git clone https://github.com/monty888/monstr.git
$ cd monstr
$ brew install postgresql automake pkg-config libtool libffi
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

# TODO

Eventually try to work how the ... python packages work, for now just copy in the folder and install the requirements.
The examples folder is not required.
