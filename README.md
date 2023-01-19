# monstr

python code for working with nostr

* A basic relay implementation for testing against locally
* Client for working with a single relay
* ClientPool for working with multiple relays
* Keys for working with and converting between hex/npub/nsec

# install
> git clone https://github.com/monty888/monstr.git  
> cd monstr  
> python3 -m venv venv  
> source venv/bin/activate  
> pip install -r requirements.txt  
> -- probably required to run examples else nostr module won't be found  
> export PYTHONPATH="$PYTHONPATH:./"

Note: developed against python 3.8

# use 

basic queries with context manager
```
    async with Client(url) as c:
        events = await c.query({
            'limit': 100
        })

        for c_evt in events:
            print(c_evt)
```
manually manage context
```
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
