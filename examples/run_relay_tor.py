import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.relay.tor import TORService

"""
    runs a relay available over tor - this won't be storing any events so all queries to it'll will return empty
    
    This should run with the torbrowser running.
    To use with the controller (without the browser up and running), make changes to 
    /etc/torr/torrc - file maybe somewhere else depending on system
    
    should contain something like ....
    #ControlPort 9051
    ## If you enable the controlport, be sure to enable one of these
    ## authentication methods, to prevent attackers from accessing it.
    #HashedControlPassword 16:775E7AE128CD63126062B2C548F5D2E515E4D15212A43288D7B32112BC
    #CookieAuthentication 1
    
    uncomment ControlPort and enable HashedControlPassword
    generate the password using:  tor --hash-password PASSWORD
    uncomment HashedControlPassword and set password to the output of above
    restart the tor service: sudo systemctl restart tor
    
    now you should be able to run without the torbrowser open if you pass the password(unhashed) in here 
"""
async def run_relay():
    port = 8081

    with TORService(relay_port=port,
                    service_dir=None,
                    password=None,
                    is_ssl=False,
                    empheral=True):
        r = Relay()
        await r.start(port=port)

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())
