import os
from monstr.util import ConfigError
import shutil

try:
    from stem.control import Controller
except Exception as e:
    pass


class TORService:

    def __init__(self, relay_port,
                 service_dir=None,
                 password: str = None,
                 is_ssl: bool = False,
                 empheral: bool = True):
        try:
            if Controller:
                pass
        except NameError as ne:
            raise ConfigError(f'No Controller class - try pip install stem')

        # the relays actual port if we were to it normally
        self._relay_port = relay_port

        # password used to auth with controller
        # best to supply - but without and if tor_browser is running we still might be ok
        # (don't quite understand the exact way this is working)
        self._password = password

        # the tor service will either be on port 80 http or 443 https
        self._service_port = 80
        if is_ssl:
            self._service_port = 443

        # create the tor service as empheral
        self._empheral = empheral

        # if not empheral then this is the directory where the hidden service will be created
        # just give the actual dir, the full path is worked out using the controller class
        # for example something like/home/monty/tor-browser/Browser/TorBrowser/Data/[service_dir]
        self._hidden_service_dir = service_dir
        if self._hidden_service_dir is None:
            self._hidden_service_dir = 'monstr_relay'

    def __enter__(self):
        # this will be default port probably 9051
        self._controller = Controller.from_port()
        if self._password is None:
            self._controller.authenticate()
        else:
            self._controller.authenticate(password=self._password)

        # address of service when we have it
        onion_addr = None

        # we'll get a new onion address each time
        if self._empheral:
            result = self._controller.create_ephemeral_hidden_service({self._service_port: self._relay_port},
                                                                      await_publication=True)

            onion_addr = result.service_id + '.onion'
        # after first create the onion address will be the same
        else:
            base_dir = self._controller.get_conf('DataDirectory', '/tmp')
            actual_dir = os.path.join(base_dir, self._hidden_service_dir)

            print(f' * Creating our hidden service {self._hidden_service_dir} in {base_dir}')
            result = self._controller.create_hidden_service(actual_dir,
                                                            self._service_port,
                                                            target_port=self._relay_port)

            onion_addr = None
            if result:
                onion_addr = result.hostname
            else:
                # probably the service already exists, try open the service_dir/hostname file
                # not sure why create_hidden_services doesn't just return that for us anyway?
                try:
                    f = open(os.path.join(actual_dir, 'hostname'), "r")
                    lines = f.readlines()
                    onion_addr = lines[0]
                except Exception as e:
                    pass

        if onion_addr:
            print(f" hidden service is available at {onion_addr}")
        else:
            print(
                f" Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")

    def __exit__(self, exc_type, exc_val, exc_tb):
        print(" * Shutting down our hidden service")
        self._controller.close()
        self._controller.remove_hidden_service(self._hidden_service_dir)
        shutil.rmtree(self._hidden_service_dir)
