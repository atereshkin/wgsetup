import logging
import subprocess

log = logging.getLogger(__name__)


def run_locally(*args, input=None):
    log.debug(f'Running {" ".join(args)}')
    cp = subprocess.run(args, input=input, capture_output=True)
    try:
        cp.check_returncode()
    except subprocess.CalledProcessError:
        log.error(cp.stderr)
        raise
    return cp.stdout, cp.stderr


class AbstractInstaller:

    def __init__(self, runner, wg_listen_port=51290, server_address=None):
        self.run = runner
        self.wg_listen_port = wg_listen_port
        self.srv_private_key = None
        self.srv_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        self.server_address = server_address

    def install_wireguard(self):
        raise NotImplementedError()

    def get_config_path(self):
        return '/etc/wireguard/wg0.conf'  # TODO: scan for existing configs

    def generate_private_key(self):
        key, _ = self.run('wg', 'genkey')
        return key.trim()

    def get_public_key(self, private_key):
        key, _ = self.run('wg', 'pubkey', input=private_key)
        return key.trim()

    def get_server_vpn_address(self):
        return '10.12.0.1'  # TODO: make dynamic

    def get_client_vpn_address(self):
        return '10.12.0.2'  # TODO: make dynamic

    def get_subnet(self):
        return '10.12.0.2/32'  # TODO: make dynamic

    def get_server_config(self):
        cfg = '[Interface]\n'
        cfg += f'Address = {self.get_server_vpn_address()}\n'
        cfg += f'PrivateKey = {self.srv_private_key}\n'
        cfg += f'ListenPort = {self.wg_listen_port}\n\n'
        cfg += '[Peer]\n'
        cfg += f'PublicKey = {self.client_public_key}\n'
        cfg += f'AllowedIPs = {self.get_subnet()}\n'
        return cfg

    def get_client_config(self):
        cfg = '[Interface]\n'
        cfg += f'PrivateKey = {self.client_private_key}\n'
        cfg += f'Address = {self.get_client_vpn_address()}\n\n'
        cfg += '[Peer]\n'
        cfg += f'Endpoint {self.server_address}:{self.wg_listen_port}\n'
        cfg += f'PublicKey = {self.srv_public_key}\n'
        cfg += f'AllowedIPs = {self.get_subnet()}\n'
        cfg += 'PersistentKeepalive = 25\n'
        return cfg

    def install(self):
        log.debug('Installing wireguard')
        self.install_wireguard()
        log.debug('Generating server key')
        self.srv_private_key = self.generate_private_key()
        self.srv_public_key = self.get_public_key(self.srv_private_key)
        log.debug('Generating client key')
        self.client_private_key = self.generate_private_key()
        self.client_public_key = self.get_public_key(self.client_private_key)
        with open(self.get_config_path(), 'wt') as conf:
            conf.write(self.get_server_config())


class DebianInstaller(AbstractInstaller):
    def install_wireguard(self):
        self.run('apt-get', '-y', 'install', 'wireguard')


def main():
    logging.getLogger('root').setLevel(logging.DEBUG)
    i = DebianInstaller(runner=run_locally, server_address='1.2.3.4')
    i.install()
    print('*********Client config************')
    print(i.get_client_config())


if __name__ == '__main__':
    main()
