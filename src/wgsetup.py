import argparse
import ipaddress
import logging
import socket
import subprocess
import sys

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

    def __init__(self, runner, network=None, wg_listen_port=0, server_address=None):
        assert server_address is not None
        assert network is not None
        assert wg_listen_port > 0
        self.run = runner
        self.network = network
        self.wg_listen_port = wg_listen_port
        self.srv_private_key = None
        self.srv_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        self.server_address = server_address

    def install_dependencies(self):
        raise NotImplementedError()

    def enable_forwarding(self):
        raise NotImplementedError()

    def setup_nat(self):
        raise NotImplementedError()

    def get_config_path(self):
        return '/etc/wireguard/wg0.conf'  # TODO: scan for existing configs

    def generate_private_key(self):
        key, _ = self.run('wg', 'genkey')
        return key.decode('utf-8').strip()

    def get_public_key(self, private_key):
        key, _ = self.run('wg', 'pubkey', input=private_key.encode('utf-8'))
        return key.decode('utf-8').strip()

    def get_server_vpn_address(self):
        return self.network.network_address + 1

    def get_client_vpn_address(self):
        return self.get_server_vpn_address() + 1

    def get_client_subnet(self):
        return ipaddress.ip_network(self.get_client_vpn_address())

    def get_server_config(self):
        cfg = '[Interface]\n'
        cfg += f'Address = {self.get_server_vpn_address()}\n'
        cfg += f'PrivateKey = {self.srv_private_key}\n'
        cfg += f'ListenPort = {self.wg_listen_port}\n\n'
        cfg += '[Peer]\n'
        cfg += f'PublicKey = {self.client_public_key}\n'
        cfg += f'AllowedIPs = {self.get_client_subnet()}\n'
        return cfg

    def get_client_config(self):
        cfg = '[Interface]\n'
        cfg += f'PrivateKey = {self.client_private_key}\n'
        cfg += f'Address = {self.get_client_vpn_address()}\n\n'
        cfg += '[Peer]\n'
        cfg += f'Endpoint = {self.server_address}:{self.wg_listen_port}\n'
        cfg += f'PublicKey = {self.srv_public_key}\n'
        cfg += f'AllowedIPs = 0.0.0.0/0\n'
        cfg += 'PersistentKeepalive = 25\n'
        return cfg

    def install(self):
        log.debug('Installing dependencies')
        self.install_dependencies()
        log.debug('Generating server key')
        self.srv_private_key = self.generate_private_key()
        self.srv_public_key = self.get_public_key(self.srv_private_key)
        log.debug('Enabling forwarding')
        self.enable_forwarding()
        log.debug('Setting up NAT')
        self.setup_nat()
        log.debug('Generating client key')
        self.client_private_key = self.generate_private_key()
        self.client_public_key = self.get_public_key(self.client_private_key)
        log.debug('Configuring WireGuard')
        self.configure_wireguard()

    def configure_wireguard(self):
        with open(self.get_config_path(), 'wt') as conf:
            conf.write(self.get_server_config())


class DebianInstaller(AbstractInstaller):
    def install_dependencies(self):
        self.run('apt-get', '-y', 'install', 'wireguard', 'nftables')

    def enable_forwarding(self):
        self.run('sysctl', '-w', 'net.ipv4.ip_forward=1')
        with open('/etc/sysctl.d/forwarding.wgsetup.conf', 'wt') as f:
            f.write('net.ipv4.ip_forward = 1')

    def setup_nat(self):
        self.run('nft', 'add', 'table', 'nat')
        self.run('nft', 'add chain nat postrouting { type nat hook postrouting priority 100 ; }')
        self.run('nft', 'add', 'rule', 'nat', 'postrouting', 'masquerade')
        ruleset, err = self.run('nft', 'list', 'ruleset')
        with open('/etc/nftables.conf', 'wb') as f:
            f.write(ruleset)
        self.run('systemctl', 'enable', 'nftables.service')

    def configure_wireguard(self):
        super().configure_wireguard()
        self.run('systemctl', 'enable', '--now', 'wg-quick@wg0')
        self.run('service', 'wg-quick@wg0', 'reload')


def detect_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('1.1.1.1', 1))
        ip = s.getsockname()[0]
        if ipaddress.ip_address(ip).is_private:
            raise ValueError(ip)
    finally:
        s.close()
    return ip


def get_installer():
    o, e = run_locally('lsb_release', '-d')
    if b'Debian GNU/Linux 12' in o:
        return DebianInstaller


def main():
    parser = argparse.ArgumentParser(
        prog='wgsetup',
        description='Configures the machine to be WireGuard VPN server routing all client traffic to the Internet')
    parser.add_argument('-a', '--server-address',
                        help='External address of the server that the client(s) will use to connect')
    parser.add_argument('-n', '--network4', default='10.12.1.0/24', type=ipaddress.ip_network,
                        help='IPv4 VPN subnet. '
                             'This is where server and client(s) internal addresses will be allocated. '
                             '10.12.1.0/24 if not specified.')
    parser.add_argument('-p', '--port', type=int, default=51290, help='WireGuard port. Default is 51290.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information')
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr, format='%(message)s')
    server_address = args.server_address
    if server_address is None:
        try:
            server_address = detect_ip()
        except:
            log.error('Unable to detect server IP address. Use the -a/--server-address option.')
            return

    Installer = get_installer()
    if Installer is None:
        log.error('Unsupported OS')
        return

    i = Installer(runner=run_locally,
                  server_address=server_address,
                  network=args.network4,
                  wg_listen_port=args.port)
    i.install()
    print(i.get_client_config())


if __name__ == '__main__':
    main()
