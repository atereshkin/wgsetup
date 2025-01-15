# wgsetup - deploy a WireGuard VPN server

wgsetup is a script that deploys WireGuard on a server, configures the system to route all the client traffic to the Internet and generates a client WireGuard configuration file to connect to this server.

Currently only Debian 12 and Ubuntu 22.04 are supported.

Usage:

    $ sudo python wgsetup.py

For options, see

    $ python wgsetup.py --help

