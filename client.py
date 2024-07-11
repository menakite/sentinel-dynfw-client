#!/usr/bin/env python3
# Turris:Sentinel DynFW client - client application for sentinel dynamic firewall
# Copyright (C) 2018-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import enum
import ipaddress
import logging
import logging.handlers
import os
import re
import signal
import socket
import subprocess
import sys
import time
import typing
import urllib.request

import msgpack
import zmq
import zmq.auth
from zmq.utils.monitor import recv_monitor_message

# socket module is only needed if started by Systemd
if os.environ.get('NOTIFY_SOCKET') is None:
    del socket


SERVER_CERT_URL = "https://repo.turris.cz/sentinel/dynfw.pub"

TOPIC_DYNFW_DELTA = "dynfw/delta"
TOPIC_DYNFW_LIST = "dynfw/list"

REQUIRED_DELTA_KEYS = (
    "serial",
    "delta",
    "ip",
)
REQUIRED_LIST_KEYS = (
    "serial",
    "list",
)

MISSING_UPDATE_CNT_LIMIT = 10

LOGGER = None

SYSTEMD_NOTIFY_SOCKET = None


def download_server_certificate(cert_url: str, cert_path: str) -> str:
    notify_systemd_status('Downloading server certificate...')
    delay = 1
    cert_file = None
    while True:
        try:
            with urllib.request.urlopen(cert_url, timeout=10) as urlf:
                cert_file = os.path.join(cert_path, os.path.basename(urlf.url))
                with open(cert_file, 'wb') as filef:
                    filef.write(urlf.read())
            break
        except urllib.error.URLError as exc:
            delay = min(delay * 2, 120)  # At maximum we wait for two minutes to try again
            get_logger().warning('Unable to download server certificate (%s), retrying in %d seconds...', exc.reason, delay)

            # Block for just 1 second at a time
            slept = 0
            while slept < delay:
                time.sleep(1)
                slept += 1
    get_logger().info('Server certificate downloaded correctly.')
    return cert_file


def wait_for_connection(socket):
    notify_systemd_status('Connecting to the Sentinel ZeroMQ server...')
    monitor = socket.get_monitor_socket()
    get_logger().debug("waiting for connection")
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        if evt['event'] == zmq.EVENT_CONNECTED:
            notify_systemd('READY', 1)
            get_logger().info('Connection to ZeroMQ server %s established successfully.', evt['endpoint'].decode('utf-8'))
            break
        if evt['event'] in (zmq.EVENT_HANDSHAKE_FAILED_NO_DETAIL,
                            zmq.EVENT_HANDSHAKE_FAILED_PROTOCOL,
                            zmq.EVENT_HANDSHAKE_FAILED_AUTH):
            # detect handshake failure
            get_logger().error("Can't connect - handshake failed.")
            sys.exit(1)
    socket.disable_monitor()
    monitor.close()


@enum.unique
class Actions(enum.Enum):
    INSERT_RULE = enum.auto()
    DELETE_RULE = enum.auto()
    ADD_SET = enum.auto()
    DELETE_SET = enum.auto()
    ADD_ELEMENT = enum.auto()
    DELETE_ELEMENT = enum.auto()
    LIST_RULESET = enum.auto()
    FLUSH_SET = enum.auto()


class FirewallProxy:
    def __init__(self, backend, table_name, set_name):
        self.backend = backend
        self.table_name = table_name
        self.set_name = set_name
        self.setup()

    def setup(self):
        self.execute(Actions.ADD_SET)
        if self.backend == 'nftables':
            # Add drop rule on Nftables
            self.execute(Actions.INSERT_RULE)

    def cleanup(self):
        if self.backend == 'nftables':
            # Delete drop rule on Nftables
            output = self.execute(Actions.LIST_RULESET)
            pattern = re.compile('^\s+ip saddr @{} counter packets \d+ bytes \d+ drop # handle (\d+)$'.format(self.set_name), re.MULTILINE)  # noqa: W605
            groups = pattern.findall(output.decode('utf-8'))
            if len(groups) == 1:
                handle = groups.pop()
                self.execute(Actions.DELETE_RULE, handle)
            else:
                get_logger().warning('Failed to delete Nftables rule "ip saddr @{} counter drop"'.format(self.set_name))

        self.execute(Actions.DELETE_SET)

    def add_ip(self, ip: typing.Union[str, bytes, list]):
        ip_list = ip
        if not isinstance(ip, list):
            ip_list = [ip]

        valid_ips = []
        for ip_address in ip_list:
            if self.validate_ip_address(ip_address):
                valid_ips.append(ip_address)
            else:
                get_logger().warning('(+) IP address discarded as it is either not valid or not globally routable: %s', ip)

        self.execute(Actions.ADD_ELEMENT, valid_ips)

    def del_ip(self, ip):
        if self.validate_ip_address(ip):
            self.execute(Actions.DELETE_ELEMENT, ip)
        else:
            get_logger().warning('(-) IP address discarded as it is either not valid or not globally routable: %s', ip)

    def validate_ip_address(self, ip: typing.Union[str, bytes]) -> bool:
        if isinstance(ip, bytes):
            ip = ip.decode('utf-8')

        ret = True
        try:
            address = ipaddress.IPv4Address(ip)
            ret = address.is_global
        except ipaddress.AddressValueError:
            ret = False

        return ret

    def reset(self):
        self.execute(Actions.FLUSH_SET)

    def execute(self, action: Actions, arg: typing.Union[str, bytes, list] = None) -> bytes:
        cmd = ''
        if action == Actions.INSERT_RULE:
            # Doesn't apply to Ipset
            if self.backend == 'nftables':
                cmd = 'insert rule {} input ip saddr @{} counter drop'.format(self.table_name, self.set_name)

        elif action == Actions.DELETE_RULE:
            # Doesn't apply to Ipset
            if self.backend == 'nftables':
                cmd = 'delete rule {} input handle {}'.format(self.table_name, arg)

        elif action == Actions.ADD_SET:
            if self.backend == 'ipset':
                cmd = 'create {} hash:ip -exist'.format(self.set_name)
            elif self.backend == 'nftables':
                cmd = 'add set {} {} {{ type ipv4_addr; }}'.format(self.table_name, self.set_name)

        elif action == Actions.DELETE_SET:
            if self.backend == 'ipset':
                cmd = 'destroy {}'.format(self.set_name)
            elif self.backend == 'nftables':
                cmd = 'delete set {} {}'.format(self.table_name, self.set_name)

        elif action == Actions.ADD_ELEMENT:
            if self.backend == 'ipset':
                if len(arg) == 1:
                    cmd = 'add {} {} -exist'.format(self.set_name, arg[0])
                else:
                    for ip_address in arg:
                        cmd += 'add {} {} -exist\n'.format(self.set_name, ip_address)
            elif self.backend == 'nftables':
                cmd = 'add element {} {} {{ {} }}'.format(self.table_name, self.set_name, ', '.join(arg))

        elif action == Actions.DELETE_ELEMENT:
            if self.backend == 'ipset':
                cmd = 'del {} {} -exist'.format(self.set_name, arg)
            elif self.backend == 'nftables':
                cmd = 'delete element {} {} {{ {} }}'.format(self.table_name, self.set_name, arg)

        elif action == Actions.LIST_RULESET:
            # Doesn't apply to Ipset
            if self.backend == 'nftables':
                cmd = '--handle --terse list ruleset'

        elif action == Actions.FLUSH_SET:
            if self.backend == 'ipset':
                cmd = 'flush {}'.format(self.set_name)
            elif self.backend == 'nftables':
                cmd = 'flush set {} {}'.format(self.table_name, self.set_name)

        else:
            get_logger().debug('Ipset.execute() called with an unknown action: %s', action)
            return b''

        if len(cmd) == 0:
            # Safety check.  Caller is supposed to not invoke execute() if
            # an action is not supported/applicable to the specific backend.
            return b''

        executable = '/usr/sbin/ipset'
        if self.backend == 'nftables':
            executable = '/usr/sbin/nft'

        cp = input_bytes = None
        if self.backend == 'ipset' and action == Actions.ADD_ELEMENT and len(arg) > 1:
            # Bulk insertion from LIST message
            input_bytes = cmd.encode('utf-8')
            cmd = 'restore'

        try:
            cp = subprocess.run([executable] + cmd.split(), input=input_bytes, capture_output=True, check=True)
        except subprocess.CalledProcessError as proc_error:
            if self.backend == 'nftables' and proc_error.stderr.startswith(b'Error: Could not process rule: No such file or directory'):
                # Sometimes we receive removals for non-existent elements... just ignore in this case.
                pass
            else:
                get_logger().error('Error running command "%s": return code %d.', ' '.join(proc_error.cmd), proc_error.returncode)
        except (PermissionError, FileNotFoundError) as e:
            # these errors are permanent, i.e., they won't disappear upon next run
            get_logger().critical("Can't run command: %s.", str(e))
            sys.exit(1)
        except OSError as e:
            # the rest of OSError should be temporary, e.g., ChildProcessError or BrokenPipeError
            get_logger().error("Error running command: %s.", str(e))

        if cp is not None:
            return cp.stdout
        else:
            return b''


def create_zmq_socket(context, certs_cache_dir, server_public_file):
    socket = context.socket(zmq.SUB)
    if not os.path.exists(certs_cache_dir):
        os.mkdir(certs_cache_dir, mode=0o750)
    _, client_secret_file = zmq.auth.create_certificates(certs_cache_dir, "client")
    client_public, client_secret = zmq.auth.load_certificate(client_secret_file)
    socket.curve_secretkey = client_secret
    socket.curve_publickey = client_public
    server_public, _ = zmq.auth.load_certificate(server_public_file)
    socket.curve_serverkey = server_public
    return socket


class InvalidMsgError(Exception):
    pass


def parse_msg(data):
    try:
        msg_type = str(data[0], encoding="UTF-8")
        payload = msgpack.unpackb(data[1], raw=False)
    except IndexError:
        raise InvalidMsgError("Not enough parts in message")
    except (TypeError, msgpack.exceptions.UnpackException, UnicodeDecodeError) as e:
        raise InvalidMsgError("Broken message: {}".format(e))
    return msg_type, payload


class Serial:
    def __init__(self, missing_limit):
        self.missing_limit = missing_limit
        self.received_out_of_order = set()
        self.current_serial = 0

    def update_ok(self, serial):
        # update serial & return bool
        # return whether the serial is ok or if the list should be reloaded
        if serial == self.current_serial + 1:
            # received expected serial
            self.current_serial = serial
            while self.current_serial + 1 in self.received_out_of_order:
                # rewind serials
                self.current_serial = self.current_serial + 1
                self.received_out_of_order.remove(self.current_serial)
            return True
        else:
            if serial < self.current_serial:
                get_logger().debug("received lower serial (restarted server?)")
                return False
            if len(self.received_out_of_order) > self.missing_limit:
                get_logger().debug("too many missed messages")
                return False
            self.received_out_of_order.add(serial)
            return True

    def reset(self, serial):
        # reset serial - after list reload
        self.received_out_of_order = set()
        self.current_serial = serial


class DynfwList:
    def __init__(self, socket, backend, dynfw_table_name, dynfw_ipset_name):
        self.socket = socket
        self.serial = Serial(MISSING_UPDATE_CNT_LIMIT)
        self.fwproxy = FirewallProxy(backend, dynfw_table_name, dynfw_ipset_name)
        self.socket.subscribe(TOPIC_DYNFW_LIST)
        self.running = True
        signal.signal(signal.SIGTERM, self.handle_sigterm)
        notify_systemd_status('Waiting to receive initial list...')

    def handle_delta(self, msg):
        for key in REQUIRED_DELTA_KEYS:
            if key not in msg:
                raise InvalidMsgError("missing delta key {}".format(key))
        if not self.serial.update_ok(msg["serial"]):
            get_logger().debug("going to reload the whole list")
            self.socket.unsubscribe(TOPIC_DYNFW_DELTA)
            self.socket.subscribe(TOPIC_DYNFW_LIST)
            return
        if msg["delta"] == "positive":
            self.fwproxy.add_ip(msg["ip"])
#            get_logger().debug("DELTA message: +%s, serial %d", msg["ip"], msg["serial"])
        elif msg["delta"] == "negative":
            self.fwproxy.del_ip(msg["ip"])
#            get_logger().debug("DELTA message: -%s, serial %d", msg["ip"], msg["serial"])

    def handle_list(self, msg):
        for key in REQUIRED_LIST_KEYS:
            if key not in msg:
                raise InvalidMsgError("missing list key {}".format(key))
        self.serial.reset(msg["serial"])
        self.fwproxy.reset()
        get_logger().info('(Re-)Loading initial list containing %d IP addresses (serial number: %d).', len(msg['list']), msg['serial'])
        self.fwproxy.add_ip(msg['list'])
        self.socket.unsubscribe(TOPIC_DYNFW_LIST)
        self.socket.subscribe(TOPIC_DYNFW_DELTA)
        notify_systemd_status('Accepting updates.')

    def handle_sigterm(self, signum, frame):
        notify_systemd('STOPPING', 1)
        get_logger().info('Received TERM signal -- cleaning rules and exiting.')
        self.running = False
        self.fwproxy.reset()
        self.fwproxy.cleanup()


def parse_args():
    parser = argparse.ArgumentParser(description='Turris::Sentinel Dynamic Firewall Client')
    parser.add_argument('-s',
                        '--server',
                        default="sentinel.turris.cz",
                        help='Server address')
    parser.add_argument('-p',
                        '--port',
                        type=int,
                        default=7087,
                        help='Server port')
    parser.add_argument('--cache-dir',
                        default="/var/run/dynfw",
                        help='Path to the directory where certificates are stored',
                        metavar='PATH')
    parser.add_argument('--cert-url',
                        default=SERVER_CERT_URL,
                        help='URL to retrieve server certificate from',
                        metavar='URL')
    parser.add_argument('--backend',
                        choices=['ipset', 'nftables'],
                        default='ipset',
                        help='Firewall backend')
    parser.add_argument('--ipset',
                        default="turris-sn-dynfw-block",
                        help='IP set name to push blocked IPs to')
    parser.add_argument('--table',
                        default="inet filter",
                        help='Nftables table name containing the IP set')
    parser.add_argument('--syslog',
                        action='store_true',
                        help='Send log message to syslog')
    parser.add_argument('-v',
                        '--verbose',
                        action="store_true",
                        help='Increase output verbosity')
    return parser.parse_args()


def configure_logging(syslog: bool, debug: bool):
    global LOGGER
    handler = format_string = None
    if syslog:
        handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_DAEMON)
        format_string = '%(name)s: %(message)s'
    else:
        handler = logging.StreamHandler()
        format_string = '%(asctime)s - %(levelname)s - %(message)s'

    logging.basicConfig(format=format_string, handlers=(handler,))
    LOGGER = logging.getLogger('sentinel-dynfw')
    LOGGER.setLevel(logging.INFO)

    if debug:
        LOGGER.setLevel(logging.DEBUG)


def get_logger():
    global LOGGER
    return LOGGER


def notify_systemd_status(status: str):
    if len(status) > 0:
        notify_systemd('STATUS', status)


def notify_systemd(env_name: str, env_value: typing.Union[int, str]):
    global SYSTEMD_NOTIFY_SOCKET
    if SYSTEMD_NOTIFY_SOCKET is not None:
        message = f'{env_name}={env_value}'
        sck = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sck.sendto(message.encode('utf-8'), SYSTEMD_NOTIFY_SOCKET)
        except Exception as exc:
            get_logger().debug('Exception caught in notify_systemd(): %s (%s), ignoring.', type(exc).__name__, exc)
        finally:
            sck.close()


def main():
    global SYSTEMD_NOTIFY_SOCKET
    SYSTEMD_NOTIFY_SOCKET = os.environ.get('NOTIFY_SOCKET')
    if SYSTEMD_NOTIFY_SOCKET is not None:
        if not SYSTEMD_NOTIFY_SOCKET.startswith(('/', '@')):
            # Unsupported socket type
            SYSTEMD_NOTIFY_SOCKET = None
        elif SYSTEMD_NOTIFY_SOCKET.startswith('@'):
            # Abstract socket
            SYSTEMD_NOTIFY_SOCKET = SYSTEMD_NOTIFY_SOCKET.replace('@', '\0', 1)

    args = parse_args()
    configure_logging(args.syslog, args.verbose)

    get_logger().info('Using backend %s.', args.backend.capitalize())
    server_cert = download_server_certificate(args.cert_url, args.cache_dir)

    context = zmq.Context.instance()
    context.setsockopt(zmq.CONNECT_TIMEOUT, 1000 * 5)  # Milliseconds (5 seconds)
    context.setsockopt(zmq.HEARTBEAT_IVL, 1000 * 60)  # 1 minute
    context.setsockopt(zmq.HEARTBEAT_TIMEOUT, 1000 * 15)  # 15 seconds

    # Enable IPv6 if supported
    import socket
    if socket.has_dualstack_ipv6():
        context.setsockopt(zmq.IPV6, True)
    del socket

    context.setsockopt(zmq.LINGER, 0)
    context.setsockopt(zmq.TCP_KEEPALIVE, True)
    context.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 120)  # Seconds (2 minutes)
    context.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)  # 3 retries
    context.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 5)  # 5 seconds

    socket = create_zmq_socket(context, args.cache_dir, server_cert)
    socket.connect("tcp://{}:{}".format(args.server, args.port))
    wait_for_connection(socket)
    dynfw_list = DynfwList(socket, args.backend, args.table, args.ipset)
    while dynfw_list.running:
        try:
            msg = socket.recv_multipart(flags=zmq.NOBLOCK)
            topic, payload = parse_msg(msg)
            if topic == TOPIC_DYNFW_LIST:
                dynfw_list.handle_list(payload)
            elif topic == TOPIC_DYNFW_DELTA:
                dynfw_list.handle_delta(payload)
            else:
                get_logger().warning("received unknown topic: %s", topic)
        except zmq.error.Again:
            time.sleep(0.25)
        except InvalidMsgError as e:
            get_logger().error("Invalid message: %s", e)
    else:
        socket.disconnect(socket.last_endpoint)
        socket.close()
        context.term()


if __name__ == "__main__":
    main()
