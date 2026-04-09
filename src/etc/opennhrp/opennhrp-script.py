#!/usr/bin/env python3
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import sys
import time
import pyroute2
import vyos.ipsec

from json import loads
from pathlib import Path

from vyos.logger import getLogger
from vyos.utils.process import cmd
from vyos.utils.process import process_named_running

NHRP_CONFIG: str = '/run/opennhrp/opennhrp.conf'
NHRP_ADMIN_SOCKET: str = '/run/opennhrp.socket'


def opennhrpctl(command: str):
    """
    Execute command on OpenNHRP admin socket

    Args:
        command (str): a command/argument for opennhrpctl

    Returns:
        str: returns the stdout of opennhrpctl command
    """
    return cmd(f'sudo opennhrpctl -a {NHRP_ADMIN_SOCKET} {command}')


def vici_get_ipsec_uniqueid(conn: str, src_nbma: str,
                            dst_nbma: str) -> list[str]:
    """ Find and return IKE SAs by src nbma and dst nbma

    Args:
        conn (str): a connection name
        src_nbma (str): an IP address of NBMA source
        dst_nbma (str): an IP address of NBMA destination

    Returns:
        list: a list of IKE connections that match a criteria
    """
    if not conn or not src_nbma or not dst_nbma:
        logger.error(
            f'Incomplete input data for resolving IKE unique ids: '
            f'conn: {conn}, src_nbma: {src_nbma}, dst_nbma: {dst_nbma}')
        return []

    try:
        logger.info(
            f'Resolving IKE unique ids for: conn: {conn}, '
            f'src_nbma: {src_nbma}, dst_nbma: {dst_nbma}')
        list_ikeid: list[str] = []
        list_sa: list = vyos.ipsec.get_vici_sas_by_name(conn, None)
        for sa in list_sa:
            if sa[conn]['local-host'].decode('ascii') == src_nbma \
                    and sa[conn]['remote-host'].decode('ascii') == dst_nbma:
                list_ikeid.append(sa[conn]['uniqueid'].decode('ascii'))
        return list_ikeid
    except Exception as err:
        logger.error(f'Unable to find unique ids for IKE: {err}')
        return []


def vici_ike_terminate(list_ikeid: list[str]) -> bool:
    """Terminating IKE SAs by list of IKE IDs

    Args:
        list_ikeid (list[str]): a list of IKE ids to terminate

    Returns:
        bool: result of termination action
    """
    if not list:
        logger.warning('An empty list for termination was provided')
        return False

    try:
        vyos.ipsec.terminate_vici_ikeid_list(list_ikeid)
        return True
    except Exception as err:
        logger.error(f'Failed to terminate SA for IKE ids {list_ikeid}: {err}')
        return False


def parse_type_ipsec(interface: str) -> tuple[str, str]:
    """Get DMVPN Type and NHRP Profile from the configuration

    Args:
        interface (str): a name of interface

    Returns:
        tuple[str, str]: `peer_type` and `profile_name`
    """
    if not interface:
        logger.error('Cannot find peer type - no input provided')
        return '', ''

    config_file: str = Path(NHRP_CONFIG).read_text()
    regex: str = rf'^interface {interface} #(?P<peer_type>hub|spoke) ?(?P<profile_name>[^\n]*)$'
    match = re.search(regex, config_file, re.M)
    if match:
        return match.groupdict()['peer_type'], match.groupdict()[
            'profile_name']
    return '', ''


def add_peer_route(nbma_src: str, nbma_dst: str, mtu: str) -> None:
    """Add a route to a NBMA peer

    Args:
        nbma_src (str): a local IP address
        nbma_dst (str): a remote IP address
        mtu (str): a MTU for a route
    """
    logger.info(f'Adding route from {nbma_src} to {nbma_dst} with MTU {mtu}')
    # Find routes to a peer
    route_get_cmd: str = f'sudo ip --json route get {nbma_dst} from {nbma_src}'
    try:
        route_info_data = loads(cmd(route_get_cmd))
    except Exception as err:
        logger.error(f'Unable to find a route to {nbma_dst}: {err}')
        return

    # Check if an output has an expected format
    if not isinstance(route_info_data, list):
        logger.error(
            f'Garbage returned from the "{route_get_cmd}" '
            f'command: {route_info_data}')
        return

    # Add static routes to a peer
    for route_item in route_info_data:
        route_dev = route_item.get('dev')
        route_dst = route_item.get('dst')
        route_gateway = route_item.get('gateway')
        # Prepare a command to add a route
        route_add_cmd = 'sudo ip route add'
        if route_dst:
            route_add_cmd = f'{route_add_cmd} {route_dst}'
        if route_gateway:
            route_add_cmd = f'{route_add_cmd} via {route_gateway}'
        if route_dev:
            route_add_cmd = f'{route_add_cmd} dev {route_dev}'
        route_add_cmd = f'{route_add_cmd} proto 42 mtu {mtu}'
        # Add a route
        try:
            cmd(route_add_cmd)
        except Exception as err:
            logger.error(
                f'Unable to add a route using command "{route_add_cmd}": '
                f'{err}')


def vici_initiate(conn: str, child_sa: str, src_addr: str,
                  dest_addr: str) -> bool:
    """Initiate IKE SA connection with specific peer

    Args:
        conn (str): an IKE connection name
        child_sa (str): a child SA profile name
        src_addr (str): NBMA local address
        dest_addr (str): NBMA address of a peer

    Returns:
        bool: a result of initiation command
    """
    logger.info(
        f'Trying to initiate connection. Name: {conn}, child sa: {child_sa}, '
        f'src_addr: {src_addr}, dst_addr: {dest_addr}')
    try:
        vyos.ipsec.vici_initiate(conn, child_sa, src_addr, dest_addr)
        return True
    except Exception as err:
        logger.error(f'Unable to initiate connection {err}')
        return False


def vici_terminate(conn: str, src_addr: str, dest_addr: str) -> None:
    """Find and terminate IKE SAs by local NBMA and remote NBMA addresses

    Args:
        conn (str): IKE connection name
        src_addr (str): NBMA local address
        dest_addr (str): NBMA address of a peer
    """
    logger.info(
        f'Terminating IKE connection {conn} between {src_addr} '
        f'and {dest_addr}')

    ikeid_list: list[str] = vici_get_ipsec_uniqueid(conn, src_addr, dest_addr)

    if not ikeid_list:
        logger.warning(
            f'No active sessions found for IKE profile {conn}, '
            f'local NBMA {src_addr}, remote NBMA {dest_addr}')
    else:
        try:
            vyos.ipsec.terminate_vici_ikeid_list(ikeid_list)
        except Exception as err:
            logger.error(
                f'Failed to terminate SA for IKE ids {ikeid_list}: {err}')

def iface_up(interface: str) -> None:
    """Proceed tunnel interface UP event

    Args:
        interface (str): an interface name
    """
    if not interface:
        logger.warning('No interface name provided for UP event')

    logger.info(f'Turning up interface {interface}')
    try:
        cmd(f'sudo ip route flush proto 42 dev {interface}')
        cmd(f'sudo ip neigh flush dev {interface}')
    except Exception as err:
        logger.error(
            f'Unable to flush route on interface "{interface}": {err}')

def wait_for_src_nbma(dest_nbma: str, delay_sec: int = 1, max_attempts: int = 10) -> bool:
    """Wait until the kernel can resolve a preferred source address for 'dest_nbma'.

    During boot, OpenNHRP may emit peer-up before the tunnel source interface has
    finished obtaining its DHCP address. In that state NHRP_SRCNBMA is still
    missing, but a route lookup toward the remote NBMA can later expose the
    local preferred source address once the interface becomes usable.

    It based on implementation 'kernel_route' in opennhrp lib:
      - https://github.com/ibazzi/opennhrp/blob/master/nhrp/sysdep_netlink.c#L1004-L1076

    Returns:
        bool: True if a source NBMA address became available, False otherwise.
    """
    with pyroute2.IPRoute() as ipr:
        for attempt in range(1, max_attempts + 1):
            error_message = ''
            try:
                routes = ipr.route('get', dst=dest_nbma)
            except pyroute2.netlink.NetlinkError as e:
                error_message = f'Netlink error while resolving source NBMA: {e}'
            else:
                if routes:
                    attrs = dict(routes[0].get('attrs', []))
                    src_nbma = attrs.get('RTA_PREFSRC')

                    if src_nbma:
                        logger.info(
                            'Local NBMA address became available after '
                            f'{attempt} attempt(s): {src_nbma}'
                        )
                        return True
            logger.info(
                'Local NBMA address not ready yet '
                f'(attempt {attempt}/{max_attempts}). {error_message}'
            )
            if attempt < max_attempts:
                time.sleep(delay_sec)

    logger.error(
        'Local NBMA address is still unavailable after '
        f'{max_attempts} attempt(s)'
    )
    return False


def peer_up(dmvpn_type: str, conn: str) -> None:
    """Proceed NHRP peer UP event

    Args:
        dmvpn_type (str): a type of peer
        conn (str): an IKE profile name
    """
    logger.info(f'Peer UP event for {dmvpn_type} using IKE profile {conn}')

    src_nbma = os.getenv('NHRP_SRCNBMA')
    dest_nbma = os.getenv('NHRP_DESTNBMA')
    dest_mtu = os.getenv('NHRP_DESTMTU')
    interface = os.getenv('NHRP_INTERFACE')
    down_reason = os.getenv('NHRP_PEER_DOWN_REASON')

    # On boot, peer-up can arrive before the tunnel source interface has a
    # usable local NBMA address, for example while DHCP is still settling.
    # In that state the destination NBMA may already be known, but IPsec
    # initiation cannot continue without a local source address.
    #
    # Waiting briefly helps when the interface is only slightly behind. If the
    # event still arrived too early, force OpenNHRP to move the peer to
    # 'lower-down' so it emits peer-up again once the interface is fully ready.
    if interface and not src_nbma and dest_nbma:
        # Do not repeat the same recovery for an event that was already caused
        # by a 'lower-down' transition, otherwise the handler can loop forever.
        if down_reason != 'lower-down':
            logger.warning(
                'Can not retrieve local NHRP NBMA address because '
                f'interface {interface} is not ready'
            )

            if wait_for_src_nbma(dest_nbma):
                logger.info(
                    'Forcing OpenNHRP to retry peer-up after interface readiness changes'
                )
                opennhrpctl(f'cache lowerdown interface {interface}')
                return

    if not src_nbma or not dest_nbma:
        logger.error(
            f'Can not get NHRP NBMA addresses: local {src_nbma}, '
            f'remote {dest_nbma}')
        return

    logger.info(f'NBMA addresses: local {src_nbma}, remote {dest_nbma}')
    if dest_mtu:
        add_peer_route(src_nbma, dest_nbma, dest_mtu)
    if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
        vici_terminate(conn, src_nbma, dest_nbma)
        vici_initiate(conn, 'dmvpn', src_nbma, dest_nbma)


def peer_down(dmvpn_type: str, conn: str) -> None:
    """Proceed NHRP peer DOWN event

    Args:
        dmvpn_type (str): a type of peer
        conn (str): an IKE profile name
    """
    logger.info(f'Peer DOWN event for {dmvpn_type} using IKE profile {conn}')

    src_nbma = os.getenv('NHRP_SRCNBMA')
    dest_nbma = os.getenv('NHRP_DESTNBMA')

    if not src_nbma or not dest_nbma:
        logger.error(
            f'Can not get NHRP NBMA addresses: local {src_nbma}, '
            f'remote {dest_nbma}')
        return

    logger.info(f'NBMA addresses: local {src_nbma}, remote {dest_nbma}')
    if conn and dmvpn_type == 'spoke' and process_named_running('charon'):
        vici_terminate(conn, src_nbma, dest_nbma)
    try:
        cmd(f'sudo ip route del {dest_nbma} src {src_nbma} proto 42')
    except Exception as err:
        logger.error(
            f'Unable to del route from {src_nbma} to {dest_nbma}: {err}')


def route_up(interface: str) -> None:
    """Proceed NHRP route UP event

    Args:
        interface (str): an interface name
    """
    logger.info(f'Route UP event for interface {interface}')

    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')
    next_hop = os.getenv('NHRP_NEXTHOP')

    if not dest_addr or not dest_prefix or not next_hop:
        logger.error(
            f'Can not get route details: dest_addr {dest_addr}, '
            f'dest_prefix {dest_prefix}, next_hop {next_hop}')
        return

    logger.info(
        f'Route details: dest_addr {dest_addr}, dest_prefix {dest_prefix}, '
        f'next_hop {next_hop}')

    try:
        cmd(f'sudo ip route replace {dest_addr}/{dest_prefix} proto 42 \
                via {next_hop} dev {interface}')
        cmd('sudo ip route flush cache')
    except Exception as err:
        logger.error(
            f'Unable replace or flush route to {dest_addr}/{dest_prefix} '
            f'via {next_hop} dev {interface}: {err}')


def route_down(interface: str) -> None:
    """Proceed NHRP route DOWN event

    Args:
        interface (str): an interface name
    """
    logger.info(f'Route DOWN event for interface {interface}')

    dest_addr = os.getenv('NHRP_DESTADDR')
    dest_prefix = os.getenv('NHRP_DESTPREFIX')

    if not dest_addr or not dest_prefix:
        logger.error(
            f'Can not get route details: dest_addr {dest_addr}, '
            f'dest_prefix {dest_prefix}')
        return

    logger.info(
        f'Route details: dest_addr {dest_addr}, dest_prefix {dest_prefix}')
    try:
        cmd(f'sudo ip route del {dest_addr}/{dest_prefix} proto 42')
        cmd('sudo ip route flush cache')
    except Exception as err:
        logger.error(
            f'Unable delete or flush route to {dest_addr}/{dest_prefix}: '
            f'{err}')


if __name__ == '__main__':
    logger = getLogger('opennhrp-script', syslog=True)
    logger.debug(
        f'Running script with arguments: {sys.argv}, '
        f'environment: {os.environ}')

    action = sys.argv[1]
    interface = os.getenv('NHRP_INTERFACE')

    if not interface:
        logger.error('Can not get NHRP interface name')
        sys.exit(1)

    dmvpn_type, profile_name = parse_type_ipsec(interface)
    if not dmvpn_type:
        logger.info(f'Interface {interface} is not NHRP tunnel')
        sys.exit()

    dmvpn_conn: str = ''
    if profile_name:
        dmvpn_conn: str = f'dmvpn-{profile_name}-{interface}'
    if action == 'interface-up':
        iface_up(interface)
    elif action == 'peer-register':
        pass
    elif action == 'peer-up':
        peer_up(dmvpn_type, dmvpn_conn)
    elif action == 'peer-down':
        peer_down(dmvpn_type, dmvpn_conn)
    elif action == 'route-up':
        route_up(interface)
    elif action == 'route-down':
        route_down(interface)

    sys.exit()
