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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import typing
import re
import struct
from pypureomapi import Omapi, OmapiMessage, OmapiError, pack_ip, OMAPI_OP_UPDATE

from datetime import datetime
from glob import glob
from ipaddress import ip_address
from isc_dhcp_leases import IscDhcpLeases
from tabulate import tabulate

import vyos.opmode

from vyos.base import Warning
from vyos.configquery import ConfigTreeQuery

from vyos.utils.process import is_systemd_service_running
from vyos.utils.process import call

time_string = "%a %b %d %H:%M:%S %Z %Y"

config = ConfigTreeQuery()
lease_valid_states = ['all', 'active', 'free', 'expired', 'released', 'abandoned', 'reset', 'backup']
sort_valid_inet = ['end', 'mac', 'hostname', 'ip', 'pool', 'remaining', 'start', 'state']
sort_valid_inet6 = ['end', 'duid', 'ip', 'last_communication', 'pool', 'remaining', 'state', 'type']

ArgFamily = typing.Literal['inet', 'inet6']
ArgState = typing.Literal['all', 'active', 'free', 'expired', 'released', 'abandoned', 'reset', 'backup']
ArgOrigin = typing.Literal['local', 'remote']

def _utc_to_local(utc_dt):
    return datetime.fromtimestamp((datetime.fromtimestamp(utc_dt) - datetime(1970, 1, 1)).total_seconds())


def _format_hex_string(in_bytes):
    in_str = bytes(in_bytes).hex()
    out_str = ""
    # if input is divisible by 2, add : every 2 chars
    if len(in_str) > 0 and len(in_str) % 2 == 0:
        out_str = ':'.join(a+b for a,b in zip(in_str[::2], in_str[1::2]))
    else:
        out_str = in_str

    return out_str


def _find_list_of_dict_index(lst, key='ip', value='') -> int:
    """
    Find the index entry of list of dict matching the dict value
    Exampe:
        % lst = [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}]
        % _find_list_of_dict_index(lst, key='ip', value='192.0.2.2')
        % 1
    """
    idx = next((index for (index, d) in enumerate(lst) if d[key] == value), None)
    return idx


def _get_raw_server_leases(family='inet', pool=None, sorted=None, state=[], origin=None) -> list:
    """
    Get DHCP server leases
    :return list
    """
    lease_file = '/config/dhcpdv6.leases' if family == 'inet6' else '/config/dhcpd.leases'
    data = []
    leases = IscDhcpLeases(lease_file).get(include_backups=True)

    # Determine pool(s) to process
    pool_list = [pool] if pool else _get_dhcp_pools(family=family)
    aux = pool is not None

    # Process each lease
    for lease in leases:
        lease_pool_name = lease.sets.get('shared-networkname', '')

        # Check if lease matches specified pool(s)
        if lease_pool_name in pool_list or (not aux and lease_pool_name == ''):
            data_lease = {
                'ip': lease.ip,
                'state': lease.binding_state or 'unknown',
                'pool': lease_pool_name,
                'end': lease.end.timestamp() if lease.end else None,
                'origin': 'local' if lease_pool_name else 'remote',
                'remaining': '-',
                'start': lease.start.timestamp() if family == 'inet' and lease.start else None,
                'hostname': lease.hostname if family == 'inet' else None,
                'mac': lease.ethernet if family == 'inet' else None,
                'last_communication': lease.last_communication.timestamp() if family == 'inet6' and lease.last_communication else None,
                'duid': _format_hex_string(lease.duid) if family == 'inet6' else None,
                'type': None
            }

            # Set lease type for IPv6
            if family == 'inet6' and lease.type:
                lease_types_long = {'na': 'non-temporary', 'ta': 'temporary', 'pd': 'prefix delegation'}
                data_lease['type'] = lease_types_long.get(lease.type, 'unknown')

            # Calculate remaining time for the lease
            if lease.end:
                remaining_time = lease.end - datetime.utcnow()
                data_lease['remaining'] = str(remaining_time).split('.')[0] if remaining_time.days >= 0 else '-'

            # Filter by state, origin, and pool, then add lease to data if valid
            if (not state or data_lease['state'] in state or state == 'all') and \
               (not origin or data_lease['origin'] in origin) and \
               (not aux or data_lease['pool'] == lease_pool_name):
                data.append(data_lease)

    # Deduplicate entries based on IP address
    unique_data = {entry['ip']: entry for entry in data}.values()

    # Sort data if needed
    if sorted:
        if sorted == 'ip':
            unique_data = sorted(unique_data, key=lambda x: ip_address(x['ip']))
        else:
            unique_data = sorted(unique_data, key=lambda x: x.get(sorted, ''))

    return list(unique_data)


def _get_formatted_server_leases(raw_data, family='inet'):
    data_entries = []
    if family == 'inet':
        for lease in raw_data:
            ipaddr = lease.get('ip', '-')
            hw_addr = lease.get('mac', '-')
            state = lease.get('state', '-')
            start = lease.get('start')
            start = _utc_to_local(start).strftime('%Y/%m/%d %H:%M:%S') if start else '-'
            end = lease.get('end')
            end = _utc_to_local(end).strftime('%Y/%m/%d %H:%M:%S') if end else '-'
            remain = lease.get('remaining', '-')
            pool = lease.get('pool', '-')
            hostname = lease.get('hostname', '-')
            origin = lease.get('origin', '-')
            data_entries.append([ipaddr, hw_addr, state, start, end, remain, pool, hostname, origin])

        headers = ['IP Address', 'MAC address', 'State', 'Lease start', 'Lease expiration', 'Remaining', 'Pool',
                   'Hostname', 'Origin']

    elif family == 'inet6':
        for lease in raw_data:
            ipaddr = lease.get('ip', '-')
            state = lease.get('state', '-')
            start = lease.get('last_communication')
            start = _utc_to_local(start).strftime('%Y/%m/%d %H:%M:%S') if start else '-'
            end = lease.get('end')
            end = _utc_to_local(end).strftime('%Y/%m/%d %H:%M:%S') if end else '-'
            remain = lease.get('remaining', '-')
            lease_type = lease.get('type', '-')
            pool = lease.get('pool', '-')
            host_identifier = lease.get('duid', '-')
            data_entries.append([ipaddr, state, start, end, remain, lease_type, pool, host_identifier])

        headers = ['IPv6 address', 'State', 'Last communication', 'Lease expiration', 'Remaining', 'Type', 'Pool',
                   'DUID']

    output = tabulate(data_entries, headers, numalign='left')
    return output


def _get_dhcp_pools(family='inet') -> list:
    v = 'v6' if family == 'inet6' else ''
    pools = config.list_nodes(f'service dhcp{v}-server shared-network-name')
    return pools


def _get_pool_size(pool, family='inet'):
    v = 'v6' if family == 'inet6' else ''
    base = f'service dhcp{v}-server shared-network-name {pool}'
    size = 0
    subnets = config.list_nodes(f'{base} subnet')
    for subnet in subnets:
        if family == 'inet6':
            ranges = config.list_nodes(f'{base} subnet {subnet} address-range start')
        else:
            ranges = config.list_nodes(f'{base} subnet {subnet} range')
        for range in ranges:
            if family == 'inet6':
                start = config.list_nodes(f'{base} subnet {subnet} address-range start')[0]
                stop = config.value(f'{base} subnet {subnet} address-range start {start} stop')
            else:
                start = config.value(f'{base} subnet {subnet} range {range} start')
                stop = config.value(f'{base} subnet {subnet} range {range} stop')
            # Add +1 because both range boundaries are inclusive
            size += int(ip_address(stop)) - int(ip_address(start)) + 1
    return size


def _get_raw_pool_statistics(family='inet', pool=None):
    if pool is None:
        pool = _get_dhcp_pools(family=family)
    else:
        pool = [pool]

    v = 'v6' if family == 'inet6' else ''
    stats = []
    for p in pool:
        subnet = config.list_nodes(f'service dhcp{v}-server shared-network-name {p} subnet')
        size = _get_pool_size(family=family, pool=p)
        leases = len(_get_raw_server_leases(family=family, pool=p))
        use_percentage = round(leases / size * 100) if size != 0 else 0
        pool_stats = {'pool': p, 'size': size, 'leases': leases,
                      'available': (size - leases), 'use_percentage': use_percentage, 'subnet': subnet}
        stats.append(pool_stats)
    return stats


def _get_formatted_pool_statistics(pool_data, family='inet'):
    data_entries = []
    for entry in pool_data:
        pool = entry.get('pool')
        size = entry.get('size')
        leases = entry.get('leases')
        available = entry.get('available')
        use_percentage = entry.get('use_percentage')
        use_percentage = f'{use_percentage}%'
        data_entries.append([pool, size, leases, available, use_percentage])

    headers = ['Pool', 'Size','Leases', 'Available', 'Usage']
    output = tabulate(data_entries, headers, numalign='left')
    return output


def _verify(func):
    """Decorator checks if DHCP(v6) config exists"""
    from functools import wraps

    @wraps(func)
    def _wrapper(*args, **kwargs):
        config = ConfigTreeQuery()
        family = kwargs.get('family')
        v = 'v6' if family == 'inet6' else ''
        unconf_message = f'DHCP{v} server is not configured'
        # Check if config does not exist
        if not config.exists(f'service dhcp{v}-server'):
            raise vyos.opmode.UnconfiguredSubsystem(unconf_message)
        return func(*args, **kwargs)
    return _wrapper

def _verify_client(func):
    """Decorator checks if interface is configured as DHCP client"""
    from functools import wraps
    from vyos.ifconfig import Section

    @wraps(func)
    def _wrapper(*args, **kwargs):
        config = ConfigTreeQuery()
        family = kwargs.get('family')
        v = 'v6' if family == 'inet6' else ''
        interface = kwargs.get('interface')
        interface_path = Section.get_config_path(interface)
        path_elems = interface_path.split()
        base_path = ['interfaces'] + path_elems

        unconf_message = f'DHCP{v} client not configured on interface {interface}!'

        iface_conf = config.get_config_dict(
            base_path, key_mangling=('-', '_'), get_first_key=True
        )

        if family == 'inet6':
            addrs = iface_conf.get('address', [])
            has_dhcpv6_addr = 'dhcpv6' in addrs

            dhcpv6_opts = iface_conf.get('dhcpv6_options', {})
            has_parameters_only = 'parameters_only' in dhcpv6_opts
            has_pd = 'pd' in dhcpv6_opts

            config_exists = has_dhcpv6_addr or has_parameters_only or has_pd
        else:
            addrs = iface_conf.get('address', [])
            config_exists = 'dhcp' in addrs

        if not config_exists:
            raise vyos.opmode.UnconfiguredObject(unconf_message)

        return func(*args, **kwargs)
    return _wrapper

@_verify
def show_pool_statistics(raw: bool, family: ArgFamily, pool: typing.Optional[str]):
    pool_data = _get_raw_pool_statistics(family=family, pool=pool)
    if raw:
        return pool_data
    else:
        return _get_formatted_pool_statistics(pool_data, family=family)


@_verify
def show_server_leases(raw: bool, family: ArgFamily, pool: typing.Optional[str],
                       sorted: typing.Optional[str], state: typing.Optional[ArgState],
                       origin: typing.Optional[ArgOrigin] ):
    # if dhcp server is down, inactive leases may still be shown as active, so warn the user.
    v = '6' if family == 'inet6' else ''
    service_name = 'DHCPv6' if family == 'inet6' else 'DHCP'
    if not is_systemd_service_running(f'isc-dhcp-server{v}.service'):
        Warning(f'{service_name} server is configured but not started. Data may be stale.')

    v = 'v6' if family == 'inet6' else ''
    if pool and pool not in _get_dhcp_pools(family=family):
        raise vyos.opmode.IncorrectValue(f'DHCP{v} pool "{pool}" does not exist!')

    if state and state not in lease_valid_states:
        raise vyos.opmode.IncorrectValue(f'DHCP{v} state "{state}" is invalid!')

    sort_valid = sort_valid_inet6 if family == 'inet6' else sort_valid_inet
    if sorted and sorted not in sort_valid:
        raise vyos.opmode.IncorrectValue(f'DHCP{v} sort "{sorted}" is invalid!')

    lease_data = _get_raw_server_leases(family=family, pool=pool, sorted=sorted, state=state, origin=origin)
    if raw:
        return lease_data
    else:
        return _get_formatted_server_leases(lease_data, family=family)


def _get_raw_client_leases(family='inet', interface=None):
    from time import mktime
    from datetime import datetime
    from vyos.defaults import directories
    from vyos.utils.network import get_interface_vrf

    lease_dir = directories['isc_dhclient_dir']
    lease_files = []
    lease_data = []

    if interface:
        tmp = f'{lease_dir}/dhclient_{interface}.lease'
        if os.path.exists(tmp):
            lease_files.append(tmp)
    else:
        # All DHCP leases
        lease_files = glob(f'{lease_dir}/dhclient_*.lease')

    for lease in lease_files:
        tmp = {}
        with open(lease, 'r') as f:
            for line in f.readlines():
                line = line.rstrip()
                if 'last_update' not in tmp:
                    # ISC dhcp client contains least_update timestamp in human readable
                    # format this makes less sense for an API and also the expiry
                    # timestamp is provided in UNIX time. Convert string (e.g. Sun Jul
                    # 30 18:13:44 CEST 2023) to UNIX time (1690733624)
                    tmp.update({'last_update' : int(mktime(datetime.strptime(line, time_string).timetuple()))})
                    continue

                k, v = line.split('=')
                tmp.update({k : v.replace("'", "")})

        if 'interface' in tmp:
            vrf = get_interface_vrf(tmp['interface'])
            if vrf: tmp.update({'vrf' : vrf})

        lease_data.append(tmp)

    return lease_data

def _get_formatted_client_leases(lease_data, family):
    from time import localtime
    from time import strftime

    from vyos.utils.network import is_intf_addr_assigned

    data_entries = []
    for lease in lease_data:
        if not lease.get('new_ip_address'):
            continue
        data_entries.append(["Interface", lease['interface']])
        if 'new_ip_address' in lease:
            tmp = '[Active]' if is_intf_addr_assigned(lease['interface'], lease['new_ip_address']) else '[Inactive]'
            data_entries.append(["IP address", lease['new_ip_address'], tmp])
        if 'new_subnet_mask' in lease:
            data_entries.append(["Subnet Mask", lease['new_subnet_mask']])
        if 'new_domain_name' in lease:
            data_entries.append(["Domain Name", lease['new_domain_name']])
        if 'new_routers' in lease:
            data_entries.append(["Router", lease['new_routers']])
        if 'new_domain_name_servers' in lease:
            data_entries.append(["Name Server", lease['new_domain_name_servers']])
        if 'new_dhcp_server_identifier' in lease:
            data_entries.append(["DHCP Server", lease['new_dhcp_server_identifier']])
        if 'new_dhcp_lease_time' in lease:
            data_entries.append(["Lease Time", lease['new_dhcp_lease_time']])
        if 'vrf' in lease:
            data_entries.append(["VRF", lease['vrf']])
        if 'last_update' in lease:
            tmp = strftime(time_string, localtime(int(lease['last_update'])))
            data_entries.append(["Last Update", tmp])
        if 'new_expiry' in lease:
            tmp = strftime(time_string, localtime(int(lease['new_expiry'])))
            data_entries.append(["Expiry", tmp])

        # Add empty marker
        data_entries.append([''])

    output = tabulate(data_entries, tablefmt='plain')

    return output

def show_client_leases(raw: bool, family: ArgFamily, interface: typing.Optional[str]):
    lease_data = _get_raw_client_leases(family=family, interface=interface)
    if raw:
        return lease_data
    else:
        return _get_formatted_client_leases(lease_data, family=family)

@_verify_client
def renew_client_lease(raw: bool, family: ArgFamily, interface: str):
    if not raw:
        v = 'v6' if family == 'inet6' else ''
        print(f'Restarting DHCP{v} client on interface {interface}...')
    if family == 'inet6':
        call(f'systemctl restart dhcp6c@{interface}.service')
    else:
        call(f'systemctl restart dhclient@{interface}.service')

@_verify_client
def release_client_lease(raw: bool, family: ArgFamily, interface: str):
    if not raw:
        v = 'v6' if family == 'inet6' else ''
        print(f'Release DHCP{v} client on interface {interface}...')
    if family == 'inet6':
        call(f'systemctl stop dhcp6c@{interface}.service')
    else:
        call(f'systemctl stop dhclient@{interface}.service')


class CustomOmapi(Omapi):
    # Custom OMAPI client with extended functionalities to interact with DHCP leases
    def query_server_insecure(self, message):
        # Send the message and receive a response for it with insecure flag enabled
        self.send_message(message)
        return self.receive_response(message, insecure=True)

    def release_lease(self, ip_address):
        """Release a DHCP lease using its IP address by setting the lease state to 'released'.
        Args:
            ip_address (str): The IP address associated with the lease to be released.
        Raises:
            OmapiError: If the lease cannot be released due to server issues or invalid handle.
        """
        # Prepare a message to open the lease object by IP address
        msg = OmapiMessage.open(b'lease')
        msg.obj.append((b'ip-address', pack_ip(ip_address)))

        # Query server to get the handle for this lease
        response = self.query_server_insecure(msg)
        if response.opcode != OMAPI_OP_UPDATE or response.handle == 0:
            raise OmapiError('Lease lookup failed or invalid handle received.')

        # Update message to set the lease state to "released" (state code 4)
        release_msg = OmapiMessage.update(response.handle)
        release_msg.update_object({b'state': struct.pack('!I', 4)})

        # Send release message and verify the result
        release_response = self.query_server_insecure(release_msg)
        result = next((v for k, v in release_response.message if k == b'result'), None)

        if result != b'\x00\x00\x00\x00':  # Non-zero indicates failure
            raise OmapiError(
                'Failed to release the lease; non-zero result code returned.'
            )


def _extract_omapi_key(conf_path='/run/dhcp-server/dhcpd.conf'):
    """Extract the OMAPI key from the DHCP configuration file.
    Args:
        conf_path (str): Path to the DHCP configuration file (default: "/run/dhcp-server/dhcpd.conf").
    Returns:
        str: The extracted OMAPI key.
    Raises:
        ValueError: If the configuration file is not found or the key is missing.
    """
    try:
        with open(conf_path, 'r') as conf_file:
            conf_content = conf_file.read()

        # Regex pattern to match and extract OMAPI key information
        key_value_pattern = re.compile(
            r'^key vyos_omapi_key {\n\s+algorithm (?P<omapi_key_algo>[\w-]+);\n\s+secret "(?P<omapi_key>[\w+/=]+)";',
            re.M | re.S,
        )

        # Extract the OMAPI key value
        key_value_match = key_value_pattern.search(conf_content)
        if key_value_match:
            key_value = key_value_match.group('omapi_key')
        else:
            raise ValueError('Failed to load OMAPI key from dhcpd.conf')

        return key_value

    except FileNotFoundError:
        raise ValueError(f'Configuration file {conf_path} not found.')


def clear_release_lease(ip_address: str) -> None:
    """Retrieve lease information and release it if it is in an active state.
    Args:
        ip_address (str): IP address of the lease to be displayed and released.
    """
    server_ip: str = '127.0.0.1'
    server_port: int = 7911

    # Get OMAPI key from the configuration
    key_name = 'vyos_omapi_key'
    key_value = _extract_omapi_key()

    # Initialize the CustomOmapi client
    omapi_client = CustomOmapi(
        hostname=server_ip,
        port=server_port,
        username=key_name.encode('utf-8'),
        key=key_value.encode('utf-8'),
    )

    try:
        # Retrieve lease information
        lease_info = omapi_client.lookup_by_lease(ip=ip_address)

        # Allow release only if lease is in an active state (state code 2)
        if lease_info.get('state') != 2:
            raise ValueError('Only active leases can be released')

        # Proceed to release the lease
        omapi_client.release_lease(ip_address)
        print(f'Lease for {ip_address} successfully released.')

    except OmapiError as e:
        print(f'Error retrieving or releasing lease: {e}')

    finally:
        # Ensure client connection is closed
        omapi_client.close()


if __name__ == '__main__':
    try:
        res = vyos.opmode.run(sys.modules[__name__])
        if res:
            print(res)
    except (ValueError, vyos.opmode.Error) as e:
        print(e)
        sys.exit(1)
