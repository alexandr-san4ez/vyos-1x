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

import re
import unittest

from base_vyostest_shim import VyOSUnitTestSHIM

from vyos.configsession import ConfigSessionError
from vyos.utils.file import read_file
from vyos.utils.process import cmd
from vyos.utils.process import process_named_running
from vyos.xml_ref import default_value

PROCESS_NAME = 'rsyslogd'
RSYSLOG_CONF = '/etc/rsyslog.d/00-vyos.conf'

base_path = ['system', 'syslog']

dummy_interface = 'dum372874'

def get_config_value(key):
    tmp = read_file(RSYSLOG_CONF)
    tmp = re.findall(r'\n?{}\s+(.*)'.format(key), tmp)
    return tmp[0]

def get_remote_config(string=''):
    """
    Retrieve current "running configuration" from FRR
    string:        search for a specific start string in the configuration
    """
    command = 'cat /etc/rsyslog.d/00-vyos.conf'
    if string:
        command += f' | sed -n "/^{string}$/,/^)/p"'
    return cmd(command)

class TestRSYSLOGService(VyOSUnitTestSHIM.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestRSYSLOGService, cls).setUpClass()

        # ensure we can also run this test on a live system - so lets clean
        # out the current configuration :)
        cls.cli_delete(cls, base_path)

    def tearDown(self):
        # Check for running process
        self.assertTrue(process_named_running(PROCESS_NAME))

        # delete testing SYSLOG config
        self.cli_delete(base_path)
        self.cli_commit()

        # Check for running process
        self.assertFalse(process_named_running(PROCESS_NAME))

    def test_console(self):
        self.cli_set(base_path + ['console', 'facility', 'all', 'level', 'warning'])
        self.cli_commit()

        config = read_file(RSYSLOG_CONF)
        self.assertIn('*.warning /dev/console', config)

    def test_syslog_global(self):
        hostname = 'vyos123'
        domainname = 'example.local'
        self.cli_set(['system', 'host-name', hostname])
        self.cli_set(['system', 'domain-name', domainname])
        self.cli_set(base_path + ['global', 'marker', 'interval', '600'])
        self.cli_set(base_path + ['global', 'preserve-fqdn'])
        self.cli_set(base_path + ['global', 'facility', 'kern', 'level', 'err'])

        self.cli_commit()

        config = read_file(RSYSLOG_CONF)
        expected = [
            '$MarkMessagePeriod 600',
            '$PreserveFQDN on',
            'kern.err',
            f'$LocalHostName {hostname}.{domainname}',
        ]

        for e in expected:
            self.assertIn(e, config)

    def test_syslog_remote(self):
        dummy_if_path = ['interfaces', 'dummy', dummy_interface]
        rhosts = {
            '169.254.0.1': {
                'facility': {'auth' : {'level': 'info'}},
                'protocol': 'udp',
            },
            '2001:db8::1': {
                'facility': {'all' : {'level': 'debug'}},
                'port': '1514',
                'protocol': 'udp',
            },
            'syslog.vyos.net': {
                'facility': {'all' : {'level': 'debug'}},
                'format': ['include-timezone'],
                'port': '1515',
                'protocol': 'tcp',
            },
            '169.254.0.3': {
                'facility': {'auth' : {'level': 'info'},
                             'kern' : {'level': 'debug'},
                             'all'  : {'level': 'notice'},
                },
                'format': ['include-timezone', 'octet-counted'],
                'protocol': 'tcp',
                'port': '10514',
                'source_address': '172.29.0.1',
            },
        }
        default_port = default_value(base_path + ['host', next(iter(rhosts)), 'port'])
        default_protocol = default_value(base_path + ['host', next(iter(rhosts)), 'protocol'])

        self.cli_set(base_path + ['global', 'facility', 'all', 'level', 'info'])
        self.cli_set(base_path + ['global', 'facility', 'local7', 'level', 'debug'])

        for remote, remote_options in rhosts.items():
            remote_base = base_path + ['host', remote]
            if 'port' in remote_options:
                self.cli_set(remote_base + ['port', remote_options['port']])

            if 'facility' in remote_options:
                for facility, facility_options in remote_options['facility'].items():
                    level = facility_options['level']
                    self.cli_set(remote_base + ['facility', facility, 'level', level])

            if 'format' in remote_options:
                for format in remote_options['format']:
                    self.cli_set(remote_base + ['format', format])

            if 'protocol' in remote_options:
                protocol = remote_options['protocol']
                self.cli_set(remote_base + ['protocol', protocol])

            if 'source_address' in remote_options:
                source_address = remote_options['source_address']
                self.cli_set(remote_base + ['source-address', source_address])

                # check validate() - source address does not exist
                with self.assertRaises(ConfigSessionError):
                    self.cli_commit()
                self.cli_set(dummy_if_path + ['address', f'{source_address}/32'])

        self.cli_commit()

        for remote, remote_options in rhosts.items():
            config = get_remote_config(f'# Remote syslog to {remote}')

            filter = []
            if 'facility' in remote_options:
                for facility, facility_options in remote_options['facility'].items():
                    level = facility_options['level']
                    if facility == 'all':
                        facility = '*'
                    filter.append(f'{facility}.{level}')

            filter.sort()
            filter = ';'.join(filter)
            self.assertIn(f'{filter} action(type="omfwd"', config)
            self.assertIn(f'target="{remote}"', config)

            port = default_port
            if 'port' in remote_options:
                port = remote_options['port']
            self.assertIn(f'port="{port}"', config)

            if 'format' in remote_options:
                if 'include-timezone' in remote_options['format']:
                    self.assertIn(f'template="RSYSLOG_SyslogProtocol23Format"', config)

                if 'octet-counted' in remote_options['format']:
                    self.assertIn(f'TCP_Framing="octed-counted"', config)
                else:
                    self.assertIn(f'TCP_Framing="traditional"', config)

            protocol = default_protocol
            if 'protocol' in remote_options:
                protocol = remote_options['protocol']
            self.assertIn(f'protocol="{protocol}"', config)

            if 'source_address' in remote_options:
                source_address = remote_options['source_address']
                self.assertIn(f'Address="{source_address}"', config)

        # cleanup dummy interface
        self.cli_delete(dummy_if_path)

if __name__ == '__main__':
    unittest.main(verbosity=2)
