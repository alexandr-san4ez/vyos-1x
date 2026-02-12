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
import unittest
import paramiko
import pprint
import re

from time import sleep
from typing import Type

from vyos.configsession import ConfigSession
from vyos.configsession import ConfigSessionError
from vyos import ConfigError
from vyos.defaults import commit_lock
from vyos.utils.process import cmd
from vyos.utils.process import run
from vyos.utils.process import rc_cmd

save_config = '/tmp/vyos-smoketest-save'

# This class acts as shim between individual Smoketests developed for VyOS and
# the Python UnitTest framework. Before every test is loaded, we dump the current
# system configuration and reload it after the test - despite the test results.
#
# Using this approach we can not render a live system useless while running any
# kind of smoketest. In addition it adds debug capabilities like printing the
# command used to execute the test.
class VyOSUnitTestSHIM:
    class TestCase(unittest.TestCase):
        # if enabled in derived class, print out each and every set/del command
        # on the CLI. This is usefull to grap all the commands required to
        # trigger the certain failure condition.
        # Use "self.debug = True" in derived classes setUp() method
        debug = False

        @classmethod
        def setUpClass(cls):
            cls._session = ConfigSession(os.getpid())
            cls._session.save_config(save_config)
            if os.path.exists('/tmp/vyos.smoketest.debug'):
                cls.debug = True
            pass

        @classmethod
        def tearDownClass(cls):
            # discard any pending changes which might caused a messed up config
            cls._session.discard()
            # ... and restore the initial state
            cls._session.migrate_and_load_config(save_config)

            try:
                cls._session.commit()
            except (ConfigError, ConfigSessionError):
                cls._session.discard()
                cls.fail(cls)

        def cli_set(self, path, value=None):
            if self.debug:
                str = f'set {" ".join(path)} {value}' if value else f'set {" ".join(path)}'
                print(str)
            self._session.set(path, value)

        def cli_delete(self, config):
            if self.debug:
                print('del ' + ' '.join(config))
            self._session.delete(config)

        def cli_discard(self):
            if self.debug:
                print('DISCARD')
            self._session.discard()

        def cli_commit(self):
            if self.debug:
                print('commit')
            self._session.commit()
            # during a commit there is a process opening commit_lock, and run() returns 0
            while run(f'sudo lsof -nP {commit_lock}') == 0:
                sleep(0.250)

        def cli_save(self, file):
            if self.debug:
                print('save')
            self._session.save_config(file)

        def op_mode(self, path : list) -> None:
            """
            Execute OP-mode command and return stdout
            """
            if self.debug:
                print('commit')
            path = ' '.join(path)
            out = cmd(f'/opt/vyatta/bin/vyatta-op-cmd-wrapper {path}')
            if self.debug:
                print(f'\n\ncommand "{path}" returned:\n')
                pprint.pprint(out)
            return out

        def getFRRconfig(self, start_section:str=None, end_marker='$', stop_section='^!',
                         start_subsection:str=None, stop_subsection='^ exit', daemon=None) -> str:
            """
            Retrieve current "running configuration" from FRR

            start_section:    search for a specific start string in the configuration
            end_marker:       override default "line end $" marker to match on an
                              "open end" string
            stop_section:     end of the configuration
            start_subsection: search section under the result found by string
            stop_subsection:  end of the subsection (usually something with "exit")
            """
            tmp = 'show running-config'
            if daemon:
                tmp = f'{tmp} {daemon}'
            else:
                tmp = f'{tmp} no-header'
            rc, frr_config = rc_cmd(f'vtysh -c "{tmp}"')
            self.assertEqual(rc, 0)

            if not start_section:
                return frr_config

            extracted = []
            in_section = False
            for line in frr_config.splitlines():
                if not in_section:
                    if re.match(f'^{start_section}{end_marker}', line):
                        in_section = True
                        extracted.append(line)
                else:
                    extracted.append(line)
                    if re.match(stop_section, line):
                        break
            output = '\n'.join(extracted)

            # Use extracted list when searching for optional subsection
            # used by e.g. BGP address-family check
            if start_subsection:
                extracted_subsection = []
                in_subsection = False
                for line in extracted:
                    if not in_subsection:
                        if re.match(start_subsection, line):
                            in_subsection = True
                            extracted_subsection.append(line)
                    else:
                        extracted_subsection.append(line)
                        if re.match(stop_subsection, line):
                            break
                output = '\n'.join(extracted_subsection)

            if self.debug:
                print(output)
            return output

        @staticmethod
        def ssh_send_cmd(command, username, password, hostname='localhost'):
            """ SSH command execution helper """
            # Try to login via SSH
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=hostname, username=username, password=password)
            _, stdout, stderr = ssh_client.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            ssh_client.close()
            return output, error

        # Verify nftables output
        def verify_nftables(self, nftables_search, table, inverse=False, args=''):
            nftables_output = cmd(f'sudo nft {args} list table {table}')

            for search in nftables_search:
                matched = False
                for line in nftables_output.split("\n"):
                    if all(item in line for item in search):
                        matched = True
                        break
                self.assertTrue(not matched if inverse else matched, msg=search)

        def verify_nftables_chain(self, nftables_search, table, chain, inverse=False, args=''):
            nftables_output = cmd(f'sudo nft {args} list chain {table} {chain}')

            for search in nftables_search:
                matched = False
                for line in nftables_output.split("\n"):
                    if all(item in line for item in search):
                        matched = True
                        break
                self.assertTrue(not matched if inverse else matched, msg=search)

# standard construction; typing suggestion: https://stackoverflow.com/a/70292317
def ignore_warning(warning: Type[Warning]):
    import warnings
    from functools import wraps

    def inner(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=warning)
                return f(*args, **kwargs)
        return wrapped
    return inner
