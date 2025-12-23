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

from copy import deepcopy
from sys import exit
from syslog import syslog
from syslog import LOG_INFO

from vyos.base import DeprecationWarning
from vyos.config import Config
from vyos.configdict import is_node_changed
from vyos.configverify import verify_vrf
from vyos.defaults import SSH_DSA_DEPRECATION_WARNING
from vyos.utils.dict import dict_search
from vyos.utils.process import call
from vyos.utils.process import rc_cmd
from vyos.template import render
from vyos import ConfigError
from vyos import airbag
airbag.enable()

config_file = r'/run/sshd/sshd_config'

sshguard_config_file = '/etc/sshguard/sshguard.conf'
sshguard_whitelist = '/etc/sshguard/whitelist'

key_rsa = '/etc/ssh/ssh_host_rsa_key'
key_dsa = '/etc/ssh/ssh_host_dsa_key'
key_ed25519 = '/etc/ssh/ssh_host_ed25519_key'

login_motd_dsa_warning = r'/run/motd.d/91-vyos-ssh-dsa-deprecation-warning'
cipher_rijndael_cbd = 'rijndael-cbc@lysator.liu.se'
cipher_aes256_cbc = 'aes256-cbc'

# As of OpenSSH 9.8p1 in Debian trixie, DSA keys are no longer supported
deprecated_algos = ['ssh-dss', 'ssh-dss-cert-v01@openssh.com']
SSH_DSA_DEPRECATION_WARNING: str = f'{SSH_DSA_DEPRECATION_WARNING} '\
'The following hostkey-algorithms are in use:'

def get_config(config=None):
    if config:
        conf = config
    else:
        conf = Config()
    base = ['service', 'ssh']
    if not conf.exists(base):
        return None

    ssh = conf.get_config_dict(base, key_mangling=('-', '_'), get_first_key=True)

    tmp = is_node_changed(conf, base + ['vrf'])
    if tmp: ssh.update({'restart_required': {}})

    # We have gathered the dict representation of the CLI, but there are default
    # options which we need to update into the dictionary retrived.
    ssh = conf.merge_defaults(ssh, recursive=True)

    # pass config file path - used in override template
    ssh['config_file'] = config_file

    # Ignore default XML values if config doesn't exists
    # Delete key from dict
    if not conf.exists(base + ['dynamic-protection']):
         del ssh['dynamic_protection']

    return ssh

def verify(ssh):
    if not ssh:
        return None

    if 'rekey' in ssh and 'data' not in ssh['rekey']:
        raise ConfigError(f'Rekey data is required!')

    if 'hostkey_algorithm' in ssh:
        tmp = [algo for algo in ssh['hostkey_algorithm'] if algo in deprecated_algos]
        if tmp: DeprecationWarning(f'{SSH_DSA_DEPRECATION_WARNING} {", ".join(tmp)}')

    if 'ciphers' in ssh and cipher_rijndael_cbd in ssh['ciphers']:
        DeprecationWarning(f'Support for {cipher_rijndael_cbd} (a pre-standard name '\
                           f'for {cipher_aes256_cbc}) will be removed in VyOS 1.5; ' \
                           f'internal usage has moved to {cipher_aes256_cbc}.')

    verify_vrf(ssh)
    return None

def generate(ssh):
    if not ssh:
        if os.path.isfile(config_file):
            os.unlink(config_file)

        return None

    # This usually happens only once on a fresh system, SSH keys need to be
    # freshly generted, one per every system!
    if not os.path.isfile(key_rsa):
        syslog(LOG_INFO, 'SSH RSA host key not found, generating new key!')
        call(f'ssh-keygen -q -N "" -t rsa -f {key_rsa}')
    if not os.path.isfile(key_dsa):
        syslog(LOG_INFO, 'SSH DSA host key not found, generating new key!')
        call(f'ssh-keygen -q -N "" -t dsa -f {key_dsa}')
    if not os.path.isfile(key_ed25519):
        syslog(LOG_INFO, 'SSH ed25519 host key not found, generating new key!')
        call(f'ssh-keygen -q -N "" -t ed25519 -f {key_ed25519}')

    # T8098: use aes256-cbc over rijndael-cbc@lysator.liu.se
    ciphers = dict_search('ciphers', ssh)
    if ciphers and cipher_rijndael_cbd in ciphers:
        ssh['ciphers'].remove(cipher_rijndael_cbd)
        if cipher_aes256_cbc not in ciphers:
            ssh['ciphers'].append(cipher_aes256_cbc)

    render(config_file, 'ssh/sshd_config.j2', ssh)

    # Generate MOTD informing the user(s) for possible deprecated SSH hostkey-algorithm
    tmp = deepcopy(ssh)
    tmp['ssh_dsa_deprecation_warning'] = f'DEPRECATION WARNING: {SSH_DSA_DEPRECATION_WARNING}'
    tmp['deprecated_algos'] = deprecated_algos
    render(login_motd_dsa_warning, 'ssh/motd_ssh_dsa_warning.j2', tmp,
        permission=0o644, user='root', group='root')

    if 'dynamic_protection' in ssh:
        render(sshguard_config_file, 'ssh/sshguard_config.j2', ssh)
        render(sshguard_whitelist, 'ssh/sshguard_whitelist.j2', ssh)

    return None

def apply(ssh):
    systemd_service_ssh = 'ssh.service'
    systemd_service_sshguard = 'sshguard.service'
    if not ssh:
        # SSH access is removed in the commit
        call(f'systemctl stop ssh@*.service')
        call(f'systemctl stop {systemd_service_sshguard}')
        return None

    # Verify generated sshd configuration is correct
    rc, out = rc_cmd(f'/usr/sbin/sshd -t -f {config_file}')
    if rc:
        raise ConfigError(f'Unexpected error with SSH configuration! {out}')

    if 'dynamic_protection' not in ssh:
        call(f'systemctl stop {systemd_service_sshguard}')
    else:
        call(f'systemctl reload-or-restart {systemd_service_sshguard}')

    # we need to restart the service if e.g. the VRF name changed
    systemd_action = 'reload-or-restart'
    if 'restart_required' in ssh:
        # this is only true if something for the VRFs changed, thus we
        # stop all VRF services and only restart then new ones
        call(f'systemctl stop ssh@*.service')
        systemd_action = 'restart'

    for vrf in ssh['vrf']:
        call(f'systemctl {systemd_action} ssh@{vrf}.service')
    return None

if __name__ == '__main__':
    try:
        c = get_config()
        verify(c)
        generate(c)
        apply(c)
    except ConfigError as e:
        print(e)
        exit(1)
