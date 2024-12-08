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

from sys import exit
from sys import argv

from vyos.config import Config
from vyos.configdict import get_frrender_dict
from vyos.configverify import has_frr_protocol_in_dict
from vyos.configverify import verify_vrf
from vyos.frrender import FRRender
from vyos import ConfigError
from vyos import airbag
airbag.enable()

vrf = None
if len(argv) > 1:
    vrf = argv[1]

def get_config(config=None):
    if config:
        conf = config
    else:
        conf = Config()

    return get_frrender_dict(conf)

def verify(config_dict):
    global vrf
    if not has_frr_protocol_in_dict(config_dict, 'eigrp', vrf):
        return None

    # eqivalent of the C foo ? 'a' : 'b' statement
    eigrp = vrf and config_dict['vrf']['name'][vrf]['protocols']['eigrp'] or config_dict['eigrp']
    eigrp['policy'] = config_dict['policy']

    if 'system_as' not in eigrp:
        raise ConfigError('EIGRP system-as must be defined!')

    if 'vrf' in eigrp:
        verify_vrf(eigrp)

def generate(config_dict):
    if 'frrender_cls' not in config_dict:
        FRRender().generate(config_dict)
    return None

def apply(config_dict):
    if 'frrender_cls' not in config_dict:
        FRRender().apply()
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
