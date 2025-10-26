#!/bin/vbash
# Please note that this file is required in order to properly setup a VyOS
# ConfigSession for the CLI script to work on the system. Directly calling
# the CLI helper script from e.g. systemd certbot.timer will not work, as there
# will be no Config() available to the CLI script
source /opt/vyatta/etc/functions/script-template
/usr/libexec/vyos/op_mode/pki.py --action certbot_renew
