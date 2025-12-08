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
import argparse
import glob
from datetime import datetime
from pathlib import Path
from shutil import rmtree

from socket import gethostname
from sys import exit
from tarfile import open as tar_open
from vyos.utils.process import cmd
from vyos.utils.process import call
from vyos.utils.process import rc_cmd
from vyos.remote import upload

def op(cmd: str) -> str:
    """Returns a command with the VyOS operational mode wrapper."""
    return f'/opt/vyatta/bin/vyatta-op-cmd-wrapper {cmd}'

def save_stdout(command: str, file: Path) -> None:
    rc, stdout = rc_cmd(command)
    body: str = f'''### {command} ###
Command: {command}
Exit code: {rc}
Stdout:
{stdout}

'''
    with file.open(mode='a') as f:
        f.write(body)
def __rotate_logs(path: str, log_pattern:str):
    files_list = glob.glob(f'{path}/{log_pattern}')
    if len(files_list) > 5:
        oldest_file = min(files_list, key=os.path.getctime)
        os.remove(oldest_file)


def __generate_archived_files(location_path: str) -> None:
    """
    Generate arhives of main directories
    :param location_path: path to temporary directory
    :type location_path: str
    """
    # Dictionary arhive_name:directory_to_arhive
    archive_dict = {
        'etc': '/etc',
        'home': '/home',
        'var-log': '/var/log',
        'root': '/root',
        'tmp': '/tmp',
        'core-dump': '/var/core',
        'config': '/opt/vyatta/etc/config'
    }
    # Dictionary arhive_name:excluding pattern
    archive_excludes = {
        # Old location of archives
        'config': 'tech-support-archive',
        # New locations of arhives
        'tmp': 'tech-support-archive'
    }
    for archive_name, path in archive_dict.items():
        archive_file: str = f'{location_path}/{archive_name}.tar.gz'
        with tar_open(name=archive_file, mode='x:gz') as tar_file:
            if archive_name in archive_excludes:
                tar_file.add(path, filter=lambda x: None if str(archive_excludes[archive_name]) in str(x.name) else x)
            else:
                tar_file.add(path)


def __generate_main_archive_file(archive_file: str, tmp_dir_path: str) -> None:
    """
    Generate main arhive file
    :param archive_file: name of arhive file
    :type archive_file: str
    :param tmp_dir_path: path to arhive memeber
    :type tmp_dir_path: str
    """
    with tar_open(name=archive_file, mode='x:gz') as tar_file:
        tar_file.add(tmp_dir_path, arcname=os.path.basename(tmp_dir_path))

def __generate_topology_snapshots(output_dir: Path) -> None:
    """
    Generates physical and logical topology PNG files using `lstopo`
    :param output_dir: directory where topology PNGs will be stored
    """

    physical_topo = output_dir / 'topology.png'
    logical_topo = output_dir / 'topology-logical.png'

    # Capture physical topology
    call(['lstopo', '--output-format', 'png', str(physical_topo)])

    # Capture logical topology
    call(['lstopo', '--logical', '--output-format', 'png', str(logical_topo)])

def __ensure_known_host_has_entry(host: str, port: int = 22) -> bool:
    """
    Ensure the SSH host key for this server is the first plain‑text entry in
    known_hosts.

    cURL's SFTP implementation can fail key exchange when the file
    begins with unrelated hashed hosts, because it may select the wrong hostkey
    type. By adding or moving the correct key to the beginning of the file, we
    guarantee that cURL negotiates successfully and the upload works.

    Returns True if file was modified, otherwise False.

    :param host: hostname of the server
    :type host: str
    :param port: port of the server
    :type port: int
    """

    known_hosts = Path('/root/.ssh/known_hosts')
    if not known_hosts.exists():
        return False  # No change needed for not existing file

    # Read current contents
    lines = [line.rstrip() for line in known_hosts.read_text().splitlines()]

    # Check if the first line already matches this host
    if lines and lines[0].startswith(f'{host} '):
        return False  # No change needed

    # Run ssh-keyscan to get the current host key
    try:
        result = cmd(['ssh-keyscan', '-p', str(port), host])
    except OSError as err:
        print(err)
        return False  # Failed to run ssh-keyscan, treat as no change

    keys = result.strip().splitlines()
    if not keys:
        return False  # No changes are required since there are no host keys
    new_key = keys[0]

    # Remove all existing plain entries for the same host (avoid duplicates)
    new_lines = [line for line in lines if not line.startswith(f'{host} ')]

    # Insert new key at the top
    new_lines.insert(0, new_key)

    # Atomic write back
    temp_known_hosts = known_hosts.with_suffix('.tmp')
    temp_known_hosts.write_text('\n'.join(new_lines) + '\n')
    os.replace(temp_known_hosts, known_hosts)  # atomic rename

    return True

def __upload_to_vyos(path: str, ticket: str, user: str):
    """
    Upload an archive over SFTP to VyOS support system.

    :param path: path to archived file
    :type path: str
    :param ticket: ID of the ticket provided by user
    :type ticket: str
    :param user: name of user for uploading archive
    :type user: str
    """

    host = 'ticket-files.vyos.io'

    # XXX: cURL SFTP host key workaround
    # When cURL performs SFTP transfers using libssh2 it reads /root/.ssh/known_hosts
    # to decide which host‑key algorithms to prefer during the SSH handshake.
    # If the first entry in known_hosts is a hashed hostname, cURL cannot
    # identify which host it belongs to and may incorrectly apply its key type
    # (for example "ssh‑rsa" instead "ssh-ed25519") to every connection.
    # Many modern servers disable older algorithms like ssh‑rsa,
    # so the handshake can fail with:
    #
    #     * Connected to example.com (127.0.0.1) port 22
    #     * libssh2 cryptography backend: openssl compatible
    #     * Found host example.com in /root/.ssh/known_hosts
    #     * Set "ssh‑rsa" as SSH hostkey type
    #     * Failure establishing ssh session: -5, Unable to exchange encryption keys
    #
    # More details about this bug here:
    #  - https://github.com/libssh2/libssh2/issues/676#issuecomment-1741877207
    #
    # To avoid this, we ensure that the correct host's plain‑text key entry is
    # explicitly present and placed at the beginning of known_hosts before running
    # cURL. The function below does the following:
    #
    #   * Runs ssh‑keyscan to obtain the current public host key for the target.
    #   * If an entry for the host already exists and is the first line, no action
    #     is taken (idempotent behavior).
    #   * If the entry exists deeper in the file, it is moved to the top.
    #   * If no entry exists, it is added as the first line.
    #
    # This guarantees that cURL's SFTP logic reads the correct key information
    # first, avoiding false key‑type restrictions and ensuring reliable transfers.
    known_host_modified = __ensure_known_host_has_entry(host)
    if known_host_modified:
        print(f'Updated `known_hosts` for {host}')

    # XXX: we call curl here because cURL's SFTP can work
    # without requiring directory listing on the server
    # Almost everything else requires it and fails to work
    # with our write-only server.
    os.system(f'curl --upload-file {path} sftp://{host}/{ticket}/ --user {user}')


if __name__ == '__main__':
    defualt_tmp_dir = '/tmp'
    parser = argparse.ArgumentParser()
    parser.add_argument("--ticket", type=str)
    parser.add_argument("--user", type=str)
    parser.add_argument("path", nargs='?', default=defualt_tmp_dir)
    args = parser.parse_args()
    location_path = args.path[:-1] if args.path[-1] == '/' else args.path

    hostname: str = gethostname()
    time_now: str = datetime.now().isoformat(timespec='seconds').replace(":", "-")

    remote = False
    tmp_path = ''
    tmp_dir_path = ''
    if ('ftp://' in args.path or 'scp://' in args.path) or args.ticket:
        remote = True
        tmp_path = defualt_tmp_dir
    else:
        tmp_path = location_path
    archive_pattern = f'_tech-support-archive_'
    archive_file_name = f'{hostname}{archive_pattern}{time_now}.tar.gz'

    # Log rotation in tmp directory
    if tmp_path == defualt_tmp_dir:
        __rotate_logs(tmp_path, f'*{archive_pattern}*')

    # Temporary directory creation
    tmp_dir_path = f'{tmp_path}/drops-debug_{time_now}'
    tmp_dir: Path = Path(tmp_dir_path)
    tmp_dir.mkdir(parents=True)

    archive_file_path = f'{tmp_path}/{archive_file_name}'

    report_file: Path = Path(f'{tmp_dir_path}/show_tech-support_report.txt')
    report_file.touch()

    # Call the topology snapshot function here
    __generate_topology_snapshots(tmp_dir)

    try:

        save_stdout(op('show tech-support report'), report_file)
        # Generate included archives
        __generate_archived_files(tmp_dir_path)

        # Generate main archive
        __generate_main_archive_file(archive_file_path, tmp_dir_path)
        # Delete temporary directory
        rmtree(tmp_dir)
        # Upload to remote site if it is scpecified
        if remote:
            if args.ticket:
                __upload_to_vyos(archive_file_path, args.ticket, args.user)
            else:
                upload(archive_file_path, args.path)
        print(f'Debug file is generated and located in {location_path}/{archive_file_name}')
    except Exception as err:
        print(f'Error during generating a debug file: {err}')
        # cleanup
        if tmp_dir.exists():
            rmtree(tmp_dir)
    finally:
        # cleanup
        exit()
