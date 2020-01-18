#!/usr/bin/env python3

"""
VMRun v1.2 (vmrun) command wrapper for VMWare (@haxxinen).

Usage:
  vmrun show_vms
  vmrun <vm-alias> start
  vmrun <vm-alias> stop
  vmrun <vm-alias> reboot
  vmrun <vm-alias> status
  vmrun <vm-alias> ssh
  vmrun <vm-alias> tools_deploy
  vmrun <vm-alias> tools_remove
  vmrun <vm-alias> pubkey
  vmrun <vm-alias> ip
  vmrun <vm-alias> share_on
  vmrun <vm-alias> share_off
  vmrun <vm-alias> share_list
  vmrun <vm-alias> share_add <local_dirpath>
  vmrun <vm-alias> share_remove <shared_dir>
  vmrun <vm-alias> share_permissions (writable|readonly) <local_dirpath>
  vmrun <vm-alias> push <local_path>
  vmrun <vm-alias> pull <remote_path>
  vmrun <vm-alias> show_tmp
  vmrun <vm-alias> make_sudoer
  vmrun <vm-alias> config

Options:
    show_vms          Show list if VMs from config.
    start             Power-on the VM.
    stop              Power-off the VM.
    reboot            Reboot the VM.
    ssh               SSH into the VM.
    tools_deploy      Deploy VMWare tools installer on the VM.
    tools_remove      Remove VMWare tools installer deployment.
    pubkey            Push locally stored SSH public key on the VM.
    ip                Get IP address of the VM.
    share_on          Turn on file sharing.
    share_off         Turn off file sharing.
    share_list        List shared files.
    share_add         Add directory to be shared.
    share_remove      Remove directory to be shared.
    share_permissions Modify RW sharing permissions.
    push              Push local file/directory on VM via SSH.
    pull              Pull remote file from VM via SSH.
    show_tmp          Directory listing for /tmp directory on VM.
    make_sudoer       Add SSH user to /etc/sudoers file (requires sudo password).
    config            Print(VM config info.)
"""

import json
import os
import platform
import socket
import subprocess
import getpass
import time

from docopt import docopt
from termcolor import colored

mac_os = 'darwin'
linux_os = 'linux'

vmware_cfg = {
    linux_os: {
        'ssh_pub_key_path': os.environ['HOME'] + '/.ssh/id_rsa.pub',
        'vmrun': '',
        'tools': {
            'linux': ''
        }
    },
    mac_os: {
        'ssh_pub_key_path': os.environ['HOME'] + '/.ssh/id_rsa.pub',
        'vmrun': "/Applications/VMware Fusion.app/Contents/Library/vmrun",
        'tools': {
            'linux': '/Applications/VMware Fusion.app/Contents/Library/isoimages/linux.iso'
        },
        'tools_mount_path': '/Volumes/VMware Tools/'
    }
}

this_platform = platform.system().lower()


def print_error(err, quit=True):
    print(colored(err, 'red'))
    if quit:
        exit(1)


def print_success(msg):
    print(colored(msg, 'green'))


def print_error_unknown(action):
    print_error('Unknown error occurred: ' + action)


def run_command(command):
    if not isinstance(command, list):
        print_error('run_command() expects a list.')

    cmd = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout = cmd.stdout.read()
    stderr = cmd.stderr.read()

    cmd_ret = stdout if len(stdout) is not 0 else stderr

    if 'Error: Cannot open VM' in cmd_ret:
        cmd_ret = handle_error(cmd_ret, command)

    return cmd_ret


def handle_error(stdout, cmd):
    global password

    def execute_cmd_with_password():
        global password
        while password is None or len(password) is 0:
            password = getpass.getpass('VM Password: ')

        cmd[2] = password
        return run_command(cmd)

    if 'password is required' in stdout:
        cmd.insert(1, '-vp')
        cmd.insert(2, 'password')
        stdout = execute_cmd_with_password()

    elif 'Incorrect password' in stdout:
        while 'Incorrect password' in stdout:
            print_error('Wrong password!', quit=False)
            password = ''
            stdout = execute_cmd_with_password()
    else:
        print_error_unknown(cmd[3] + ' (' + (' '.join(stdout.replace('\n', '').split('Error: ')[1:])) + ')')

    return stdout


def vm_is_powered_on():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, 22))
        status = True
    except socket.error:
        status = False
    s.close()

    return status


def copy_to_vm(local_path, remote_path):
    if not os.path.exists(local_path):
        print_error('Argument <local_path> not a file/directory.')

    if not exists_on_remote(remote_path):
        print_error('Destination does not exist on guest OS.')

    run_command(['scp', '-r', local_path, str(ssh_user + '@' + host + ':' + remote_path)])


def copy_from_vm(remote_path, local_path):
    if not exists_on_remote(remote_path):
        print_error('Argument <remote_path> does not exist on remote host.')

    if not os.path.exists(local_path):
        print_error('Destination does not exist on host OS.')

    run_command(['scp', '-r', str(ssh_user + '@' + host + ':' + remote_path), local_path])


def tools_copy_to_vm(tools_mount_path):
    print(colored('Trying to deploy VMWare tools on VM.', 'yellow'))
    copy_to_vm(tools_mount_path, '/tmp/vmware_tools')
    if tools_exists_on_vm():
        print_success('Successfully deployed VMWare tools installer on VM.')


def tools_mount(tools_image, tools_mount_path):
    if not os.path.isfile(tools_image):
        print_error('Wrong VMWare tools image path. File not found.')

    if this_platform == mac_os:
        run_command(['hdiutil', 'mount', tools_image])
    elif this_platform == linux_os:
        pass

    if not os.path.isdir(tools_mount_path):
        print_error('Could not mount VMware tools image.')
    else:
        print_success('Mounted VMWare tools image.')


def tools_unmount(tools_image, tools_mount_path):
    if this_platform == mac_os:
        output = run_command(['hdiutil', 'unmount', tools_mount_path])
    elif this_platform == linux_os:
        pass

    if 'unmounted successfully' not in output and not os.path.isdir(tools_mount_path):
        print_error('Could not unmount:' + tools_image)


def check_if_vm_is_on():
    if not vm_is_powered_on():
        print_error('VM is not running.')


def tools_exists_on_vm():
    cmd_ret = run_command(
        ['ssh', str(ssh_user + '@' + host), '[ ! -e /tmp/vmware_tools ] && echo False || echo True']
    ).replace('\n', '')
    return False if cmd_ret == 'False' else True


def check_if_tools_installed():
    cmd_ret = run_command(
        ['ssh', str(ssh_user + '@' + host), '[ ! -e /etc/vmware-tools ] && echo False || echo True']
    ).replace('\n', '')
    return False if cmd_ret == 'False' else True


def check_if_tools_running():
    cmd_ret = run_command(
        ['ssh', str(ssh_user + '@' + host), '/etc/init.d/vmware-tools status']
    ).replace('\n', '')
    return False if 'not running' in cmd_ret else True


def ssh_key_data_to_list(d):
    return [' '.join(line.replace('\n', '').split(' ')[0:2]) for line in d if len(line) is not 0]


def read_ssh_pubkey(file_path):
    with open(file_path, 'r') as pub_key:
        return ' '.join(ssh_key_data_to_list(pub_key.readlines()))


def read_authorized_keys():
    return ssh_key_data_to_list(
        [run_command([
            'ssh', '-o BatchMode=yes',
            str(ssh_user + '@' + host),
            str('cat /home/' + ssh_user + '/.ssh/authorized_keys')
        ])]
    )


def user_can_ssh_login():
    output = run_command(['ssh', str(ssh_user + '@' + host), '-n', '-o BatchMode=yes'])
    return False if 'Permission denied' and 'publickey' in output else True


def push_pubkey_in_authorized_hosts(ssh_pub_key):
    print_success('SSHing to add your public key...')
    return run_command(
        [
            'ssh',
            str(ssh_user + '@' + host),
            '[ ! -e ~/.ssh/ ] && mkdir ~/.ssh/; echo ' + ssh_pub_key + ' >> ~/.ssh/authorized_keys'
        ]
    )


def run_sudo_command(command, sudo_pwd):
    command = command.replace("'", '"')
    command = command.replace('"', '\\"')

    cmd_ret = run_command([
        'expect', '-c',
        "spawn ssh -tt " + str(ssh_user + '@' + host) +
        " \"su -c '" + command + "'\"; expect \"Password:\"; send \"" + sudo_pwd + "\n\"; interact"
    ])
    import re
    cmd_ret = re.sub('^spawn.*', '', cmd_ret)
    cmd_ret = re.sub('Password:', '', cmd_ret)
    cmd_ret = re.sub('Connection to.*closed.*', '', cmd_ret)
    return cmd_ret.strip()


def read_su_password():
    sudo_pwd = None
    while sudo_pwd is None or len(sudo_pwd) is 0:
        sudo_pwd = getpass.getpass('SU password: ')
    return sudo_pwd


def make_sudoer():
    check_if_vm_is_on()
    sudo_pwd = None
    cmd_ret = None
    sudoers_line = "'" + ssh_user + " ALL=(ALL) NOPASSWD:ALL'"

    while cmd_ret is None or 'Authentication failure' in cmd_ret:
        sudo_pwd = read_su_password()
        cmd_ret = run_sudo_command("grep " + sudoers_line + " /etc/sudoers | grep -v '#' | sort -u", sudo_pwd)
        if 'Authentication failure' in cmd_ret:
            print_error('Incorrect root password.', quit=False)

    if sudoers_line.replace("'", '') == cmd_ret:
        print_error('This user is already in the sudoers file.')
    else:
        cmd_ret = run_sudo_command("echo " + sudoers_line + " >> /etc/sudoers", sudo_pwd)
        if len(cmd_ret) == 0:
            print_success('SSH user added to sudoers file.')
        else:
            print_error('There was an error while adding SSH user to sudoers file.')


def sshuser_is_sudoer():
    check_if_vm_is_on()
    cmd_ret = run_command(['ssh', str(ssh_user + '@' + host), str('sudo whoami')]).replace('\n', '')
    return True if cmd_ret == 'root' else False


def list_dir(remote_dir):
    check_if_vm_is_on()
    output = run_command(['ssh', str(ssh_user + '@' + host), 'ls -laF ' + remote_dir])
    if 'No such file or directory' in output:
        print_error('File sharing not activated yet.')
    if "cannot access '/mnt/hgfs/'" in output:
        print_error('File sharing not activated yet.')
    else:
        print(output)


def wait_for_power():
    t = 0
    while not vm_is_powered_on():
        time.sleep(0.5)
        if t == 40:
            print_error('Looks like the VM is stuck...?', quit=False)
        t = t + 1


def start():
    if not vm_is_powered_on():
        stdout = run_command([vmrun, 'start', vm_file, 'nogui'])
        if 'PID' in stdout:
            print_success('VM is now booting up...')
    else:
        print_success('VM is already running.')

    wait_for_power()
    share_off() # to fix VMWare share
    share_on()
    ssh()


def stop(hard=False):
    if not hard:
        check_if_vm_is_on()
        run_command([vmrun, 'stop', str(vm_file), 'soft'])
    else:
        run_command([vmrun, 'stop', str(vm_file), 'hard'])

    print_success('VM is terminated.')


def reboot():
    stop()
    start()


def ssh():
    check_if_vm_is_on()
    subprocess.call(['ssh', '-o', 'ConnectTimeout=1', str(ssh_user + '@' + host)])


def check_tools_on_guest():
    if not check_if_tools_installed():
        print_error('Gotta first install VMWare tools to do that.')
    if not check_if_tools_running():
        print_error('VMWare tools service not running.')


def update_shared_folders_state(state=None):
    check_if_vm_is_on()
    check_tools_on_guest()
    ret_cmd = run_command([vmrun, state, str(vm_file)])
    print_error(ret_cmd) if len(ret_cmd) != 0 else print_success('Done!')


def share_on():
    update_shared_folders_state('enableSharedFolders')


def share_off():
    update_shared_folders_state('disableSharedFolders')


def share_add(local_dirpath):
    check_if_vm_is_on()
    check_tools_on_guest()

    if not os.path.isdir(local_dirpath):
        print_error('Argument for <local_dirpath> must be a directory.')

    local_dirpath = os.path.abspath(local_dirpath)
    basename = ''.join([directory for directory in local_dirpath.split('/') if len(directory) is not 0][-1:])

    run_command([vmrun, 'addSharedFolder', vm_file, basename, local_dirpath])


def share_remove(shared_dir):
    check_if_vm_is_on()
    check_tools_on_guest()
    run_command([vmrun, 'removeSharedFolder', vm_file, shared_dir])


def share_list():
    list_dir('/mnt/hgfs/')


def share_permissions(local_dirpath, permission):
    check_if_vm_is_on()

    if not os.path.isdir(local_dirpath):
        print_error('Argument for <local_dirpath> must be a directory.')

    basename = ''.join([directory for directory in local_dirpath.split('/') if len(directory) is not 0][-1:])
    print(run_command([vmrun, 'setSharedFolderState', vm_file, basename, local_dirpath, permission]))


def tools_remove():
    check_if_vm_is_on()

    if not tools_exists_on_vm():
        print_error('VMWare tools not deployed on machine. Nothing to remove.')

    if not sshuser_is_sudoer():
        print_error('Not in /etc/sudoers file: ' + ssh_user)

    cmd_ret = run_command(['ssh', str(ssh_user + '@' + host), 'sudo rm -r /tmp/vmware_tools'])
    if len(cmd_ret) == 0:
        print_success('Successfully removed VMWare tools installer from VM.')
    else:
        print_error('There was an error while removing the /tmp/vmware_tools directory.')


def tools_deploy():
    check_if_vm_is_on()

    if tools_exists_on_vm():
        print_error('VMWare tools already deployed.')

    if check_if_tools_installed():
        print_error('VMWare tools already installed, but deploying anyways...', quit=False)

    tools_image = vmware_cfg[this_platform]['tools']['linux']
    tools_mount_path = vmware_cfg[this_platform]['tools_mount_path']

    tools_mount(tools_image, tools_mount_path)
    tools_copy_to_vm(tools_mount_path)
    tools_unmount(tools_image, tools_mount_path)


def pubkey():
    check_if_vm_is_on()
    ssh_pub_key_path = vmware_cfg[this_platform]['ssh_pub_key_path']
    if not os.path.isfile(ssh_pub_key_path):
        print_error('File not found in config: "ssh_pub_key_path".')

    ssh_pub_key = read_ssh_pubkey(ssh_pub_key_path)

    can_login = user_can_ssh_login()
    if (not can_login):
        push_pubkey_in_authorized_hosts(ssh_pub_key + ' ' + getpass.getuser())

    if ssh_pub_key in read_authorized_keys():
        print_success('Your public SSH key is authorized on VM.')
        ssh()


def exists_on_remote(remote_path):
    return False if 'No such file or directory' in run_command(
        ['ssh', str(ssh_user + '@' + host), 'file ' + remote_path]
    ) else True


def pull(remote_path):
    check_if_vm_is_on()

    local_home_dir = os.path.expanduser('~')
    if local_home_dir in remote_path:
        remote_path = '~/' + remote_path.strip(local_home_dir)

    copy_from_vm(remote_path, '/tmp')


def push(local_path):
    check_if_vm_is_on()
    copy_to_vm(local_path, '/tmp')
    print_success('Done!')


def show_tmp():
    list_dir('/tmp')


def print_config():
    print("IP:", host)
    print("SSH-user:", ssh_user)
    print("VM-file:", vm_file)


########################


def trigger():
    if arguments['start']:
        start()

    if arguments['stop']:
        stop()

    if arguments['reboot']:
        reboot()

    if arguments['status']:
        print_success('VM is powered on.') if vm_is_powered_on() else print_error('VM is powered off.')

    if arguments['ssh']:
        ssh()

    if arguments['tools_deploy']:
        tools_deploy()

    if arguments['tools_remove']:
        tools_remove()

    if arguments['pubkey']:
        pubkey()

    if arguments['ip']:
        print(host)

    if arguments['share_on']:
        share_on()

    if arguments['share_off']:
        share_off()

    if arguments['share_list']:
        share_list()

    if arguments['share_add']:
        share_add(arguments['<local_dirpath>'])

    if arguments['share_remove']:
        share_remove(arguments['<shared_dir>'])

    if arguments['share_permissions']:
        share_permissions(arguments['<local_dirpath>'], 'readonly' if arguments['readonly'] else 'writable')

    if arguments['push']:
        push(arguments['<local_path>'])

    if arguments['pull']:
        pull(arguments['<remote_path>'])

    if arguments['show_tmp']:
        show_tmp()

    if arguments['make_sudoer']:
        make_sudoer()

    if arguments['config']:
        print_config()


if __name__ == '__main__':
    try:
        arguments = docopt(__doc__)
        vm_alias = arguments['<vm-alias>']

        config_file = os.environ['HOME'] + '/.vmrun_config.json'

        if not os.path.exists(config_file):
            print_error('Missing config file at: ' + config_file)

        with open(config_file) as data:
            vms_cfg = json.load(data)

        if arguments['show_vms']:
            print('\n'.join([i for i in vms_cfg]))
            exit(0)

        if vm_alias not in vms_cfg:
            print_error('VM alias "' + vm_alias + '" not found in vms_cfg.')

        if len(vms_cfg[vm_alias]['host']) is 0 or len(vms_cfg[vm_alias]['ssh_user']) is 0:
            print_error('VM alias IP or SSH user for "' + vm_alias + '" not found in vms_cfg.')

        else:
            host = vms_cfg[vm_alias]['host']
            ssh_user = vms_cfg[vm_alias]['ssh_user']
            vm_file = vms_cfg[vm_alias]['vm_file']
            password = vms_cfg[vm_alias]['password'] if 'password' in vms_cfg[vm_alias] else None

        vmrun = vmware_cfg[this_platform]['vmrun']

        if not os.path.isfile(vmrun):
            print_error('Wrong "vmrun" path. File not found or VMWare not installed?')

        if not os.path.isdir(vm_file):
            print_error('Wrong VM directory path. Directory not found.')

        trigger()

    except KeyboardInterrupt:
        exit('')
    except EOFError:
        exit('')
