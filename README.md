# vmrun
VMRun (vmrun) command wrapper for VMWare.

## Setup

##### 1. Install
```
$ git clone https://github.com/haxxinen/vmrun && mv vmrun .vmrun && cd .vmrun
$ bash install.sh
```

##### 1. Configuration in `~/.vmrun_config.json`
```json
{
  "jessie": {
    "host": "192.168.1.101",
    "ssh_user": "myuser",
    "vm_file": "/tmp/jessie.vmwarevm",
    "password": ""
  }
}
```

###### Keywords

* `"jessie": { ... }` - main VM alias-name that you will use when running the script (can be modified at will)
* `host` - the IP address of the VM (preferably static)
* `ssh_user` - the user that will be used when using the `vmrun <vm-alias> ssh` command
* `vm_file` - the VM file that will be used for this entry
* `password` - password for encrypted VMWare boxes (optional parameter;
               up to you to set it up - in case VM is encrypted but the
               password is missing in the config file, you will get a
               prompt to enter the decryption key)

##### 4. Restart `bash` session to apply changes

## Usage

##### 1. Help menu
```console
$ vmrun --help
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
```

##### 2. In action
```console
$ vmrun jessie status
VM is powered on.
$ touch test.txt
$ vmrun jessie push test.txt
$ vmrun jessie show_tmp | grep -oE test.txt
test.txt
$ vmrun jessie ssh
        \\
         \\_
      .---(')
    o( )_-\_
Follow the rabbit! Don't stop!
user@jessie:~$
```
