# macOS VM's for tstest and natlab

## Building

```
%make all
```

Will build both the TailMac and the VMHost app.  You will need a developer account.  The default bundle identifiers
default to tailscale owned ids, so if you don't have (or aren't using) a tailscale dev account, you will need to change this.
This should build automatically as long as you have a valid developer cert.  Signing is automatic.  The binaries both
require proper entitlements, so they do need to be signed.

There are separate recipes in the makefile to rebuild the individual components if needed.

All binaries are copied to the bin directory.

You can generally do all interactions via the TailMac command line util.

## Locations

Everything is persisted at ~/VM.bundle

Each vm gets it's own directory under there.  

RestoreImage.ipsw is used to build new VMs.  You may replace this manually if you wish.

Individual parameters for each instance are saved in a json config file (config.json)

## Installing

### Default a parameters

The default virtio socket device port is 51009
The default server socket for the virtual network device is /tmp/qemu.sock
The default memory size is 4Gb
The default mac address for the socket based network is 5a:94:ef:e4:0c:ee
The defualt mac address for normal ethernet is 5a:94:ef:e4:0c:ef

All of these parameters are configurable.

### Creating and managing VMs

To create a new VM (this will grab a restore image if needed).  Restore images are large.  Installation takes a minute
```
TailMac create --id my_vm_id
```

To delete a new VM 
```
TailMac delete --id my_vm_id
```

To refresh an existing restore image:
```
TailMac refresh
```

To clone an existing vm (this will clone the mac and port as well)
```
TailMac clone --id old_vm_id --target-id new_vm_id
```

To reconfigure a vm with a specific mac and a virtio socket device port:
```
TailMac configure --id vm_id --mac 11:22:33:44:55:66 --port 12345 --ethermac 22:33:44:55:66:77 --mem 4000000000 --sock "/var/netdevice.sock"
```

## Running a VM

MacHost is an app bundle, but the main binary behaves as a command line util.  You can invoke it
thusly:

```
TailMac --id machine_1
 ```

 You may invoke multiple vms, but the limit on the number of concurrent instances is on the order of 2.

 To stop a running VM (this is a fire and forget thing):

 ```
 TailMac stop --id machine_1
 ```
