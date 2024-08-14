# Lightweight macOS VM's for tstest and natlab

This utility is designed to provide custom virtual machine tooling support for macOS.  The intent
is to quickly create and spin up small, preconfigured virtual machines, for executing integration
and unit tests.

The primary driver is to provide support for VZVirtioNetworkDeviceConfiguration which is not 
supported by other popular macOS VM hosts.  This also gives us the freedom to fully customize and script
all virtual machine setup and interaction. VZVirtioNetworkDeviceConfiguration lets us
directly inject and sink network traffic for simulating various network conditions,
protocols, and topologies and ensure that the TailScale clients handle all of these situations correctly.

This may also be used as a drop-in replacement for UTM or Tart on ARM Macs for quickly spinning up 
test VMs.  It has the added benefit that, unlike UTM which uses AppleScript, it can be run
via SSH.

This uses Virtualization.framework which only supports arm64.  The binaries only build for arm64.


## Components

The application is built in two components:

The tailmac command line utility is used to set up and configure VM instances. The Host.app does the heavy lifting.

You will typically initiate all interactions via the tailmac command-line util.

For a full list of options:
```
tailmac -h
```


## Building

```
% make all
```

Will build both the tailmac command line util and Host.app.  You will need a developer account.  The default bundle identifiers
default to TailScale owned ids, so if you don't have (or aren't using) a TailScale dev account, you will need to change this.
This should build automatically as long as you have a valid developer cert.  Signing is automatic.  The binaries both
require the virtualization entitlement, so they do need to be signed.

There are separate recipes in the makefile to rebuild the individual components if needed.

All binaries are copied to the bin directory.


## Locations

All vm images, restore images, block device files, save states, and other supporting files are persisted at ~/VM.bundle

Each vm gets its own directory.  These can be archived for posterity to preserve a particular image and/or state.
The mere existence of a directory containing all of the required files in ~/VM.bundle is sufficient for tailmac to 
be able to see and run it.  ~/VM.bundle and it's contents *is* tailmac's state.  No other state is maintained elsewhere.

Each vm has its own custom configuration which can be modified while the vm is idle.  It's simple JSON - you may
modify this directly, or using 'tailmac configure'.


## Installing

### Default a parameters

* The default virtio socket device port is 51009
* The default server socket for the virtual network device is /tmp/qemu-dgram.sock
* The default memory size is 4Gb
* The default mac address for the socket based networking is 52:cc:cc:cc:cc:01
* The default mac address for the standard ethernet interface is 52:cc:cc:cc:ce:01

### Creating and managing VMs

 You generally perform all interactions via the tailmac command line util. A NAT ethernet device is provided so
 you can ssh into your instance. The ethernet IP will be dhcp assigned by the host and can be determined by parsing 
 the contents of /var/db/dhcpd_leases

#### Creation

To create a new VM (this will grab a restore image for what apples deems a 'latest; if needed).  Restore images are large 
(on the order of 10 Gb) and installation after downloading takes a few minutes.   If you wish to use a custom restore image,
specify it with the --image option.  If RestoreImage.ipsw  exists in ~/VM.bundle, it will be used.  macOS versions from 
12 to 15 have been tested and appear to work correctly.
```
tailmac create --id my_vm_id 
```

With a custom restore image and parameters:
```
tailmac create --id my_custom_vm_id --image "/images/macos_ventura.ipsw" --mac 52:cc:cc:cc:cc:07 --mem 8000000000 --sock "/temp/custom.sock" --port 52345 
```

A typical workflow would be to create single VM, manually set it up the way you wish including the installation of any required client side software
(tailscaled or the client-side test harness for example)  then clone that images as required and back up your 
images for future use.

Fetching and persisting pre-configured images is left as an exercise for the reader (for now).  A previously used image can simply be copied to the
~/VM.bundle directory under a unique path and tailmac will automatically pick it up.  No versioning is supported so old images may stop working in
the future.

To delete a VM image, you may simply remove it's directory under ~/VM.bundle or
```
tailmac delete --id my_stale_vm
```

Note that the disk size is fixed, but should be sufficient (perhaps even excessive) for most lightweight workflows. 

#### Restore Images

To refresh an existing restore image:
```
tailmac refresh
```

Restore images can also be obtained directly from Apple for all macOS releases.  Note Apple restore images are raw installs, and the OS will require
configuration, user setup, etc before being useful.  Cloning a vm after clicking through the setup, creating a user and disabling things like the
lock screen and enabling auto-login will save you time in the future.


#### Cloning

To clone an existing vm (this will clone the mac and port as well)
```
tailmac clone --id old_vm_id --target-id new_vm_id
```

#### Configuration

To reconfigure a existing vm:
```
tailmac configure --id vm_id --mac 11:22:33:44:55:66 --port 12345  --ethermac 22:33:44:55:66:77 -sock "/tmp/my.sock"
```

## Running a VM

To list the available VM images
```
tailmac ls
```

To launch an VM
```
tailmac run --id machine_1
```

 You may invoke multiple vms, but the limit on the number of concurrent instances is on the order of 2.  Use the --tail option to watch the stdout of the
 Host.app process.  There is currently no way to list the running VM instances, but invoking stop or halt  for a vm instance
 that is not running is perfectly safe.

 To gracefully stop a running VM and save its state (this is a fire and forget thing):

 ```
 tailmac stop --id machine_1
 ```
 
Manually closing a VM's window will save the VM's state (if possible) and is the equivalent of running 'tailmac stop --id vm_id'
 
 To halt a running vm without saving its state:
 ```
 tailmac halt --id machine_1
 ```
