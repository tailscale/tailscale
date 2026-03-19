# tsapp on UTM

qemu from homebrew is recommended for tsapp development.
See the [main README](README.md) for details.

If you don't want to use qemu, this documents a way to use UTM on
macOS for tsapp development. It's not as quick of an edit-run-test
iteration cycle, but this is how:

* Create new VM, choose "Emulate" (for now) and not "Virtualize"
* Pick "Linux" as the operating system
* For "Boot ISO Image", select the built `tsapp.img`
* Architecture: `x86_64` (for now; arm64 later)
* System: `Standard PC (...) (q35)`
* Memory: 1024 MB is fine for testing
* CPUs: Default
* Storage size: 3GB
* Shared Directory: none. Continue.
* Summary: check "Open VM Settings"
* Network: Emulated Network Card: `virtio-net-pci`
* Display: Emulated Display Card: `virtio-vga` (not that there's much to see)
* Drives: delete all disks
* Drives: New... Interface `VirtIO`, Import ... find `tsapp.img` again. Save.
* Devices: New... Serial. Mode: Psuedo-TTY Device, Target: Automatic Serial Device.

Once created & the `img` is imported once, UTM converts it to qcow2 format
under `$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Tsapp.utm/Data/tsapp.qcow2`.

To update it, stop the VM, then:

```
qemu-img convert -f raw -O qcow2 tsapp.img tsapp.qcow2 && \
  mv tsapp.qcow2 $HOME/Library/Containers/com.utmapp.UTM/Data/Documents/Tsapp.utm/Data/tsapp.qcow2
```

To attach to its serial:

```
% /Applications/UTM.app/Contents/MacOS/utmctl list
UUID                                 Status   Name
C0DE927B-F426-4ABA-A6E7-E30AA429371F started  Tsapp

% % /Applications/UTM.app/Contents/MacOS/utmctl attach C0DE927B-F426-4ABA-A6E7-E30AA429371F
WARNING: attach command is not implemented yet!
PTTY: /dev/ttys017

% screen /dev/ttys017
```

(Then `Ctrl-a K` to kill screen session)
