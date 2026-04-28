// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Cocoa
import Foundation
import Virtualization
import Foundation

class VMController: NSObject, VZVirtualMachineDelegate {
    var virtualMachine: VZVirtualMachine!

    lazy var helper = TailMacConfigHelper(config: config)

    override init() {
        super.init()
        listenForNotifications()
    }

    func listenForNotifications() {
        let nc = DistributedNotificationCenter()
        nc.addObserver(forName: Notifications.stop, object: nil, queue: nil) { notification in
            if let vmID = notification.userInfo?["id"] as? String {
                if config.vmID == vmID {
                    print("We've been asked to stop... Saving state and exiting")
                    self.pauseAndSaveVirtualMachine {
                        exit(0)
                    }
                }
            }
        }

        nc.addObserver(forName: Notifications.halt, object: nil, queue: nil) { notification in
            if let vmID = notification.userInfo?["id"] as? String {
                if config.vmID == vmID {
                    print("We've been asked to stop... Saving state and exiting")
                    self.virtualMachine.pause { (result) in
                        if case let .failure(error) = result {
                            fatalError("Virtual machine failed to pause with \(error)")
                        }
                        exit(0)
                    }
                }
            }
        }
    }

    func createMacPlaform() -> VZMacPlatformConfiguration {
        let macPlatform = VZMacPlatformConfiguration()

        let auxiliaryStorage = VZMacAuxiliaryStorage(contentsOf: config.auxiliaryStorageURL)
        macPlatform.auxiliaryStorage = auxiliaryStorage

        if !FileManager.default.fileExists(atPath: config.vmDataURL.path()) {
            fatalError("Missing Virtual Machine Bundle at \(config.vmDataURL). Run InstallationTool first to create it.")
        }

        // Retrieve the hardware model and save this value to disk during installation.
        guard let hardwareModelData = try? Data(contentsOf: config.hardwareModelURL) else {
            fatalError("Failed to retrieve hardware model data.")
        }

        guard let hardwareModel = VZMacHardwareModel(dataRepresentation: hardwareModelData) else {
            fatalError("Failed to create hardware model.")
        }

        if !hardwareModel.isSupported {
            fatalError("The hardware model isn't supported on the current host")
        }
        macPlatform.hardwareModel = hardwareModel

        // Retrieve the machine identifier and save this value to disk during installation.
        guard let machineIdentifierData = try? Data(contentsOf: config.machineIdentifierURL) else {
            fatalError("Failed to retrieve machine identifier data.")
        }

        guard let machineIdentifier = VZMacMachineIdentifier(dataRepresentation: machineIdentifierData) else {
            fatalError("Failed to create machine identifier.")
        }
        macPlatform.machineIdentifier = machineIdentifier

        return macPlatform
    }

    func createVirtualMachine(headless: Bool = false, disconnectedNIC: Bool = false, natNIC: Bool = false) {
        let virtualMachineConfiguration = VZVirtualMachineConfiguration()

        virtualMachineConfiguration.platform = createMacPlaform()
        virtualMachineConfiguration.bootLoader = helper.createBootLoader()
        virtualMachineConfiguration.cpuCount = helper.computeCPUCount()
        virtualMachineConfiguration.memorySize = helper.computeMemorySize()
        virtualMachineConfiguration.graphicsDevices = [helper.createGraphicsDeviceConfiguration()]
        virtualMachineConfiguration.storageDevices = [helper.createBlockDeviceConfiguration()]
        if headless {
            if natNIC {
                // NAT NIC for SSH access during snapshot preparation.
                virtualMachineConfiguration.networkDevices = [helper.createNetworkDeviceConfiguration()]
            } else if disconnectedNIC {
                // Create a NIC with no attachment. The NIC exists in the hardware
                // config (so saved state is compatible) but appears disconnected.
                // Call attachNetwork() after restore to hot-swap the attachment.
                virtualMachineConfiguration.networkDevices = [helper.createDisconnectedNetworkDeviceConfiguration()]
            } else {
                virtualMachineConfiguration.networkDevices = [helper.createSocketNetworkDeviceConfiguration()]
            }
        } else {
            virtualMachineConfiguration.networkDevices = [helper.createNetworkDeviceConfiguration(), helper.createSocketNetworkDeviceConfiguration()]
        }
        virtualMachineConfiguration.pointingDevices = [helper.createPointingDeviceConfiguration()]
        virtualMachineConfiguration.keyboards = [helper.createKeyboardConfiguration()]
        virtualMachineConfiguration.socketDevices = [helper.createSocketDeviceConfiguration()]

        if let dir = config.sharedDir, let shareConfig = helper.createDirectoryShareConfiguration(tag: "vmshare") {
            print("Sharing \(dir) as vmshare.  Use: mount_virtiofs vmshare <path> in the guest to mount.")
            virtualMachineConfiguration.directorySharingDevices = [shareConfig]
        } else {
            print("No shared directory created.  \(config.sharedDir ?? "none") was requested.")
        }

        try! virtualMachineConfiguration.validate()
        try! virtualMachineConfiguration.validateSaveRestoreSupport()

        virtualMachine = VZVirtualMachine(configuration: virtualMachineConfiguration)
        virtualMachine.delegate = self
    }

    /// Disconnect the NIC by setting its attachment to nil.
    /// Call before saving state so the snapshot has no active link.
    func disconnectNetwork() {
        guard let nic = virtualMachine.networkDevices.first else {
            print("disconnectNetwork: no network devices")
            return
        }
        nic.attachment = nil
        print("disconnectNetwork: NIC attachment set to nil")
    }

    /// Hot-swap the NIC attachment on a running VM. The VM must have been
    /// created with disconnectedNIC=true. After calling this, the guest
    /// sees the link come up and does DHCP.
    func attachNetwork(serverSocket: String, clientID: String) {
        guard let nic = virtualMachine.networkDevices.first else {
            print("attachNetwork: no network devices")
            return
        }
        guard let attachment = helper.createDgramAttachment(serverSocket: serverSocket, clientID: clientID) else {
            print("attachNetwork: failed to create attachment")
            return
        }
        nic.attachment = attachment
        print("attachNetwork: NIC attachment swapped to \(serverSocket)")
    }


    func startVirtualMachine() {
        virtualMachine.start(completionHandler: { (result) in
            if case let .failure(error) = result {
                fatalError("Virtual machine failed to start with \(error)")
            }
            self.startSocketDevice()
        })
    }

    func startSocketDevice() {
        if let device = virtualMachine.socketDevices.first as? VZVirtioSocketDevice {
            print("Configuring socket device at port \(config.port)")
            device.connect(toPort: config.port) { connection in
                //TODO: Anything?  Or is this enough to bootstrap it on both ends?
            }
        } else {
            print("Virtual machine could not start it's socket device")
        }
    }

    /// Start a vsock listener that tells the guest TTA agent what IP to configure.
    /// If response is nil, the listener replies "wait" (snapshot prep mode).
    func startIPConfigListener(response: String) {
        guard let device = virtualMachine.socketDevices.first as? VZVirtioSocketDevice else {
            print("startIPConfigListener: no socket device")
            return
        }
        let listener = IPConfigListener(response: response)
        retainedIPConfigListener = listener
        let vsockListener = VZVirtioSocketListener()
        vsockListener.delegate = listener
        device.setSocketListener(vsockListener, forPort: 51011)
        print("startIPConfigListener: listening on vsock port 51011")
    }

    func resumeVirtualMachine() {
        virtualMachine.resume(completionHandler: { (result) in
            if case let .failure(error) = result {
                fatalError("Virtual machine failed to resume with \(error)")
            }
        })
    }

    func restoreVirtualMachine() {
        virtualMachine.restoreMachineStateFrom(url: config.saveFileURL, completionHandler: { [self] (error) in
            // Remove the saved file. Whether success or failure, the state no longer matches the VM's disk.
            let fileManager = FileManager.default
            try! fileManager.removeItem(at: config.saveFileURL)

            if error == nil {
                self.resumeVirtualMachine()
            } else {
                self.startVirtualMachine()
            }
        })
    }

    func saveVirtualMachine(completionHandler: @escaping () -> Void) {
        virtualMachine.saveMachineStateTo(url: config.saveFileURL, completionHandler: { (error) in
            guard error == nil else {
                fatalError("Virtual machine failed to save with \(error!)")
            }

            completionHandler()
        })
    }

    func pauseAndSaveVirtualMachine(completionHandler: @escaping () -> Void) {
        virtualMachine.pause { result in
            if case let .failure(error) = result {
                fatalError("Virtual machine failed to pause with \(error)")
            }

            self.saveVirtualMachine(completionHandler: completionHandler)
        }
    }

    // MARK: - VZVirtualMachineDeleate

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        print("Virtual machine did stop with error: \(error.localizedDescription)")
        exit(-1)
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        print("Guest did stop virtual machine.")
        exit(0)
    }
}

// Global to prevent ARC deallocation of the vsock listener.
var retainedIPConfigListener: IPConfigListener?

/// Listens on vsock port 51011 for TTA connections and replies with
/// an IP configuration JSON string (or "wait" during snapshot prep).
class IPConfigListener: NSObject, VZVirtioSocketListenerDelegate {
    let response: String

    init(response: String) {
        self.response = response
    }

    func listener(_ listener: VZVirtioSocketListener,
                  shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool {
        let fd = connection.fileDescriptor
        let data = Array((response + "\n").utf8)
        data.withUnsafeBufferPointer { buf in
            _ = write(fd, buf.baseAddress!, buf.count)
        }
        connection.close()
        return true
    }
}
