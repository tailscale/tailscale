// Copyright (c) Tailscale Inc & AUTHORS
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

    func createVirtualMachine() {
        let virtualMachineConfiguration = VZVirtualMachineConfiguration()

        virtualMachineConfiguration.platform = createMacPlaform()
        virtualMachineConfiguration.bootLoader = helper.createBootLoader()
        virtualMachineConfiguration.cpuCount = helper.computeCPUCount()
        virtualMachineConfiguration.memorySize = helper.computeMemorySize()
        virtualMachineConfiguration.graphicsDevices = [helper.createGraphicsDeviceConfiguration()]
        virtualMachineConfiguration.storageDevices = [helper.createBlockDeviceConfiguration()]
        virtualMachineConfiguration.networkDevices = [helper.createNetworkDeviceConfiguration(), helper.createSocketNetworkDeviceConfiguration()]
        virtualMachineConfiguration.pointingDevices = [helper.createPointingDeviceConfiguration()]
        virtualMachineConfiguration.keyboards = [helper.createKeyboardConfiguration()]
        virtualMachineConfiguration.socketDevices = [helper.createSocketDeviceConfiguration()]

        try! virtualMachineConfiguration.validate()
        try! virtualMachineConfiguration.validateSaveRestoreSupport()

        virtualMachine = VZVirtualMachine(configuration: virtualMachineConfiguration)
        virtualMachine.delegate = self
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
