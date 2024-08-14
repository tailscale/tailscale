// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Virtualization

class VMInstaller: NSObject {
    private var installationObserver: NSKeyValueObservation?
    private var virtualMachine: VZVirtualMachine!

    private var config: Config
    private var helper: TailMacConfigHelper

    init(_ config: Config) {
        self.config = config
        helper = TailMacConfigHelper(config: config)
    }

    public func installMacOS(ipswURL: URL) {
        print("Attempting to install from IPSW at \(ipswURL).")
        VZMacOSRestoreImage.load(from: ipswURL, completionHandler: { [self](result: Result<VZMacOSRestoreImage, Error>) in
            switch result {
            case let .failure(error):
                fatalError(error.localizedDescription)

            case let .success(restoreImage):
                installMacOS(restoreImage: restoreImage)
            }
        })
    }

    // MARK: - Internal helper functions.

    private func installMacOS(restoreImage: VZMacOSRestoreImage) {
        guard let macOSConfiguration = restoreImage.mostFeaturefulSupportedConfiguration else {
            fatalError("No supported configuration available.")
        }

        if !macOSConfiguration.hardwareModel.isSupported {
            fatalError("macOSConfiguration configuration isn't supported on the current host.")
        }

        DispatchQueue.main.async { [self] in
            setupVirtualMachine(macOSConfiguration: macOSConfiguration)
            startInstallation(restoreImageURL: restoreImage.url)
        }
    }

    // MARK: Create the Mac platform configuration.

    private func createMacPlatformConfiguration(macOSConfiguration: VZMacOSConfigurationRequirements) -> VZMacPlatformConfiguration {
        let macPlatformConfiguration = VZMacPlatformConfiguration()


        let auxiliaryStorage: VZMacAuxiliaryStorage
        do {
            auxiliaryStorage = try VZMacAuxiliaryStorage(creatingStorageAt: config.auxiliaryStorageURL,
                                                             hardwareModel: macOSConfiguration.hardwareModel,
                                                             options: [])
        } catch {
            fatalError("Unable to create aux storage at \(config.auxiliaryStorageURL) \(error)")
        }
        macPlatformConfiguration.auxiliaryStorage = auxiliaryStorage
        macPlatformConfiguration.hardwareModel = macOSConfiguration.hardwareModel
        macPlatformConfiguration.machineIdentifier = VZMacMachineIdentifier()

        // Store the hardware model and machine identifier to disk so that you
        // can retrieve them for subsequent boots.
        try! macPlatformConfiguration.hardwareModel.dataRepresentation.write(to: config.hardwareModelURL)
        try! macPlatformConfiguration.machineIdentifier.dataRepresentation.write(to: config.machineIdentifierURL)

        return macPlatformConfiguration
    }

    private func setupVirtualMachine(macOSConfiguration: VZMacOSConfigurationRequirements) {
        let virtualMachineConfiguration = VZVirtualMachineConfiguration()

        virtualMachineConfiguration.platform = createMacPlatformConfiguration(macOSConfiguration: macOSConfiguration)
        virtualMachineConfiguration.cpuCount = helper.computeCPUCount()
        if virtualMachineConfiguration.cpuCount < macOSConfiguration.minimumSupportedCPUCount {
            fatalError("CPUCount isn't supported by the macOS configuration.")
        }

        virtualMachineConfiguration.memorySize = helper.computeMemorySize()
        if virtualMachineConfiguration.memorySize < macOSConfiguration.minimumSupportedMemorySize {
            fatalError("memorySize isn't supported by the macOS configuration.")
        }

        createDiskImage()

        virtualMachineConfiguration.bootLoader = helper.createBootLoader()
        virtualMachineConfiguration.graphicsDevices = [helper.createGraphicsDeviceConfiguration()]
        virtualMachineConfiguration.storageDevices = [helper.createBlockDeviceConfiguration()]
        virtualMachineConfiguration.networkDevices = [helper.createNetworkDeviceConfiguration(), helper.createSocketNetworkDeviceConfiguration()]
        virtualMachineConfiguration.pointingDevices = [helper.createPointingDeviceConfiguration()]
        virtualMachineConfiguration.keyboards = [helper.createKeyboardConfiguration()]

        try! virtualMachineConfiguration.validate()
        try! virtualMachineConfiguration.validateSaveRestoreSupport()

        virtualMachine = VZVirtualMachine(configuration: virtualMachineConfiguration)
    }

    private func startInstallation(restoreImageURL: URL) {
        let installer = VZMacOSInstaller(virtualMachine: virtualMachine, restoringFromImageAt: restoreImageURL)

        print("Starting installation.")
        installer.install(completionHandler: { (result: Result<Void, Error>) in
            if case let .failure(error) = result {
                fatalError(error.localizedDescription)
            } else {
                print("Installation succeeded.")
            }
        })

        // Observe installation progress.
        installationObserver = installer.progress.observe(\.fractionCompleted, options: [.initial, .new]) { (progress, change) in
            print("Installation progress: \(change.newValue! * 100).")
        }
    }

    // Create an empty disk image for the virtual machine.
    private func createDiskImage() {
        let diskFd = open(config.diskImageURL.path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)
        if diskFd == -1 {
            fatalError("Cannot create disk image.")
        }

        // 72 GB disk space.
        var result = ftruncate(diskFd, config.diskSize)
        if result != 0 {
            fatalError("ftruncate() failed.")
        }

        result = close(diskFd)
        if result != 0 {
            fatalError("Failed to close the disk image.")
        }
    }
}
