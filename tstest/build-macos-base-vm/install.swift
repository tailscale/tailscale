// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This is a helper program invoked by the Go build-macos-base-vm command.
// It uses Apple's Virtualization.framework for two operations:
//
//   fetch-ipsw-url           — prints the URL of the latest supported IPSW
//   install <vm-dir> <ipsw>  — installs macOS from a local IPSW into a VM

import Foundation
import Virtualization

guard CommandLine.arguments.count >= 2 else {
    fputs("usage: installer {fetch-ipsw-url | install <vm-dir> <ipsw-path>}\n", stderr)
    exit(1)
}

let mode = CommandLine.arguments[1]

switch mode {
case "fetch-ipsw-url":
    VZMacOSRestoreImage.fetchLatestSupported { result in
        switch result {
        case .failure(let error):
            fputs("Failed to fetch restore image info: \(error)\n", stderr)
            exit(1)
        case .success(let image):
            // Print URL to stdout for the Go caller to parse.
            print(image.url.absoluteString)
            exit(0)
        }
    }
    RunLoop.main.run()

case "install":
    guard CommandLine.arguments.count == 4 else {
        fputs("usage: installer install <vm-dir> <ipsw-path>\n", stderr)
        exit(1)
    }
    let vmDir = CommandLine.arguments[2]
    let ipswPath = CommandLine.arguments[3]

    let diskURL = URL(fileURLWithPath: vmDir).appendingPathComponent("Disk.img")
    let auxURL = URL(fileURLWithPath: vmDir).appendingPathComponent("AuxiliaryStorage")
    let hwModelURL = URL(fileURLWithPath: vmDir).appendingPathComponent("HardwareModel")
    let machineIdURL = URL(fileURLWithPath: vmDir).appendingPathComponent("MachineIdentifier")

    let diskSize: Int64 = 72 * 1024 * 1024 * 1024
    let memorySize: UInt64 = 8 * 1024 * 1024 * 1024

    fputs("Loading IPSW...\n", stderr)
    VZMacOSRestoreImage.load(from: URL(fileURLWithPath: ipswPath)) { result in
        switch result {
        case .failure(let error):
            fputs("Failed to load IPSW: \(error)\n", stderr)
            exit(1)
        case .success(let restoreImage):
            guard let macOSConfig = restoreImage.mostFeaturefulSupportedConfiguration else {
                fputs("No supported macOS configuration for this host.\n", stderr)
                exit(1)
            }
            guard macOSConfig.hardwareModel.isSupported else {
                fputs("Hardware model not supported on this host.\n", stderr)
                exit(1)
            }
            DispatchQueue.main.async {
                // Create disk image (sparse).
                let fd = open(diskURL.path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)
                guard fd != -1 else { fputs("Cannot create disk image.\n", stderr); exit(1) }
                guard ftruncate(fd, diskSize) == 0 else { fputs("ftruncate failed.\n", stderr); exit(1) }
                close(fd)

                // Create platform config.
                let platform = VZMacPlatformConfiguration()
                platform.auxiliaryStorage = try! VZMacAuxiliaryStorage(
                    creatingStorageAt: auxURL,
                    hardwareModel: macOSConfig.hardwareModel,
                    options: [])
                platform.hardwareModel = macOSConfig.hardwareModel
                platform.machineIdentifier = VZMacMachineIdentifier()
                try! platform.hardwareModel.dataRepresentation.write(to: hwModelURL)
                try! platform.machineIdentifier.dataRepresentation.write(to: machineIdURL)

                // Build VM config (minimal — just enough for installation).
                let vmConfig = VZVirtualMachineConfiguration()
                vmConfig.platform = platform
                vmConfig.bootLoader = VZMacOSBootLoader()

                var cpuCount = ProcessInfo.processInfo.processorCount - 1
                cpuCount = max(cpuCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
                cpuCount = min(cpuCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
                vmConfig.cpuCount = cpuCount

                var mem = memorySize
                mem = max(mem, VZVirtualMachineConfiguration.minimumAllowedMemorySize)
                mem = min(mem, VZVirtualMachineConfiguration.maximumAllowedMemorySize)
                vmConfig.memorySize = mem

                let gfx = VZMacGraphicsDeviceConfiguration()
                gfx.displays = [VZMacGraphicsDisplayConfiguration(widthInPixels: 1920, heightInPixels: 1200, pixelsPerInch: 80)]
                vmConfig.graphicsDevices = [gfx]

                let disk = try! VZDiskImageStorageDeviceAttachment(url: diskURL, readOnly: false)
                vmConfig.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: disk)]
                vmConfig.networkDevices = []
                vmConfig.pointingDevices = [VZMacTrackpadConfiguration()]
                vmConfig.keyboards = [VZMacKeyboardConfiguration()]

                try! vmConfig.validate()

                let vm = VZVirtualMachine(configuration: vmConfig)

                fputs("Starting macOS installation...\n", stderr)
                let installer = VZMacOSInstaller(virtualMachine: vm, restoringFromImageAt: restoreImage.url)
                installer.install { result in
                    switch result {
                    case .success:
                        fputs("Installation complete.\n", stderr)
                        exit(0)
                    case .failure(let error):
                        fputs("Installation failed: \(error)\n", stderr)
                        exit(1)
                    }
                }
                _ = installer.progress.observe(\.fractionCompleted, options: [.initial, .new]) { _, change in
                    let pct = Int((change.newValue ?? 0) * 100)
                    fputs("  install: \(pct)%\n", stderr)
                }
            }
        }
    }
    RunLoop.main.run()

default:
    fputs("unknown mode: \(mode)\n", stderr)
    exit(1)
}
