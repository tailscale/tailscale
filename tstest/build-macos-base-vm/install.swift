// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This is a helper program invoked by the Go build-macos-base-vm command.
// It uses Apple's Virtualization.framework to download a macOS IPSW
// restore image and install macOS into a VM disk image.
//
// Usage: installer <vm-dir> <ipsw-path>

import Foundation
import Virtualization

guard CommandLine.arguments.count == 3 else {
    fputs("usage: installer <vm-dir> <ipsw-path>\n", stderr)
    exit(1)
}

let vmDir = CommandLine.arguments[1]
let ipswPath = CommandLine.arguments[2]

let diskURL = URL(fileURLWithPath: vmDir).appendingPathComponent("Disk.img")
let auxURL = URL(fileURLWithPath: vmDir).appendingPathComponent("AuxiliaryStorage")
let hwModelURL = URL(fileURLWithPath: vmDir).appendingPathComponent("HardwareModel")
let machineIdURL = URL(fileURLWithPath: vmDir).appendingPathComponent("MachineIdentifier")

let diskSize: Int64 = 72 * 1024 * 1024 * 1024 // 72 GB sparse
let memorySize: UInt64 = 8 * 1024 * 1024 * 1024 // 8 GB

// Step 1: Download IPSW if needed.
func downloadIPSW(to path: String, completion: @escaping (URL) -> Void) {
    let url = URL(fileURLWithPath: path)
    if FileManager.default.fileExists(atPath: path) {
        print("Using existing IPSW at \(path)")
        completion(url)
        return
    }
    print("Downloading latest macOS restore image...")
    VZMacOSRestoreImage.fetchLatestSupported { result in
        switch result {
        case .failure(let error):
            fputs("Failed to fetch restore image info: \(error)\n", stderr)
            exit(1)
        case .success(let image):
            print("Downloading from \(image.url)...")
            let task = URLSession.shared.downloadTask(with: image.url) { localURL, _, error in
                if let error = error {
                    fputs("Download failed: \(error)\n", stderr)
                    exit(1)
                }
                do {
                    try FileManager.default.moveItem(at: localURL!, to: url)
                } catch {
                    fputs("Failed to move IPSW: \(error)\n", stderr)
                    exit(1)
                }
                print("Downloaded IPSW to \(path)")
                completion(url)
            }
            task.progress.observe(\.fractionCompleted, options: [.new]) { _, change in
                let pct = Int((change.newValue ?? 0) * 100)
                print("  download: \(pct)%")
            }
            task.resume()
        }
    }
}

// Step 2: Install macOS from IPSW.
func installMacOS(ipswURL: URL) {
    print("Loading IPSW...")
    VZMacOSRestoreImage.load(from: ipswURL) { result in
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
                doInstall(restoreImage: restoreImage, macOSConfig: macOSConfig)
            }
        }
    }
}

func doInstall(restoreImage: VZMacOSRestoreImage, macOSConfig: VZMacOSConfigurationRequirements) {
    // Create disk image.
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

    // Save hardware model and machine identifier for future boots.
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

    // Install.
    print("Starting macOS installation...")
    let installer = VZMacOSInstaller(virtualMachine: vm, restoringFromImageAt: restoreImage.url)
    installer.install { result in
        switch result {
        case .success:
            print("Installation complete.")
            exit(0)
        case .failure(let error):
            fputs("Installation failed: \(error)\n", stderr)
            exit(1)
        }
    }
    _ = installer.progress.observe(\.fractionCompleted, options: [.initial, .new]) { _, change in
        let pct = Int((change.newValue ?? 0) * 100)
        print("  install: \(pct)%")
    }
}

// Main flow.
downloadIPSW(to: ipswPath) { url in
    installMacOS(ipswURL: url)
}
RunLoop.main.run()
