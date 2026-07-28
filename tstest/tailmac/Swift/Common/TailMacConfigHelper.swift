// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Virtualization

struct TailMacConfigHelper {
    let config: Config

    func computeCPUCount() -> Int {
        let totalAvailableCPUs = ProcessInfo.processInfo.processorCount

        var virtualCPUCount = totalAvailableCPUs <= 1 ? 1 : totalAvailableCPUs - 1
        virtualCPUCount = max(virtualCPUCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
        virtualCPUCount = min(virtualCPUCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount)

        return virtualCPUCount
    }

    func computeMemorySize() -> UInt64 {
        // Set the amount of system memory to 4 GB; this is a baseline value
        // that you can change depending on your use case.
        var memorySize = config.memorySize
        memorySize = max(memorySize, VZVirtualMachineConfiguration.minimumAllowedMemorySize)
        memorySize = min(memorySize, VZVirtualMachineConfiguration.maximumAllowedMemorySize)

        return memorySize
    }

    func createBootLoader() -> VZMacOSBootLoader {
        return VZMacOSBootLoader()
    }

    func createGraphicsDeviceConfiguration() -> VZMacGraphicsDeviceConfiguration {
        let graphicsConfiguration = VZMacGraphicsDeviceConfiguration()
        graphicsConfiguration.displays = [
            // The system arbitrarily chooses the resolution of the display to be 1920 x 1200.
            VZMacGraphicsDisplayConfiguration(widthInPixels: 1920, heightInPixels: 1200, pixelsPerInch: 80)
        ]

        return graphicsConfiguration
    }

    func createBlockDeviceConfiguration() -> VZVirtioBlockDeviceConfiguration {
        do {
            let diskImageAttachment = try VZDiskImageStorageDeviceAttachment(url: config.diskImageURL, readOnly: false)
            let disk = VZVirtioBlockDeviceConfiguration(attachment: diskImageAttachment)
            return disk
        } catch {
            fatalError("Failed to create Disk image. \(error)")
        }
    }

    func createSocketDeviceConfiguration() -> VZVirtioSocketDeviceConfiguration {
       return VZVirtioSocketDeviceConfiguration()
    }

    func createNetworkDeviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.macAddress = VZMACAddress(string: config.ethermac)!

        /* Bridged networking requires special entitlements from Apple
         if let interface = VZBridgedNetworkInterface.networkInterfaces.first(where: { $0.identifier == "en0" }) {
            let networkAttachment = VZBridgedNetworkDeviceAttachment(interface: interface)
            networkDevice.attachment = networkAttachment
         } else {
            print("Assuming en0 for bridged ethernet.  Could not findd adapter")
         }*/

        /// But we can do NAT without Tim Apple's approval
        let networkAttachment = VZNATNetworkDeviceAttachment()
        networkDevice.attachment = networkAttachment

        return networkDevice
    }

    /// Creates a NIC configuration connected to the vnet dgram socket.
    func createSocketNetworkDeviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.macAddress = VZMACAddress(string: config.mac)!
        if let attachment = createDgramAttachment(serverSocket: config.serverSocket, clientID: config.vmID) {
            networkDevice.attachment = attachment
        }
        return networkDevice
    }

    /// Creates a NIC configuration with no attachment (disconnected).
    /// The attachment can be hot-swapped later via VZNetworkDevice.attachment.
    func createDisconnectedNetworkDeviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.macAddress = VZMACAddress(string: config.mac)!
        // No attachment — NIC appears disconnected to the guest.
        return networkDevice
    }

    /// Creates a dgram socket attachment for connecting to a vnet server.
    /// Returns nil on error.
    func createDgramAttachment(serverSocket: String, clientID: String) -> VZFileHandleNetworkDeviceAttachment? {
        let socket = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)

        let clientSocket = "/tmp/qemu-dgram-\(clientID).sock"

        unlink(clientSocket)
        var clientAddr = sockaddr_un()
        clientAddr.sun_family = sa_family_t(AF_UNIX)
        clientSocket.withCString { ptr in
            withUnsafeMutablePointer(to: &clientAddr.sun_path.0) { dest in
                _ = strcpy(dest, ptr)
            }
        }

        let bindRes = Darwin.bind(socket,
                                  withUnsafePointer(to: &clientAddr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 } }),
                                  socklen_t(MemoryLayout<sockaddr_un>.size))

        if bindRes == -1 {
            print("Error binding virtual network client socket - \(String(cString: strerror(errno)))")
            return nil
        }

        var serverAddr = sockaddr_un()
        serverAddr.sun_family = sa_family_t(AF_UNIX)
        serverSocket.withCString { ptr in
            withUnsafeMutablePointer(to: &serverAddr.sun_path.0) { dest in
                _ = strcpy(dest, ptr)
            }
        }

        let connectRes = Darwin.connect(socket,
                                        withUnsafePointer(to: &serverAddr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 } }),
                                        socklen_t(MemoryLayout<sockaddr_un>.size))

        if connectRes == -1 {
            print("Error connecting to server socket \(serverSocket) - \(String(cString: strerror(errno)))")
            return nil
        }

        print("Virtual if mac address is \(config.mac)")
        print("Client bound to \(clientSocket)")
        print("Connected to server at \(serverSocket)")

        let handle = FileHandle(fileDescriptor: socket)
        return VZFileHandleNetworkDeviceAttachment(fileHandle: handle)
    }

    func createPointingDeviceConfiguration() -> VZPointingDeviceConfiguration {
        return VZMacTrackpadConfiguration()
    }

    func createKeyboardConfiguration() -> VZKeyboardConfiguration {
        return VZMacKeyboardConfiguration()
    }

    func createDirectoryShareConfiguration(tag: String) -> VZDirectorySharingDeviceConfiguration? {
        guard let dir = config.sharedDir else { return nil }

        let sharedDir = VZSharedDirectory(url: URL(fileURLWithPath: dir), readOnly: false)
        let share = VZSingleDirectoryShare(directory: sharedDir)

        // Create the VZVirtioFileSystemDeviceConfiguration and assign it a unique tag.
        let sharingConfiguration = VZVirtioFileSystemDeviceConfiguration(tag: tag)
        sharingConfiguration.share = share

        return sharingConfiguration
    }
}

