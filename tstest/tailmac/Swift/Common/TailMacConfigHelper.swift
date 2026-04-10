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

    func createSocketNetworkDeviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.macAddress = VZMACAddress(string: config.mac)!

        let socket = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)

        // Outbound network packets
        let serverSocket = config.serverSocket

        // Inbound network packets — bind a client socket so the server can reply.
        let clientSockId = config.vmID
        let clientSocket = "/tmp/qemu-dgram-\(clientSockId).sock"

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
            return networkDevice
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
            return networkDevice
        }

        print("Virtual if mac address is \(config.mac)")
        print("Client bound to \(clientSocket)")
        print("Connected to server at \(serverSocket)")

        // Use a socketpair between VZ and the relay. VZ reads/writes one end;
        // background threads relay between the other end and the vnet dgram socket.
        // This is more reliable than giving VZ the dgram socket directly.
        var spFds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &spFds) == 0 else {
            print("socketpair failed: \(String(cString: strerror(errno)))")
            return networkDevice
        }
        let vzFd = spFds[0]
        let relayFd = spFds[1]

        let vzHandle = FileHandle(fileDescriptor: vzFd)
        let device = VZFileHandleNetworkDeviceAttachment(fileHandle: vzHandle)
        networkDevice.attachment = device

        // Relay: guest→network (read from relayFd, write to dgram socket)
        DispatchQueue.global().async {
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = Darwin.read(relayFd, &buf, buf.count)
                if n <= 0 { break }
                Darwin.write(socket, buf, n)
            }
        }

        // Relay: network→guest (read from dgram socket, write to relayFd)
        DispatchQueue.global().async {
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = Darwin.read(socket, &buf, buf.count)
                if n <= 0 { break }
                Darwin.write(relayFd, buf, n)
            }
        }

        return networkDevice
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

