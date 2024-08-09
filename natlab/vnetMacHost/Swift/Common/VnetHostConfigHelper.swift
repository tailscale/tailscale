/*
See the LICENSE.txt file for this sample’s licensing information.

Abstract:
The helper that creates various configuration objects exposed in the `VZVirtualMachineConfiguration`.
*/

import Foundation
import Virtualization

#if arch(arm64)

struct VnetHostConfigHelper {
    static func computeCPUCount() -> Int {
        let totalAvailableCPUs = ProcessInfo.processInfo.processorCount

        var virtualCPUCount = totalAvailableCPUs <= 1 ? 1 : totalAvailableCPUs - 1
        virtualCPUCount = max(virtualCPUCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
        virtualCPUCount = min(virtualCPUCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount)

        return virtualCPUCount
    }

    static func computeMemorySize() -> UInt64 {
        // Set the amount of system memory to 4 GB; this is a baseline value
        // that you can change depending on your use case.
        var memorySize = Config.memorySize
        memorySize = max(memorySize, VZVirtualMachineConfiguration.minimumAllowedMemorySize)
        memorySize = min(memorySize, VZVirtualMachineConfiguration.maximumAllowedMemorySize)

        return memorySize
    }

    static func createBootLoader() -> VZMacOSBootLoader {
        return VZMacOSBootLoader()
    }

    static func createGraphicsDeviceConfiguration() -> VZMacGraphicsDeviceConfiguration {
        let graphicsConfiguration = VZMacGraphicsDeviceConfiguration()
        graphicsConfiguration.displays = [
            // The system arbitrarily chooses the resolution of the display to be 1920 x 1200.
            VZMacGraphicsDisplayConfiguration(widthInPixels: 1920, heightInPixels: 1200, pixelsPerInch: 80)
        ]

        return graphicsConfiguration
    }

    static func createBlockDeviceConfiguration() -> VZVirtioBlockDeviceConfiguration {
        guard let diskImageAttachment = try? VZDiskImageStorageDeviceAttachment(url: diskImageURL, readOnly: false) else {
            fatalError("Failed to create Disk image.")
        }
        let disk = VZVirtioBlockDeviceConfiguration(attachment: diskImageAttachment)
        return disk
    }

    static func createNetworkDeviceConfiguration() -> VZVirtioNetworkDeviceConfiguration {
        let networkDevice = VZVirtioNetworkDeviceConfiguration()
        networkDevice.macAddress = VZMACAddress(string: Config.mac)!

        let socket = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)

        let serverSocket = Config.serverSocket
        let clientSocket = Config.clientSocket

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
            print("Error binding virtual network server socket - \(String(cString: strerror(errno)))")
            return networkDevice
        }

        print("Virtual if mac address is \(Config.mac)")
        print("Client bound to \(clientSocket)")
        print("Connected to server at \(serverSocket)")
        print("Socket fd is \(socket)")


        let handle = FileHandle(fileDescriptor: socket)
        let device = VZFileHandleNetworkDeviceAttachment(fileHandle: handle)
        networkDevice.attachment = device
        return networkDevice
    }

    static func createPointingDeviceConfiguration() -> VZPointingDeviceConfiguration {
        return VZMacTrackpadConfiguration()
    }

    static func createKeyboardConfiguration() -> VZKeyboardConfiguration {
        if #available(macOS 14.0, *) {
            return VZMacKeyboardConfiguration()
        } else {
            return VZUSBKeyboardConfiguration()
        }
    }
}

#endif
