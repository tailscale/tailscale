// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation

let kDefaultDiskSizeGb: Int64 = 72
let kDefaultMemSizeGb: UInt64 = 72


/// Represents a configuration for a virtual machine
class Config: Codable {
    var serverSocket = "/tmp/qemu-dgram.sock"
    var memorySize = (kDefaultMemSizeGb * 1024 * 1024 * 1024) as UInt64
    var mac = "52:cc:cc:cc:cc:01"
    var ethermac = "52:cc:cc:cc:ce:01"
    var port: UInt32 = 51009

    // The virtual machines ID.  Also double as the directory name under which
    // we will store configuration, block device, etc.
    let vmID: String

    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let ethermac = try container.decodeIfPresent(String.self, forKey: .ethermac) {
            self.ethermac = ethermac
        }
        if let serverSocket = try container.decodeIfPresent(String.self, forKey: .serverSocket) {
            self.serverSocket = serverSocket
        }
        if let memorySize = try container.decodeIfPresent(UInt64.self, forKey: .memorySize) {
            self.memorySize = memorySize
        }
        if let port = try container.decodeIfPresent(UInt32.self, forKey: .port) {
            self.port = port
        }
        if let mac = try container.decodeIfPresent(String.self, forKey: .mac) {
            self.mac = mac
        }
        if let vmID = try container.decodeIfPresent(String.self, forKey: .vmID) {
            self.vmID = vmID
        } else {
            self.vmID = "default"
        }
    }

    init(_ vmID: String = "default") {
        self.vmID = vmID
        let configFile = vmDataURL.appendingPathComponent("config.json")
        if FileManager.default.fileExists(atPath: configFile.path()) {
            print("Using config file at path \(configFile)")
            if let jsonData = try? Data(contentsOf: configFile) {
                let config = try! JSONDecoder().decode(Config.self, from: jsonData)
                self.serverSocket = config.serverSocket
                self.memorySize = config.memorySize
                self.mac = config.mac
                self.port = config.port
                self.ethermac = config.ethermac
            }
        }
    }

    func persist() {
        let configFile = vmDataURL.appendingPathComponent("config.json")
        let data = try! JSONEncoder().encode(self)
        try! data.write(to: configFile)
    }

    lazy var restoreImageURL: URL = {
        vmBundleURL.appendingPathComponent("RestoreImage.ipsw")
    }()

    // The VM Data URL holds the specific files composing a unique VM guest instance
    // By default, VM's are persisted at ~/VM.bundle/<vmID>
    lazy var vmDataURL =  {
        let dataURL = vmBundleURL.appendingPathComponent(vmID)
        return dataURL
    }()

    lazy var auxiliaryStorageURL = {
        vmDataURL.appendingPathComponent("AuxiliaryStorage")
    }()

    lazy var diskImageURL = {
        vmDataURL.appendingPathComponent("Disk.img")
    }()

    lazy var diskSize: Int64 = {
        kDefaultDiskSizeGb * 1024 * 1024 * 1024
    }()

    lazy var hardwareModelURL = {
        vmDataURL.appendingPathComponent("HardwareModel")
    }()

    lazy var machineIdentifierURL = {
        vmDataURL.appendingPathComponent("MachineIdentifier")
    }()

    lazy var saveFileURL = {
        vmDataURL.appendingPathComponent("SaveFile.vzvmsave")
    }()

}

// The VM Bundle URL holds the restore image and a set of VM images
// By default, VM's are persisted at ~/VM.bundle
var vmBundleURL: URL = {
    let vmBundlePath = NSHomeDirectory() + "/VM.bundle/"
    createDir(vmBundlePath)
    let bundleURL = URL(fileURLWithPath: vmBundlePath)
    return bundleURL
}()


func createDir(_ path: String) {
    do {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    } catch {
        fatalError("Unable to create dir at \(path) \(error)")
    }
}




