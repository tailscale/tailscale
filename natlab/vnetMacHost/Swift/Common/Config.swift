import Foundation

// We need to make this all configurable via config file of some kind and
// read it in.
struct Config {
    static let mac = "5a:94:ef:e4:0c:ee"
    static let serverSocket = "/tmp/qemu.sock"
    static let clientSocket = "/tmp/qemu_client.sock"

    static let memorySize = (4 * 1024 * 1024 * 1024) as UInt64
}

let vmBundlePath = NSHomeDirectory() + "/VM.bundle/"
let vmBundleURL = URL(fileURLWithPath: vmBundlePath)
let auxiliaryStorageURL = vmBundleURL.appendingPathComponent("AuxiliaryStorage")
let diskImageURL = vmBundleURL.appendingPathComponent("Disk.img")
let hardwareModelURL = vmBundleURL.appendingPathComponent("HardwareModel")
let machineIdentifierURL = vmBundleURL.appendingPathComponent("MachineIdentifier")
let restoreImageURL = vmBundleURL.appendingPathComponent("RestoreImage.ipsw")
let saveFileURL = vmBundleURL.appendingPathComponent("SaveFile.vzvmsave")
