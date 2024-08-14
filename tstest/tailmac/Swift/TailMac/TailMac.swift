// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Virtualization
import ArgumentParser

var usage =
"""
Installs and configures VMs suitable for use with natlab

To create a new VM (this will grab a restore image if needed)
tailmac create --id <vm_id>

To refresh an existing restore image:
tailmac refresh

To clone a vm (this will clone the mac and port as well)
tailmac clone --identfier <old_vm_id> --target-id <new_vm_id>

To reconfigure a vm:
tailmac configure --id <vm_id> --mac 11:22:33:44:55:66 --port 12345 --mem 8000000000000 -sock "/tmp/mySock.sock"

To run a vm:
tailmac run --id <vm_id>

To stop a vm: (this may take a minute - the vm needs to persist it's state)
tailmac stop --id <vm_id>

To halt a vm without persisting its state
tailmac halt --id <vm_id>

To delete a vm:
tailmac delete --id <vm_id>

To list the available VM images:
tailmac ls
"""

@main
struct Tailmac: ParsableCommand {
    static var configuration = CommandConfiguration(
        abstract: "A utility for setting up VM images",
        usage: usage,
        subcommands: [Create.self, Clone.self, Delete.self, Configure.self, Stop.self, Run.self, Ls.self, Halt.self],
        defaultSubcommand: Ls.self)
}

extension Tailmac {
    struct Ls: ParsableCommand {
        mutating func run() {
            do {
                let dirs = try FileManager.default.contentsOfDirectory(atPath: vmBundleURL.path())
                var images = [String]()

                // This assumes we don't put anything else interesting in our VM.bundle dir
                // You may need to add some other exclusions or checks here if that's the case.
                for dir in dirs {
                    if !dir.contains("ipsw") {
                        images.append(URL(fileURLWithPath: dir).lastPathComponent)
                    }
                }
                print("Available images:\n\(images)")
            } catch {
                fatalError("Failed to query available images \(error)")
            }
        }
    }
}

extension Tailmac {
    struct Stop: ParsableCommand {
        @Option(help: "The vm identifier") var id: String

        mutating func run() {
            print("Stopping vm with id \(id).  This may take some time!")
            let nc = DistributedNotificationCenter()
            nc.post(name: Notifications.stop, object: nil, userInfo: ["id": id])
        }
    }
}

extension Tailmac {
    struct Halt: ParsableCommand {
        @Option(help: "The vm identifier") var id: String

        mutating func run() {
            print("Halting vm with id \(id)")
            let nc = DistributedNotificationCenter()
            nc.post(name: Notifications.halt, object: nil, userInfo: ["id": id])
        }
    }
}

extension Tailmac {
    struct Run: ParsableCommand {
        @Option(help: "The vm identifier") var id: String
        @Flag(help: "Tail the TailMac log output instead of returning immediatly") var tail

        mutating func run() {
            let process = Process()
            let stdOutPipe = Pipe()
            let appPath = "./Host.app/Contents/MacOS/Host"

            process.executableURL = URL(
                fileURLWithPath: appPath,
                isDirectory: false,
                relativeTo:  NSRunningApplication.current.bundleURL
            )

            if !FileManager.default.fileExists(atPath: appPath) {
                fatalError("Could not find Host.app.  This must be co-located with the tailmac utility")
            }

            process.arguments = ["run", "--id", id]

            do {
                process.standardOutput = stdOutPipe
                try process.run()
            } catch {
                fatalError("Unable to launch the vm process")
            }

            // This doesn't print until we exit which is not ideal, but at least we
            // get the output
            if tail != 0 {
                let outHandle = stdOutPipe.fileHandleForReading

                let queue =  OperationQueue()
                NotificationCenter.default.addObserver(
                    forName: NSNotification.Name.NSFileHandleDataAvailable,
                    object: outHandle, queue: queue)
                {
                    notification -> Void in
                    let data = outHandle.availableData
                    if data.count > 0 {
                        if let str = String(data: data, encoding: String.Encoding.utf8) {
                            print(str)
                        }
                    }
                    outHandle.waitForDataInBackgroundAndNotify()
                }
                outHandle.waitForDataInBackgroundAndNotify()
                process.waitUntilExit()
            }
        }
    }
}

extension Tailmac {
    struct Configure: ParsableCommand {
        @Option(help: "The vm identifier") var id: String
        @Option(help: "The mac address of the socket network interface") var mac: String?
        @Option(help: "The port for the virtio socket device") var port: String?
        @Option(help: "The named socket for the socket network interface") var sock: String?
        @Option(help: "The desired RAM in bytes") var mem: String?
        @Option(help: "The ethernet address for a standard NAT adapter") var ethermac: String?

        mutating func run() {
            let config = Config(id)

            let vmExists = FileManager.default.fileExists(atPath: config.vmDataURL.path())
            if !vmExists {
                print("VM with id \(id) doesn't exist.  Cannot configure.")
                return
            }

            if let mac {
                config.mac = mac
            }
            if let port, let portInt = UInt32(port) {
                config.port = portInt
            }
            if let ethermac {
                config.ethermac = ethermac
            }
            if let mem, let membytes = UInt64(mem) {
                config.memorySize = membytes
            }
            if let sock {
                config.serverSocket = sock
            }

            config.persist()

            let str = String(data:try! JSONEncoder().encode(config), encoding: .utf8)!
            print("New Config: \(str)")
        }
    }
}

extension Tailmac {
    struct Delete: ParsableCommand {
        @Option(help: "The vm identifer") var id: String?

        mutating func run() {
            guard let id else {
                print("Usage: Installer delete --id=<id>")
                return
            }

            let config = Config(id)

            let vmExists = FileManager.default.fileExists(atPath: config.vmDataURL.path())
            if !vmExists {
                print("VM with id \(id) doesn't exist.  Cannot delete.")
                return
            }

            do {
                try FileManager.default.removeItem(at: config.vmDataURL)
            } catch {
                print("Whoops... Deletion failed \(error)")
            }
        }
    }
}


extension Tailmac {
    struct Clone: ParsableCommand {
        @Option(help: "The vm identifier") var id: String
        @Option(help: "The vm identifier for the cloned vm") var targetId: String

        mutating func run() {

            let config = Config(id)
            let targetConfig = Config(targetId)

            if id == targetId {
                fatalError("The ids match.  Clone failed.")
            }

            let vmExists = FileManager.default.fileExists(atPath: config.vmDataURL.path())
            if !vmExists {
                print("VM with id \(id) doesn't exist.  Cannot clone.")
                return
            }

            print("Cloning \(config.vmDataURL) to \(targetConfig.vmDataURL)")
            do {
                try FileManager.default.copyItem(at: config.vmDataURL, to: targetConfig.vmDataURL)
            } catch {
                print("Whoops... Cloning failed \(error)")
            }
        }
    }
}

extension Tailmac {
    struct RefreshImage: ParsableCommand {
        mutating func run() {
            let config = Config()
            let exists = FileManager.default.fileExists(atPath: config.restoreImageURL.path())
            if exists {
                try? FileManager.default.removeItem(at: config.restoreImageURL)
            }
            let restoreImage = RestoreImage(config.restoreImageURL)
            restoreImage.download {
                print("Restore image refreshed")
            }
        }
    }
}

extension Tailmac {
    struct Create: ParsableCommand {
        @Option(help: "The vm identifier.  Each VM instance needs a unique ID.") var id: String
        @Option(help: "The mac address of the socket network interface") var mac: String?
        @Option(help: "The port for the virtio socket device") var port: String?
        @Option(help: "The named socket for the socket network interface") var sock: String?
        @Option(help: "The desired RAM in bytes") var mem: String?
        @Option(help: "The ethernet address for a standard NAT adapter") var ethermac: String?
        @Option(help: "The image name to build from.  If omitted we will use RestoreImage.ipsw in ~/VM.bundle and download it if needed") var image: String?

        mutating func run() {
            buildVM(id)
        }

        func buildVM(_ id: String) {
            print("Configuring vm with id \(id)")

            let config = Config(id)
            let installer = VMInstaller(config)

            let vmExists = FileManager.default.fileExists(atPath: config.vmDataURL.path())
            if vmExists {
                print("VM with id \(id) already exists.  No action taken.")
                return
            }

            createDir(config.vmDataURL.path())

            if let mac {
                config.mac = mac
            }
            if let port, let portInt = UInt32(port) {
                config.port = portInt
            }
            if let ethermac {
                config.ethermac = ethermac
            }
            if let mem, let membytes = UInt64(mem) {
                config.memorySize = membytes
            }
            if let sock {
                config.serverSocket = sock
            }

            config.persist()

            let restoreImagePath = image ?? config.restoreImageURL.path()

            let exists = FileManager.default.fileExists(atPath: restoreImagePath)
            if exists {
                print("Using existing restore image at \(restoreImagePath)")
                installer.installMacOS(ipswURL: URL(fileURLWithPath: restoreImagePath))
            } else {
                if image != nil {
                    fatalError("Unable to find custom restore image")
                }

                print("Downloading default restore image to \(config.restoreImageURL)")
                let restoreImage = RestoreImage(URL(fileURLWithPath: restoreImagePath))
                restoreImage.download {
                    // Install from the restore image that you downloaded.
                    installer.installMacOS(ipswURL: URL(fileURLWithPath: restoreImagePath))
                }
            }

            dispatchMain()
        }
    }
}
