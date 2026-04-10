// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Cocoa
import Foundation
import Virtualization
import ArgumentParser

@main
struct HostCli: ParsableCommand {
    static var configuration = CommandConfiguration(
        abstract: "A utility for running virtual machines",
        subcommands: [Run.self],
        defaultSubcommand: Run.self)
}

var config: Config = Config()

extension HostCli {
    struct Run: ParsableCommand {
        @Option var id: String
        @Option var share: String?
        @Flag(help: "Run without GUI (for automated testing)") var headless: Bool = false

        mutating func run() {
            config = Config(id)
            config.sharedDir = share
            print("Running vm with identifier \(id) and sharedDir \(share ?? "<none>")")

            if headless {
                DispatchQueue.main.async {
                    let controller = VMController()
                    controller.createVirtualMachine(headless: true)

                    let fileManager = FileManager.default
                    if fileManager.fileExists(atPath: config.saveFileURL.path) {
                        print("Restoring virtual machine state from \(config.saveFileURL)")
                        controller.restoreVirtualMachine()
                    } else {
                        print("Starting virtual machine")
                        controller.startVirtualMachine()
                    }
                }
                RunLoop.main.run()
            } else {
                _ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
            }
        }
    }
}

