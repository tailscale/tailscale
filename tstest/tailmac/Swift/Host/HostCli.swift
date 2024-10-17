// Copyright (c) Tailscale Inc & AUTHORS
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

        mutating func run() {
            print("Running vm with identifier \(id)")
            config = Config(id)
            _ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
        }
    }
}

