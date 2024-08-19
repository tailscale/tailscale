// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Cocoa
import Foundation
import Virtualization

class AppDelegate: NSObject, NSApplicationDelegate  {
    @IBOutlet var window: NSWindow!

    @IBOutlet weak var virtualMachineView: VZVirtualMachineView!

    var runner: VMController!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        DispatchQueue.main.async { [self] in
            runner = VMController()
            runner.createVirtualMachine()
            virtualMachineView.virtualMachine = runner.virtualMachine
            virtualMachineView.capturesSystemKeys = true

            // Configure the app to automatically respond to changes in the display size.
            virtualMachineView.automaticallyReconfiguresDisplay = true

            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: config.saveFileURL.path) {
                print("Restoring virtual machine state from \(config.saveFileURL)")
                runner.restoreVirtualMachine()
            } else {
                print("Restarting virtual machine")
                runner.startVirtualMachine()
            }

        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if runner.virtualMachine.state == .running {
            runner.pauseAndSaveVirtualMachine(completionHandler: {
                sender.reply(toApplicationShouldTerminate: true)
            })

            return .terminateLater
        }

        return .terminateNow
    }
}
