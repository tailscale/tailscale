/*
See the LICENSE.txt file for this sample’s licensing information.

Abstract:
The entry for `InstallationTool`.
*/

import Foundation

#if arch(arm64)

let installer = MacOSVirtualMachineInstaller()

if CommandLine.arguments.count == 2 {
    let ipswPath = String(CommandLine.arguments[1])
    let ipswURL = URL(fileURLWithPath: ipswPath)
    guard ipswURL.isFileURL else {
        fatalError("The provided IPSW path is not a valid file URL.")
    }

    installer.setUpVirtualMachineArtifacts()
    installer.installMacOS(ipswURL: ipswURL)

    dispatchMain()
} else if CommandLine.arguments.count == 1 {
    installer.setUpVirtualMachineArtifacts()

    let restoreImage = MacOSRestoreImage()
    restoreImage.download {
        // Install from the restore image that you downloaded.
        installer.installMacOS(ipswURL: restoreImageURL)
    }

    dispatchMain()
} else {
    NSLog("Invalid argument. Please either provide the path to an IPSW file, or run this tool without any argument.")
    exit(-1)
}

#else

NSLog("This tool can only be run on Apple Silicon Macs.")

#endif
