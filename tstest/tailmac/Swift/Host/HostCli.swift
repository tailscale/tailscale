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
        @Flag(help: "Create NIC with no attachment (for later hot-swap)") var disconnectedNic: Bool = false
        @Option(help: "Hot-swap NIC to this dgram socket path after boot/restore") var attachNetwork: String?
        @Option(help: "Serve screenshots on this localhost port (0 = auto)") var screenshotPort: Int?

        mutating func run() {
            config = Config(id)
            config.sharedDir = share
            print("Running vm with identifier \(id) and sharedDir \(share ?? "<none>")")

            if headless {
                let attachSocket = attachNetwork
                let disconnected = disconnectedNic || attachSocket != nil
                let wantScreenshots = screenshotPort != nil
                let requestedPort = UInt16(screenshotPort ?? 0)

                DispatchQueue.main.async {
                    let controller = VMController()
                    controller.createVirtualMachine(headless: true, disconnectedNIC: disconnected)

                    // Handle SIGINT (from test cleanup) by saving VM state before exit.
                    let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
                    signal(SIGINT, SIG_IGN) // Let DispatchSource handle it
                    sigintSource.setEventHandler {
                        print("SIGINT received, saving VM state...")
                        controller.pauseAndSaveVirtualMachine {
                            print("VM state saved, exiting.")
                            Foundation.exit(0)
                        }
                    }
                    sigintSource.resume()

                    // Set up screenshot HTTP server if requested.
                    // The window must be ordered on-screen for the window server
                    // to composite VZVirtualMachineView's content. We place it
                    // behind all other windows and make it tiny (1x1) so it's
                    // effectively invisible.
                    if wantScreenshots {
                        let vmView = VZVirtualMachineView()
                        vmView.virtualMachine = controller.virtualMachine
                        vmView.frame = NSRect(x: 0, y: 0, width: 1920, height: 1200)

                        let window = NSWindow(
                            contentRect: NSRect(x: 0, y: 0, width: 1920, height: 1200),
                            styleMask: [.borderless],
                            backing: .buffered,
                            defer: false
                        )
                        window.isReleasedWhenClosed = false
                        window.contentView = vmView
                        // Place behind all other windows so it's not visible to the user.
                        window.level = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.minimumWindow)) - 1)
                        window.orderFront(nil)

                        startScreenshotServer(view: vmView, port: requestedPort)
                    }

                    let doAttach = {
                        if let sock = attachSocket {
                            // Give macOS a moment to settle after boot/restore,
                            // then hot-swap the NIC attachment.
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                                controller.attachNetwork(serverSocket: sock, clientID: config.vmID)
                            }
                        }
                    }

                    let fileManager = FileManager.default
                    if fileManager.fileExists(atPath: config.saveFileURL.path) {
                        print("Restoring virtual machine state from \(config.saveFileURL)")
                        controller.restoreVirtualMachine()
                        doAttach()
                    } else {
                        print("Starting virtual machine")
                        controller.startVirtualMachine()
                        doAttach()
                    }
                }

                if wantScreenshots {
                    // NSApp event loop needed for VZVirtualMachineView rendering.
                    let app = NSApplication.shared
                    app.setActivationPolicy(.accessory)
                    print("STARTING_NSAPP")
                    fflush(stdout)
                    app.run()
                } else {
                    RunLoop.main.run()
                }
            } else {
                _ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
            }
        }
    }
}

// startScreenshotServer starts a localhost HTTP server that serves VM display
// screenshots on GET /screenshot as JPEG. The port is printed to stdout as
// "SCREENSHOT_PORT=<port>" so the Go test harness can discover it.
var screenshotServer: ScreenshotHTTPServer? // prevent GC

func startScreenshotServer(view: NSView, port: UInt16) {
    let server = ScreenshotHTTPServer(view: view)
    screenshotServer = server
    server.start(port: port)
}

/// Minimal HTTP server that serves screenshots of a VZVirtualMachineView.
class ScreenshotHTTPServer: NSObject {
    let view: NSView
    var acceptSource: DispatchSourceRead? // prevent GC

    init(view: NSView) {
        self.view = view
    }

    private func log(_ msg: String) {
        let s = msg + "\n"
        FileHandle.standardError.write(Data(s.utf8))
    }

    func start(port: UInt16) {
        let queue = DispatchQueue(label: "screenshot-server")

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            log("screenshot server: socket() failed")
            return
        }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian // 127.0.0.1

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            log("screenshot server: bind() failed: \(errno)")
            close(fd)
            return
        }
        guard Darwin.listen(fd, 4) == 0 else {
            log("screenshot server: listen() failed")
            close(fd)
            return
        }

        var boundAddr = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(fd, sockPtr, &boundLen)
            }
        }
        let actualPort = UInt16(bigEndian: boundAddr.sin_port)
        print("SCREENSHOT_PORT=\(actualPort)")
        fflush(stdout)

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [self] in
            let clientFd = accept(fd, nil, nil)
            self.log("screenshot: accept fd=\(clientFd)")
            guard clientFd >= 0 else { return }
            self.handleConnection(clientFd)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        self.acceptSource = source
    }

    private func handleConnection(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(fd, &buf, buf.count)
        let requestLine = n > 0 ? String(bytes: buf[..<n], encoding: .utf8) ?? "" : ""

        // Route: POST /keypress?key=<keycode> — send a key event to the VM.
        if requestLine.contains("/keypress") {
            handleKeypress(fd, requestLine)
            return
        }

        // Route: GET /screenshot — capture the VM display.
        let wantFull = requestLine.contains("full=1")

        let sem = DispatchSemaphore(value: 0)
        var jpegData: Data?
        DispatchQueue.main.async { [self] in
            jpegData = self.captureScreenshot(fullSize: wantFull)
            sem.signal()
        }
        sem.wait()

        guard let data = jpegData else {
            let resp = Data("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".utf8)
            resp.withUnsafeBytes { write(fd, $0.baseAddress!, resp.count) }
            close(fd)
            return
        }

        var response = Data("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: \(data.count)\r\nConnection: close\r\n\r\n".utf8)
        response.append(data)
        response.withUnsafeBytes { ptr in
            var total = 0
            while total < response.count {
                let n = write(fd, ptr.baseAddress! + total, response.count - total)
                if n <= 0 { break }
                total += n
            }
        }
        close(fd)
        log("screenshot: served \(data.count) bytes")
    }

    private func captureScreenshot(fullSize: Bool = false) -> Data? {
        guard let window = view.window else {
            log("screenshot: no window")
            return nil
        }

        // Use CGWindowListCreateImage to capture the composited window content,
        // which includes GPU-rendered layers like VZVirtualMachineView's Metal surface.
        let windowID = CGWindowID(window.windowNumber)
        guard let cgImage = CGWindowListCreateImage(
            .null,
            .optionIncludingWindow,
            windowID,
            [.boundsIgnoreFraming, .bestResolution]
        ) else {
            log("screenshot: CGWindowListCreateImage returned nil")
            return nil
        }

        if fullSize {
            let bitmapRep = NSBitmapImageRep(cgImage: cgImage)
            return bitmapRep.representation(using: .jpeg, properties: [.compressionFactor: 0.85])
        }

        // Resize to ~800px wide for thumbnails.
        let targetWidth = 800
        let scale = Double(targetWidth) / Double(cgImage.width)
        let targetHeight = Int(Double(cgImage.height) * scale)

        guard let ctx = CGContext(
            data: nil,
            width: targetWidth,
            height: targetHeight,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
        ) else {
            log("screenshot: CGContext creation failed")
            return nil
        }
        ctx.interpolationQuality = .high
        ctx.draw(cgImage, in: CGRect(x: 0, y: 0, width: targetWidth, height: targetHeight))

        guard let resized = ctx.makeImage() else {
            log("screenshot: makeImage failed")
            return nil
        }

        let bitmapRep = NSBitmapImageRep(cgImage: resized)
        return bitmapRep.representation(using: .jpeg, properties: [.compressionFactor: 0.6])
    }
}

