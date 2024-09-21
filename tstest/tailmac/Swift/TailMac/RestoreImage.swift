// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Virtualization

class RestoreImage: NSObject {
    private var downloadObserver: NSKeyValueObservation?

    // MARK: Observe the download progress.

    var restoreImageURL: URL

    init(_ dest: URL) {
        restoreImageURL = dest
    }

    public func download(completionHandler: @escaping () -> Void) {
        print("Attempting to download latest available restore image.")
        VZMacOSRestoreImage.fetchLatestSupported { [self](result: Result<VZMacOSRestoreImage, Error>) in
            switch result {
            case let .failure(error):
                fatalError(error.localizedDescription)

            case let .success(restoreImage):
                downloadRestoreImage(restoreImage: restoreImage, completionHandler: completionHandler)
            }
        }
    }

    private func downloadRestoreImage(restoreImage: VZMacOSRestoreImage, completionHandler: @escaping () -> Void) {
        let downloadTask = URLSession.shared.downloadTask(with: restoreImage.url) { localURL, response, error in
            if let error = error {
                fatalError("Download failed. \(error.localizedDescription).")
            }

            do {
                try FileManager.default.moveItem(at: localURL!, to: self.restoreImageURL)
            } catch {
                fatalError("Failed to move downloaded restore image to \(self.restoreImageURL) \(error).")
            }


            completionHandler()
        }

        var lastPct = 0
        downloadObserver = downloadTask.progress.observe(\.fractionCompleted, options: [.initial, .new]) { (progress, change) in
            let pct = Int(change.newValue! * 100)
            if pct != lastPct {
                print("Restore image download progress: \(pct)%")
                lastPct = pct
            }
        }
        downloadTask.resume()
    }
}

