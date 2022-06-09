// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
import * as BrowserFS from "browserfs"

export function injectFS() {
  return new Promise((resolve, reject) => {
    BrowserFS.configure({ fs: "InMemory" }, () => {
      const goFs = globalThis.fs
      const browserFs = BrowserFS.BFSRequire("fs")
      const { Buffer } = BrowserFS.BFSRequire("buffer")
      globalThis.fs = {
        constants: {
          O_WRONLY: 1,
          O_RDWR: 2,
          O_CREAT: 64,
          O_TRUNC: 512,
          O_APPEND: 1024,
          O_EXCL: 128,
        },
        ...browserFs,
        open(path, flags, mode, callback) {
          if (typeof flags === "number") {
            flags &= 0x1fff
            if (flags in FLAGS_TO_PERMISSION_STRING_MAP) {
              flags = FLAGS_TO_PERMISSION_STRING_MAP[flags]
            } else {
              console.warn(
                `Unknown flags ${flags}, will not map to permission string`
              )
            }
          }
          return browserFs.open(path, flags, mode, callback)
        },
        writeSync(fd, buf) {
          if (fd <= 2) {
            return goFs.writeSync(fd, buf)
          }
          return browserFs.writeSync(fb, buf)
        },
        write(fd, buf, offset, length, position, callback) {
          if (fd <= 2) {
            return goFs.write(fd, buf, offset, length, position, callback)
          }
          return browserFs.write(
            fd,
            Buffer.from(buf),
            offset,
            length,
            position,
            callback
          )
        },
        close(fd, callback) {
          return browserFs.close(fd, (err) => {
            callback(err === undefined ? null : err)
          })
        },
        fstat(fd, callback) {
          return browserFs.fstat(fd, (err, retStat) => {
            delete retStat["fileData"]
            retStat.atimeMs = retStat.atime.getTime()
            retStat.mtimeMs = retStat.mtime.getTime()
            retStat.ctimeMs = retStat.ctime.getTime()
            retStat.birthtimeMs = retStat.birthtime.getTime()
            return callback(err, retStat)
          })
        },
      }

      resolve()
    })
  })
}

const FLAGS_TO_PERMISSION_STRING_MAP = {
  0 /*O_RDONLY*/: "r",
  1 /*O_WRONLY*/: "r+",
  2 /*O_RDWR*/: "r+",
  64 /*O_CREAT*/: "r",
  65 /*O_WRONLY|O_CREAT*/: "r+",
  66 /*O_RDWR|O_CREAT*/: "r+",
  129 /*O_WRONLY|O_EXCL*/: "rx+",
  193 /*O_WRONLY|O_CREAT|O_EXCL*/: "rx+",
  514 /*O_RDWR|O_TRUNC*/: "w+",
  577 /*O_WRONLY|O_CREAT|O_TRUNC*/: "w",
  578 /*O_CREAT|O_RDWR|O_TRUNC*/: "w+",
  705 /*O_WRONLY|O_CREAT|O_EXCL|O_TRUNC*/: "wx",
  706 /*O_RDWR|O_CREAT|O_EXCL|O_TRUNC*/: "wx+",
  1024 /*O_APPEND*/: "a",
  1025 /*O_WRONLY|O_APPEND*/: "a",
  1026 /*O_RDWR|O_APPEND*/: "a+",
  1089 /*O_WRONLY|O_CREAT|O_APPEND*/: "a",
  1090 /*O_RDWR|O_CREAT|O_APPEND*/: "a+",
  1153 /*O_WRONLY|O_EXCL|O_APPEND*/: "ax",
  1154 /*O_RDWR|O_EXCL|O_APPEND*/: "ax+",
  1217 /*O_WRONLY|O_CREAT|O_EXCL|O_APPEND*/: "ax",
  1218 /*O_RDWR|O_CREAT|O_EXCL|O_APPEND*/: "ax+",
  4096 /*O_RDONLY|O_DSYNC*/: "rs",
  4098 /*O_RDWR|O_DSYNC*/: "rs+",
}
