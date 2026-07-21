# Tailscale 生产环境安装包构建方法

基于 commit `38885619f`，分支 `direct-udp-path-health`，Go 1.26.5。

## 构建环境

- Go 1.26.5: `~/.local/go1.26.5/bin/go`
- 宿主: linux/amd64 (WSL)
- CGO_ENABLED=0 (静态链接)
- 项目路径: `/home/sun/workspace/tailscale`

## 一、Linux amd64 包

### 构建命令

```bash
cd /home/sun/workspace/tailscale

export PATH="$HOME/.local/go1.26.5/bin:$PATH"
export CGO_ENABLED=0

# tailscale CLI
GOOS=linux GOARCH=amd64 ./build_dist.sh --strip \
  -o dist/linux/tailscale ./cmd/tailscale

# tailscaled 后台服务
GOOS=linux GOARCH=amd64 ./build_dist.sh --strip \
  -o dist/linux/tailscaled ./cmd/tailscaled
```

### 打包

```bash
tar czf dist/tailscale_<VERSION>_linux_amd64.tar.gz \
  -C dist/linux tailscale tailscaled
```

### 验证

```bash
./dist/linux/tailscale version
# 应输出:
#   1.101.250
#     track: unstable (dev); frequent updates and bugs are likely
#     tailscale commit: 38885619f...-dirty
#     long version: 1.101.250-t38885619f
#     go version: go1.26.5
```

## 二、Windows amd64 包

### 构建命令

```bash
cd /home/sun/workspace/tailscale

export PATH="$HOME/.local/go1.26.5/bin:$PATH"
export CGO_ENABLED=0

# tailscale CLI (标准 windows)
GOOS=windows GOARCH=amd64 ./build_dist.sh --strip \
  -o dist/windows/tailscale.exe ./cmd/tailscale

# tailscaled 后台服务
GOOS=windows GOARCH=amd64 ./build_dist.sh --strip \
  -o dist/windows/tailscaled.exe ./cmd/tailscaled

# tailscale-ipn GUI 系统托盘
# 注意：必须使用 TS_USE_GOCROSS=1 + ./tool/go
# windowsgui 是 gocross 的伪 GOOS，不能直接用标准 Go
export TS_USE_GOCROSS=1
GOOS=windowsgui GOARCH=amd64 ./tool/go build -trimpath \
  -o dist/windows/tailscale-ipn.exe ./cmd/systray
```

### 下载 wintun.dll

```bash
curl -sL -o /tmp/wintun.zip "https://www.wintun.net/builds/wintun-0.14.1.zip"
unzip -o /tmp/wintun.zip wintun/bin/amd64/wintun.dll -d /tmp/
cp /tmp/wintun/bin/amd64/wintun.dll dist/windows/wintun.dll
```

### 打包

```bash
cd dist/windows
zip -q ../tailscale_<VERSION>_windows_amd64.zip \
  tailscale.exe tailscaled.exe tailscale-ipn.exe wintun.dll
```

### 验证

```bash
file dist/windows/tailscale-ipn.exe
# 必须是: PE32+ executable for MS Windows 6.01 (GUI), x86-64
# 不能是 (console)，否则系统托盘不会显示

strings dist/windows/tailscale.exe | grep -E '^[0-9]+\.[0-9]+\.[0-9]+'
# 应输出版本号
```

## 三、关键细节

### 版本信息注入

`build_dist.sh` 自动调用 `./cmd/mkversion` 获取版本信息，注入 `-X tailscale.com/version.longStamp` 和 `-X tailscale.com/version.shortStamp`。

### 为什么要用 gocross 构建 tailscale-ipn.exe

`windowsgui` 不是标准 Go 的 GOOS 值。它是 Tailscale 的 `gocross` 包装器（`./tool/go`）支持的伪 GOOS，实际效果：

| 伪 GOOS | 实际 GOOS | 额外行为 |
|---------|-----------|---------|
| `windows` | `windows` | `-H windows -s` (console 子系统) |
| `windowsgui` | `windows` | `-H windowsgui -s` (GUI 子系统，无控制台窗口) |
| `windowsdll` | `windows` | 需要 cgo + mingw-w64，构建 .dll |

不设置 `TS_USE_GOCROSS=1` 时，`./tool/go` 只使用 tailscale 的 Go 工具链，不启用 gocross 的额外处理，此时 `GOOS=windowsgui` 会报错 "unsupported GOOS/GOARCH pair"。

### 为什么不能传自定义 -ldflags

gocross 的 `autoflags.go` 会根据 `GOOS=windowsgui` 自动添加 `-H windowsgui -s`。如果传了自定义 `-ldflags`，会覆盖 gocross 的自动标志，导致：
- 不传 `-ldflags` → gocross 自动添加 `-H windowsgui -s` → 正确生成 GUI 子系统
- 传 `-ldflags="-s -w"` → 覆盖了 gocross 的 `-H windowsgui` → 生成 console 子系统

### 尺寸对比

| 文件 | 未 strip | 已 strip (--strip) | 官方 |
|------|----------|-------------------|------|
| tailscale (linux) | 32 MB | 23 MB | — |
| tailscaled (linux) | 41 MB | 29 MB | — |
| tailscale.exe | 24 MB | 17 MB | 17 MB |
| tailscaled.exe | 36 MB | 25 MB | 25 MB |
| tailscale-ipn.exe | 14 MB | 9.7 MB | 25 MB |

`build_dist.sh --strip` 等价于添加 `-ldflags="-w -s"`。

## 四、一次性全量构建脚本

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION=$(cd /home/sun/workspace/tailscale && ./build_dist.sh shellvars 2>/dev/null | grep VERSION_LONG | cut -d= -f2 | tr -d '"')
echo "Building version: $VERSION"

cd /home/sun/workspace/tailscale
export PATH="$HOME/.local/go1.26.5/bin:$PATH"
export CGO_ENABLED=0
mkdir -p dist/linux dist/windows

# --- Linux ---
GOOS=linux GOARCH=amd64 ./build_dist.sh --strip -o dist/linux/tailscale ./cmd/tailscale
GOOS=linux GOARCH=amd64 ./build_dist.sh --strip -o dist/linux/tailscaled ./cmd/tailscaled
tar czf "dist/tailscale_${VERSION}_linux_amd64.tar.gz" -C dist/linux tailscale tailscaled

# --- Windows ---
GOOS=windows GOARCH=amd64 ./build_dist.sh --strip -o dist/windows/tailscale.exe ./cmd/tailscale
GOOS=windows GOARCH=amd64 ./build_dist.sh --strip -o dist/windows/tailscaled.exe ./cmd/tailscaled

export TS_USE_GOCROSS=1
GOOS=windowsgui GOARCH=amd64 ./tool/go build -trimpath -o dist/windows/tailscale-ipn.exe ./cmd/systray

curl -sL -o /tmp/wintun.zip "https://www.wintun.net/builds/wintun-0.14.1.zip"
unzip -o /tmp/wintun.zip wintun/bin/amd64/wintun.dll -d /tmp/
cp /tmp/wintun/bin/amd64/wintun.dll dist/windows/

cd dist/windows
zip -q "../tailscale_${VERSION}_windows_amd64.zip" \
  tailscale.exe tailscaled.exe tailscale-ipn.exe wintun.dll
cd ../..

echo "=== Done ==="
ls -lh "dist/tailscale_${VERSION}_linux_amd64.tar.gz" "dist/tailscale_${VERSION}_windows_amd64.zip"
```