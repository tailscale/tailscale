// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package hostinfo answers questions about the host environment that Tailscale is
// running on.
package hostinfo

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/lineread"
	"tailscale.com/version"
)

var started = time.Now()

// New returns a partially populated Hostinfo for the current host.
func New() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	hostname = dnsname.FirstLabel(hostname)
	return &tailcfg.Hostinfo{
		IPNVersion:      version.Long(),
		Hostname:        hostname,
		App:             appTypeCached(),
		OS:              version.OS(),
		OSVersion:       GetOSVersion(),
		Container:       lazyInContainer.Get(),
		Distro:          condCall(distroName),
		DistroVersion:   condCall(distroVersion),
		DistroCodeName:  condCall(distroCodeName),
		Env:             string(GetEnvType()),
		Desktop:         desktop(),
		Package:         packageTypeCached(),
		GoArch:          runtime.GOARCH,
		GoArchVar:       lazyGoArchVar.Get(),
		GoVersion:       runtime.Version(),
		Machine:         condCall(unameMachine),
		DeviceModel:     deviceModel(),
		Cloud:           string(cloudenv.Get()),
		NoLogsNoSupport: envknob.NoLogsNoSupport(),
		AllowsUpdate:    envknob.AllowsRemoteUpdate(),
		WoLMACs:         getWoLMACs(),
	}
}

// non-nil on some platforms
var (
	osVersion      func() string
	packageType    func() string
	distroName     func() string
	distroVersion  func() string
	distroCodeName func() string
	unameMachine   func() string
)

func condCall[T any](fn func() T) T {
	var zero T
	if fn == nil {
		return zero
	}
	return fn()
}

var (
	lazyInContainer = &lazyAtomicValue[opt.Bool]{f: ptr.To(inContainer)}
	lazyGoArchVar   = &lazyAtomicValue[string]{f: ptr.To(goArchVar)}
)

type lazyAtomicValue[T any] struct {
	// f is a pointer to a fill function. If it's nil or points
	// to nil, then Get returns the zero value for T.
	f *func() T

	once sync.Once
	v    T
}

func (v *lazyAtomicValue[T]) Get() T {
	v.once.Do(v.fill)
	return v.v
}

func (v *lazyAtomicValue[T]) fill() {
	if v.f == nil || *v.f == nil {
		return
	}
	v.v = (*v.f)()
}

// GetOSVersion returns the OSVersion of current host if available.
func GetOSVersion() string {
	if s, _ := osVersionAtomic.Load().(string); s != "" {
		return s
	}
	if osVersion != nil {
		return osVersion()
	}
	return ""
}

func appTypeCached() string {
	if v, ok := appType.Load().(string); ok {
		return v
	}
	return ""
}

func packageTypeCached() string {
	if v, _ := packagingType.Load().(string); v != "" {
		return v
	}
	if packageType == nil {
		return ""
	}
	v := packageType()
	if v != "" {
		SetPackage(v)
	}
	return v
}

// EnvType represents a known environment type.
// The empty string, the default, means unknown.
type EnvType string

const (
	KNative            = EnvType("kn")
	AWSLambda          = EnvType("lm")
	Heroku             = EnvType("hr")
	AzureAppService    = EnvType("az")
	AWSFargate         = EnvType("fg")
	FlyDotIo           = EnvType("fly")
	Kubernetes         = EnvType("k8s")
	DockerDesktop      = EnvType("dde")
	Replit             = EnvType("repl")
	HomeAssistantAddOn = EnvType("haao")
)

var envType atomic.Value // of EnvType

func GetEnvType() EnvType {
	if e, ok := envType.Load().(EnvType); ok {
		return e
	}
	e := getEnvType()
	envType.Store(e)
	return e
}

var (
	deviceModelAtomic atomic.Value // of string
	osVersionAtomic   atomic.Value // of string
	desktopAtomic     atomic.Value // of opt.Bool
	packagingType     atomic.Value // of string
	appType           atomic.Value // of string
	firewallMode      atomic.Value // of string
)

// SetDeviceModel sets the device model for use in Hostinfo updates.
func SetDeviceModel(model string) { deviceModelAtomic.Store(model) }

// SetOSVersion sets the OS version.
func SetOSVersion(v string) { osVersionAtomic.Store(v) }

// SetFirewallMode sets the firewall mode for the app.
func SetFirewallMode(v string) { firewallMode.Store(v) }

// SetPackage sets the packaging type for the app.
//
// As of 2022-03-25, this is used by Android ("nogoogle" for the
// F-Droid build) and tsnet (set to "tsnet").
func SetPackage(v string) { packagingType.Store(v) }

// SetApp sets the app type for the app.
// It is used by tsnet to specify what app is using it such as "golinks"
// and "k8s-operator".
func SetApp(v string) { appType.Store(v) }

func deviceModel() string {
	s, _ := deviceModelAtomic.Load().(string)
	return s
}

// FirewallMode returns the firewall mode for the app.
// It is empty if unset.
func FirewallMode() string {
	s, _ := firewallMode.Load().(string)
	return s
}

func desktop() (ret opt.Bool) {
	if runtime.GOOS != "linux" {
		return opt.Bool("")
	}
	if v := desktopAtomic.Load(); v != nil {
		v, _ := v.(opt.Bool)
		return v
	}

	seenDesktop := false
	lineread.File("/proc/net/unix", func(line []byte) error {
		seenDesktop = seenDesktop || mem.Contains(mem.B(line), mem.S(" @/tmp/dbus-"))
		seenDesktop = seenDesktop || mem.Contains(mem.B(line), mem.S(".X11-unix"))
		seenDesktop = seenDesktop || mem.Contains(mem.B(line), mem.S("/wayland-1"))
		return nil
	})
	ret.Set(seenDesktop)

	// Only cache after a minute - compositors might not have started yet.
	if time.Since(started) > time.Minute {
		desktopAtomic.Store(ret)
	}
	return ret
}

func getEnvType() EnvType {
	if inKnative() {
		return KNative
	}
	if inAWSLambda() {
		return AWSLambda
	}
	if inHerokuDyno() {
		return Heroku
	}
	if inAzureAppService() {
		return AzureAppService
	}
	if inAWSFargate() {
		return AWSFargate
	}
	if inFlyDotIo() {
		return FlyDotIo
	}
	if inKubernetes() {
		return Kubernetes
	}
	if inDockerDesktop() {
		return DockerDesktop
	}
	if inReplit() {
		return Replit
	}
	if inHomeAssistantAddOn() {
		return HomeAssistantAddOn
	}
	return ""
}

// inContainer reports whether we're running in a container.
func inContainer() opt.Bool {
	if runtime.GOOS != "linux" {
		return ""
	}
	var ret opt.Bool
	ret.Set(false)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		ret.Set(true)
		return ret
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		// See https://github.com/cri-o/cri-o/issues/5461
		ret.Set(true)
		return ret
	}
	lineread.File("/proc/1/cgroup", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("/docker/")) ||
			mem.Contains(mem.B(line), mem.S("/lxc/")) {
			ret.Set(true)
			return io.EOF // arbitrary non-nil error to stop loop
		}
		return nil
	})
	lineread.File("/proc/mounts", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("lxcfs /proc/cpuinfo fuse.lxcfs")) {
			ret.Set(true)
			return io.EOF
		}
		return nil
	})
	return ret
}

func inKnative() bool {
	// https://cloud.google.com/run/docs/reference/container-contract#env-vars
	if os.Getenv("K_REVISION") != "" && os.Getenv("K_CONFIGURATION") != "" &&
		os.Getenv("K_SERVICE") != "" && os.Getenv("PORT") != "" {
		return true
	}
	return false
}

func inAWSLambda() bool {
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" &&
		os.Getenv("AWS_LAMBDA_FUNCTION_VERSION") != "" &&
		os.Getenv("AWS_LAMBDA_INITIALIZATION_TYPE") != "" &&
		os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" {
		return true
	}
	return false
}

func inHerokuDyno() bool {
	// https://devcenter.heroku.com/articles/dynos#local-environment-variables
	if os.Getenv("PORT") != "" && os.Getenv("DYNO") != "" {
		return true
	}
	return false
}

func inAzureAppService() bool {
	if os.Getenv("APPSVC_RUN_ZIP") != "" && os.Getenv("WEBSITE_STACK") != "" &&
		os.Getenv("WEBSITE_AUTH_AUTO_AAD") != "" {
		return true
	}
	return false
}

func inAWSFargate() bool {
	return os.Getenv("AWS_EXECUTION_ENV") == "AWS_ECS_FARGATE"
}

func inFlyDotIo() bool {
	if os.Getenv("FLY_APP_NAME") != "" && os.Getenv("FLY_REGION") != "" {
		return true
	}
	return false
}

func inReplit() bool {
	// https://docs.replit.com/programming-ide/getting-repl-metadata
	if os.Getenv("REPL_OWNER") != "" && os.Getenv("REPL_SLUG") != "" {
		return true
	}
	return false
}

func inKubernetes() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		return true
	}
	return false
}

func inDockerDesktop() bool {
	return os.Getenv("TS_HOST_ENV") == "dde"
}

func inHomeAssistantAddOn() bool {
	if os.Getenv("SUPERVISOR_TOKEN") != "" || os.Getenv("HASSIO_TOKEN") != "" {
		return true
	}
	return false
}

// goArchVar returns the GOARM or GOAMD64 etc value that the binary was built
// with.
func goArchVar() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	// Look for GOARM, GOAMD64, GO386, etc. Note that the little-endian
	// "le"-suffixed GOARCH values don't have their own environment variable.
	//
	// See https://pkg.go.dev/cmd/go#hdr-Environment_variables and the
	// "Architecture-specific environment variables" section:
	wantKey := "GO" + strings.ToUpper(strings.TrimSuffix(runtime.GOARCH, "le"))
	for _, s := range bi.Settings {
		if s.Key == wantKey {
			return s.Value
		}
	}
	return ""
}

type etcAptSrcResult struct {
	mod      time.Time
	disabled bool
}

var etcAptSrcCache atomic.Value // of etcAptSrcResult

// DisabledEtcAptSource reports whether Ubuntu (or similar) has disabled
// the /etc/apt/sources.list.d/tailscale.list file contents upon upgrade
// to a new release of the distro.
//
// See https://github.com/tailscale/tailscale/issues/3177
func DisabledEtcAptSource() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	const path = "/etc/apt/sources.list.d/tailscale.list"
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	mod := fi.ModTime()
	if c, ok := etcAptSrcCache.Load().(etcAptSrcResult); ok && c.mod.Equal(mod) {
		return c.disabled
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	v := etcAptSourceFileIsDisabled(f)
	etcAptSrcCache.Store(etcAptSrcResult{mod: mod, disabled: v})
	return v
}

func etcAptSourceFileIsDisabled(r io.Reader) bool {
	bs := bufio.NewScanner(r)
	disabled := false // did we find the "disabled on upgrade" comment?
	for bs.Scan() {
		line := strings.TrimSpace(bs.Text())
		if strings.Contains(line, "# disabled on upgrade") {
			disabled = true
		}
		if line == "" || line[0] == '#' {
			continue
		}
		// Well, it has some contents in it at least.
		return false
	}
	return disabled
}

// IsSELinuxEnforcing reports whether SELinux is in "Enforcing" mode.
func IsSELinuxEnforcing() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	out, _ := exec.Command("getenforce").Output()
	return string(bytes.TrimSpace(out)) == "Enforcing"
}
