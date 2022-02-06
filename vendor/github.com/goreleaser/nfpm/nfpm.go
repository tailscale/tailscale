//go:generate go install github.com/golangci/golangci-lint/cmd/golangci-lint

// Package nfpm provides ways to package programs in some linux packaging
// formats.
package nfpm

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Masterminds/semver/v3"
	"github.com/goreleaser/chglog"
	"github.com/imdario/mergo"
	"gopkg.in/yaml.v2"
)

// nolint: gochecknoglobals
var (
	packagers = map[string]Packager{}
	lock      sync.Mutex
)

// Register a new packager for the given format.
func Register(format string, p Packager) {
	lock.Lock()
	packagers[format] = p
	lock.Unlock()
}

// ErrNoPackager happens when no packager is registered for the given format.
type ErrNoPackager struct {
	format string
}

func (e ErrNoPackager) Error() string {
	return fmt.Sprintf("no packager registered for the format %s", e.format)
}

// Get a packager for the given format.
func Get(format string) (Packager, error) {
	p, ok := packagers[format]
	if !ok {
		return nil, ErrNoPackager{format}
	}
	return p, nil
}

// Parse decodes YAML data from an io.Reader into a configuration struct.
func Parse(in io.Reader) (config Config, err error) {
	dec := yaml.NewDecoder(in)
	dec.SetStrict(true)
	if err = dec.Decode(&config); err != nil {
		return
	}

	config.Info.Release = os.ExpandEnv(config.Info.Release)
	config.Info.Version = os.ExpandEnv(config.Info.Version)

	generalPassphrase := os.ExpandEnv("$NFPM_PASSPHRASE")
	config.Deb.Signature.KeyPassphrase = generalPassphrase
	config.RPM.Signature.KeyPassphrase = generalPassphrase
	config.APK.Signature.KeyPassphrase = generalPassphrase

	debPassphrase := os.ExpandEnv("$NFPM_DEB_PASSPHRASE")
	if debPassphrase != "" {
		config.Deb.Signature.KeyPassphrase = debPassphrase
	}

	rpmPassphrase := os.ExpandEnv("$NFPM_RPM_PASSPHRASE")
	if rpmPassphrase != "" {
		config.RPM.Signature.KeyPassphrase = rpmPassphrase
	}

	apkPassphrase := os.ExpandEnv("$NFPM_APK_PASSPHRASE")
	if apkPassphrase != "" {
		config.APK.Signature.KeyPassphrase = apkPassphrase
	}

	return config, config.Validate()
}

// ParseFile decodes YAML data from a file path into a configuration struct.
func ParseFile(path string) (config Config, err error) {
	var file *os.File
	file, err = os.Open(path) //nolint:gosec
	if err != nil {
		return
	}
	defer file.Close() // nolint: errcheck,gosec
	return Parse(file)
}

// Packager represents any packager implementation.
type Packager interface {
	Package(info *Info, w io.Writer) error
	ConventionalFileName(info *Info) string
}

// Config contains the top level configuration for packages.
type Config struct {
	Info      `yaml:",inline"`
	Overrides map[string]Overridables `yaml:"overrides,omitempty"`
}

// Get returns the Info struct for the given packager format. Overrides
// for the given format are merged into the final struct.
func (c *Config) Get(format string) (info *Info, err error) {
	info = &Info{}
	// make a deep copy of info
	if err = mergo.Merge(info, c.Info); err != nil {
		return nil, fmt.Errorf("failed to merge config into info: %w", err)
	}
	override, ok := c.Overrides[format]
	if !ok {
		// no overrides
		return info, nil
	}
	if err = mergo.Merge(&info.Overridables, override, mergo.WithOverride); err != nil {
		return nil, fmt.Errorf("failed to merge overrides into info: %w", err)
	}
	return info, nil
}

// Validate ensures that the config is well typed.
func (c *Config) Validate() error {
	for format := range c.Overrides {
		if _, err := Get(format); err != nil {
			return err
		}
	}
	return nil
}

// Info contains information about a single package.
type Info struct {
	Overridables    `yaml:",inline"`
	Name            string `yaml:"name,omitempty"`
	Arch            string `yaml:"arch,omitempty"`
	Platform        string `yaml:"platform,omitempty"`
	Epoch           string `yaml:"epoch,omitempty"`
	Version         string `yaml:"version,omitempty"`
	Release         string `yaml:"release,omitempty"`
	Prerelease      string `yaml:"prerelease,omitempty"`
	VersionMetadata string `yaml:"version_metadata,omitempty"`
	Section         string `yaml:"section,omitempty"`
	Priority        string `yaml:"priority,omitempty"`
	Maintainer      string `yaml:"maintainer,omitempty"`
	Description     string `yaml:"description,omitempty"`
	Vendor          string `yaml:"vendor,omitempty"`
	Homepage        string `yaml:"homepage,omitempty"`
	License         string `yaml:"license,omitempty"`
	Bindir          string `yaml:"bindir,omitempty"` // Deprecated: this does nothing. TODO: remove.
	Changelog       string `yaml:"changelog,omitempty"`
	DisableGlobbing bool   `yaml:"disable_globbing"`
	Target          string `yaml:"-"`
}

// Overridables contain the field which are overridable in a package.
type Overridables struct {
	Replaces     []string          `yaml:"replaces,omitempty"`
	Provides     []string          `yaml:"provides,omitempty"`
	Depends      []string          `yaml:"depends,omitempty"`
	Recommends   []string          `yaml:"recommends,omitempty"`
	Suggests     []string          `yaml:"suggests,omitempty"`
	Conflicts    []string          `yaml:"conflicts,omitempty"`
	Files        map[string]string `yaml:"files,omitempty"`
	ConfigFiles  map[string]string `yaml:"config_files,omitempty"`
	Symlinks     map[string]string `yaml:"symlinks,omitempty"`
	EmptyFolders []string          `yaml:"empty_folders,omitempty"`
	Scripts      Scripts           `yaml:"scripts,omitempty"`
	RPM          RPM               `yaml:"rpm,omitempty"`
	Deb          Deb               `yaml:"deb,omitempty"`
	APK          APK               `yaml:"apk,omitempty"`
}

// RPM is custom configs that are only available on RPM packages.
type RPM struct {
	Group       string `yaml:"group,omitempty"`
	Summary     string `yaml:"summary,omitempty"`
	Compression string `yaml:"compression,omitempty"`
	// https://www.cl.cam.ac.uk/~jw35/docs/rpm_config.html
	ConfigNoReplaceFiles map[string]string `yaml:"config_noreplace_files,omitempty"`
	Signature            RPMSignature      `yaml:"signature,omitempty"`
	GhostFiles           []string          `yaml:"ghost_files,omitempty"`
}

type RPMSignature struct {
	// PGP secret key, can be ASCII-armored
	KeyFile       string `yaml:"key_file,omitempty"`
	KeyPassphrase string `yaml:"-"` // populated from environment variable
}

type APK struct {
	Signature APKSignature `yaml:"signature,omitempty"`
}

type APKSignature struct {
	// RSA private key in PEM format
	KeyFile       string `yaml:"key_file,omitempty"`
	KeyPassphrase string `yaml:"-"` // populated from environment variable
	// defaults to <maintainer email>.rsa.pub
	KeyName string `yaml:"key_name,omitempty"`
}

// Deb is custom configs that are only available on deb packages.
type Deb struct {
	Scripts         DebScripts   `yaml:"scripts,omitempty"`
	Triggers        DebTriggers  `yaml:"triggers,omitempty"`
	Breaks          []string     `yaml:"breaks,omitempty"`
	VersionMetadata string       `yaml:"metadata,omitempty"` // Deprecated: Moved to Info
	Signature       DebSignature `yaml:"signature,omitempty"`
}

type DebSignature struct {
	// PGP secret key, can be ASCII-armored
	KeyFile       string `yaml:"key_file,omitempty"`
	KeyPassphrase string `yaml:"-"` // populated from environment variable
	// origin, maint or archive (defaults to origin)
	Type string `yaml:"type,omitempty"`
}

// DebTriggers contains triggers only available for deb packages.
// https://wiki.debian.org/DpkgTriggers
// https://man7.org/linux/man-pages/man5/deb-triggers.5.html
type DebTriggers struct {
	Interest        []string `yaml:"interest,omitempty"`
	InterestAwait   []string `yaml:"interest_await,omitempty"`
	InterestNoAwait []string `yaml:"interest_noawait,omitempty"`
	Activate        []string `yaml:"activate,omitempty"`
	ActivateAwait   []string `yaml:"activate_await,omitempty"`
	ActivateNoAwait []string `yaml:"activate_noawait,omitempty"`
}

// DebScripts is scripts only available on deb packages.
type DebScripts struct {
	Rules     string `yaml:"rules,omitempty"`
	Templates string `yaml:"templates,omitempty"`
}

// Scripts contains information about maintainer scripts for packages.
type Scripts struct {
	PreInstall  string `yaml:"preinstall,omitempty"`
	PostInstall string `yaml:"postinstall,omitempty"`
	PreRemove   string `yaml:"preremove,omitempty"`
	PostRemove  string `yaml:"postremove,omitempty"`
}

// ErrFieldEmpty happens when some required field is empty.
type ErrFieldEmpty struct {
	field string
}

func (e ErrFieldEmpty) Error() string {
	return fmt.Sprintf("package %s must be provided", e.field)
}

// Validate the given Info and returns an error if it is invalid.
func Validate(info *Info) error {
	if info.Name == "" {
		return ErrFieldEmpty{"name"}
	}
	if info.Arch == "" {
		return ErrFieldEmpty{"arch"}
	}
	if info.Version == "" {
		return ErrFieldEmpty{"version"}
	}

	// deprecation warnings
	if info.Deb.VersionMetadata != "" {
		fmt.Fprintln(os.Stderr,
			"Warning: deb.metadata is deprecated and will be removed in a future version "+
				"(moved to version_metadata)")
	}

	if info.Bindir != "" {
		fmt.Fprintln(os.Stderr, "Warning: bindir is deprecated and will be removed in a future version")
	}

	return nil
}

// WithDefaults set some sane defaults into the given Info.
func WithDefaults(info *Info) *Info {
	if info.Platform == "" {
		info.Platform = "linux"
	}
	if info.Description == "" {
		info.Description = "no description given"
	}

	// parse the version as a semver so we can properly split the parts
	// and support proper ordering for both rpm and deb
	if v, err := semver.NewVersion(info.Version); err == nil {
		info.Version = fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch())
		if info.Prerelease == "" {
			info.Prerelease = v.Prerelease()
		}

		if info.VersionMetadata == "" {
			info.VersionMetadata = v.Metadata()
		}
	}

	return info
}

// GetChangeLog parses the provided changelog file.
func (info *Info) GetChangeLog() (log *chglog.PackageChangeLog, err error) {
	// if the file does not exist chglog.Parse will just silently
	// create an empty changelog but we should notify the user instead
	if _, err = os.Stat(info.Changelog); os.IsNotExist(err) {
		return nil, err
	}

	entries, err := chglog.Parse(info.Changelog)
	if err != nil {
		return nil, err
	}

	return &chglog.PackageChangeLog{
		Name:    info.Name,
		Entries: entries,
	}, nil
}

// ErrSigningFailure is returned whenever something went wrong during
// the package signing process. The underlying error can be unwrapped
// and could be crypto-related or something that occurred while adding
// the signature to the package.
type ErrSigningFailure struct {
	Err error
}

func (s *ErrSigningFailure) Error() string {
	return fmt.Sprintf("signing error: %v", s.Err)
}

func (s *ErrSigningFailure) Unwarp() error {
	return s.Err
}
