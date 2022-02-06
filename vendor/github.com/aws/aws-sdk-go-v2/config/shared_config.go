package config

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/ini"
	"github.com/aws/smithy-go/logging"
)

const (
	// Prefix to use for filtering profiles
	profilePrefix = `profile `

	// string equivalent for boolean
	endpointDiscoveryDisabled = `false`
	endpointDiscoveryEnabled  = `true`
	endpointDiscoveryAuto     = `auto`

	// Static Credentials group
	accessKeyIDKey  = `aws_access_key_id`     // group required
	secretAccessKey = `aws_secret_access_key` // group required
	sessionTokenKey = `aws_session_token`     // optional

	// Assume Role Credentials group
	roleArnKey             = `role_arn`          // group required
	sourceProfileKey       = `source_profile`    // group required
	credentialSourceKey    = `credential_source` // group required (or source_profile)
	externalIDKey          = `external_id`       // optional
	mfaSerialKey           = `mfa_serial`        // optional
	roleSessionNameKey     = `role_session_name` // optional
	roleDurationSecondsKey = "duration_seconds"  // optional

	// AWS Single Sign-On (AWS SSO) group
	ssoAccountIDKey = "sso_account_id"
	ssoRegionKey    = "sso_region"
	ssoRoleNameKey  = "sso_role_name"
	ssoStartURL     = "sso_start_url"

	// Additional Config fields
	regionKey = `region`

	// endpoint discovery group
	enableEndpointDiscoveryKey = `endpoint_discovery_enabled` // optional

	// External Credential process
	credentialProcessKey = `credential_process` // optional

	// Web Identity Token File
	webIdentityTokenFileKey = `web_identity_token_file` // optional

	// S3 ARN Region Usage
	s3UseARNRegionKey = "s3_use_arn_region"

	ec2MetadataServiceEndpointModeKey = "ec2_metadata_service_endpoint_mode"

	ec2MetadataServiceEndpointKey = "ec2_metadata_service_endpoint"

	// Use DualStack Endpoint Resolution
	useDualStackEndpoint = "use_dualstack_endpoint"

	// DefaultSharedConfigProfile is the default profile to be used when
	// loading configuration from the config files if another profile name
	// is not provided.
	DefaultSharedConfigProfile = `default`

	// S3 Disable Multi-Region AccessPoints
	s3DisableMultiRegionAccessPointsKey = `s3_disable_multiregion_access_points`

	useFIPSEndpointKey = "use_fips_endpoint"
)

// defaultSharedConfigProfile allows for swapping the default profile for testing
var defaultSharedConfigProfile = DefaultSharedConfigProfile

// DefaultSharedCredentialsFilename returns the SDK's default file path
// for the shared credentials file.
//
// Builds the shared config file path based on the OS's platform.
//
//   - Linux/Unix: $HOME/.aws/credentials
//   - Windows: %USERPROFILE%\.aws\credentials
func DefaultSharedCredentialsFilename() string {
	return filepath.Join(userHomeDir(), ".aws", "credentials")
}

// DefaultSharedConfigFilename returns the SDK's default file path for
// the shared config file.
//
// Builds the shared config file path based on the OS's platform.
//
//   - Linux/Unix: $HOME/.aws/config
//   - Windows: %USERPROFILE%\.aws\config
func DefaultSharedConfigFilename() string {
	return filepath.Join(userHomeDir(), ".aws", "config")
}

// DefaultSharedConfigFiles is a slice of the default shared config files that
// the will be used in order to load the SharedConfig.
var DefaultSharedConfigFiles = []string{
	DefaultSharedConfigFilename(),
}

// DefaultSharedCredentialsFiles is a slice of the default shared credentials files that
// the will be used in order to load the SharedConfig.
var DefaultSharedCredentialsFiles = []string{
	DefaultSharedCredentialsFilename(),
}

// SharedConfig represents the configuration fields of the SDK config files.
type SharedConfig struct {
	Profile string

	// Credentials values from the config file. Both aws_access_key_id
	// and aws_secret_access_key must be provided together in the same file
	// to be considered valid. The values will be ignored if not a complete group.
	// aws_session_token is an optional field that can be provided if both of the
	// other two fields are also provided.
	//
	//	aws_access_key_id
	//	aws_secret_access_key
	//	aws_session_token
	Credentials aws.Credentials

	CredentialSource     string
	CredentialProcess    string
	WebIdentityTokenFile string

	SSOAccountID string
	SSORegion    string
	SSORoleName  string
	SSOStartURL  string

	RoleARN             string
	ExternalID          string
	MFASerial           string
	RoleSessionName     string
	RoleDurationSeconds *time.Duration

	SourceProfileName string
	Source            *SharedConfig

	// Region is the region the SDK should use for looking up AWS service endpoints
	// and signing requests.
	//
	//	region = us-west-2
	Region string

	// EnableEndpointDiscovery can be enabled or disabled in the shared config
	// by setting endpoint_discovery_enabled to true, or false respectively.
	//
	//	endpoint_discovery_enabled = true
	EnableEndpointDiscovery aws.EndpointDiscoveryEnableState

	// Specifies if the S3 service should allow ARNs to direct the region
	// the client's requests are sent to.
	//
	// s3_use_arn_region=true
	S3UseARNRegion *bool

	// Specifies the EC2 Instance Metadata Service default endpoint selection mode (IPv4 or IPv6)
	//
	// ec2_metadata_service_endpoint_mode=IPv6
	EC2IMDSEndpointMode imds.EndpointModeState

	// Specifies the EC2 Instance Metadata Service endpoint to use. If specified it overrides EC2IMDSEndpointMode.
	//
	// ec2_metadata_service_endpoint=http://fd00:ec2::254
	EC2IMDSEndpoint string

	// Specifies if the S3 service should disable support for Multi-Region
	// access-points
	//
	// s3_disable_multiregion_access_points=true
	S3DisableMultiRegionAccessPoints *bool

	// Specifies that SDK clients must resolve a dual-stack endpoint for
	// services.
	//
	// use_dualstack_endpoint=true
	UseDualStackEndpoint aws.DualStackEndpointState

	// Specifies that SDK clients must resolve a FIPS endpoint for
	// services.
	//
	// use_fips_endpoint=true
	UseFIPSEndpoint aws.FIPSEndpointState
}

// GetS3UseARNRegion returns if the S3 service should allow ARNs to direct the region
// the client's requests are sent to.
func (c SharedConfig) GetS3UseARNRegion(ctx context.Context) (value, ok bool, err error) {
	if c.S3UseARNRegion == nil {
		return false, false, nil
	}

	return *c.S3UseARNRegion, true, nil
}

// GetEnableEndpointDiscovery returns if the enable_endpoint_discovery is set.
func (c SharedConfig) GetEnableEndpointDiscovery(ctx context.Context) (value aws.EndpointDiscoveryEnableState, ok bool, err error) {
	if c.EnableEndpointDiscovery == aws.EndpointDiscoveryUnset {
		return aws.EndpointDiscoveryUnset, false, nil
	}

	return c.EnableEndpointDiscovery, true, nil
}

// GetS3DisableMultiRegionAccessPoints returns if the S3 service should disable support for Multi-Region
// access-points.
func (c SharedConfig) GetS3DisableMultiRegionAccessPoints(ctx context.Context) (value, ok bool, err error) {
	if c.S3DisableMultiRegionAccessPoints == nil {
		return false, false, nil
	}

	return *c.S3DisableMultiRegionAccessPoints, true, nil
}

// GetRegion returns the region for the profile if a region is set.
func (c SharedConfig) getRegion(ctx context.Context) (string, bool, error) {
	if len(c.Region) == 0 {
		return "", false, nil
	}
	return c.Region, true, nil
}

// GetCredentialsProvider returns the credentials for a profile if they were set.
func (c SharedConfig) getCredentialsProvider() (aws.Credentials, bool, error) {
	return c.Credentials, true, nil
}

// GetEC2IMDSEndpointMode implements a EC2IMDSEndpointMode option resolver interface.
func (c SharedConfig) GetEC2IMDSEndpointMode() (imds.EndpointModeState, bool, error) {
	if c.EC2IMDSEndpointMode == imds.EndpointModeStateUnset {
		return imds.EndpointModeStateUnset, false, nil
	}

	return c.EC2IMDSEndpointMode, true, nil
}

// GetEC2IMDSEndpoint implements a EC2IMDSEndpoint option resolver interface.
func (c SharedConfig) GetEC2IMDSEndpoint() (string, bool, error) {
	if len(c.EC2IMDSEndpoint) == 0 {
		return "", false, nil
	}

	return c.EC2IMDSEndpoint, true, nil
}

// GetUseDualStackEndpoint returns whether the service's dual-stack endpoint should be
// used for requests.
func (c SharedConfig) GetUseDualStackEndpoint(ctx context.Context) (value aws.DualStackEndpointState, found bool, err error) {
	if c.UseDualStackEndpoint == aws.DualStackEndpointStateUnset {
		return aws.DualStackEndpointStateUnset, false, nil
	}

	return c.UseDualStackEndpoint, true, nil
}

// GetUseFIPSEndpoint returns whether the service's FIPS endpoint should be
// used for requests.
func (c SharedConfig) GetUseFIPSEndpoint(ctx context.Context) (value aws.FIPSEndpointState, found bool, err error) {
	if c.UseFIPSEndpoint == aws.FIPSEndpointStateUnset {
		return aws.FIPSEndpointStateUnset, false, nil
	}

	return c.UseFIPSEndpoint, true, nil
}

// loadSharedConfigIgnoreNotExist is an alias for loadSharedConfig with the
// addition of ignoring when none of the files exist or when the profile
// is not found in any of the files.
func loadSharedConfigIgnoreNotExist(ctx context.Context, configs configs) (Config, error) {
	cfg, err := loadSharedConfig(ctx, configs)
	if err != nil {
		if _, ok := err.(SharedConfigProfileNotExistError); ok {
			return SharedConfig{}, nil
		}
		return nil, err
	}

	return cfg, nil
}

// loadSharedConfig uses the configs passed in to load the SharedConfig from file
// The file names and profile name are sourced from the configs.
//
// If profile name is not provided DefaultSharedConfigProfile (default) will
// be used.
//
// If shared config filenames are not provided DefaultSharedConfigFiles will
// be used.
//
// Config providers used:
// * sharedConfigProfileProvider
// * sharedConfigFilesProvider
func loadSharedConfig(ctx context.Context, configs configs) (Config, error) {
	var profile string
	var configFiles []string
	var credentialsFiles []string
	var ok bool
	var err error

	profile, ok, err = getSharedConfigProfile(ctx, configs)
	if err != nil {
		return nil, err
	}
	if !ok {
		profile = defaultSharedConfigProfile
	}

	configFiles, ok, err = getSharedConfigFiles(ctx, configs)
	if err != nil {
		return nil, err
	}

	credentialsFiles, ok, err = getSharedCredentialsFiles(ctx, configs)
	if err != nil {
		return nil, err
	}

	// setup logger if log configuration warning is seti
	var logger logging.Logger
	logWarnings, found, err := getLogConfigurationWarnings(ctx, configs)
	if err != nil {
		return SharedConfig{}, err
	}
	if found && logWarnings {
		logger, found, err = getLogger(ctx, configs)
		if err != nil {
			return SharedConfig{}, err
		}
		if !found {
			logger = logging.NewStandardLogger(os.Stderr)
		}
	}

	return LoadSharedConfigProfile(ctx, profile,
		func(o *LoadSharedConfigOptions) {
			o.Logger = logger
			o.ConfigFiles = configFiles
			o.CredentialsFiles = credentialsFiles
		},
	)
}

// LoadSharedConfigOptions struct contains optional values that can be used to load the config.
type LoadSharedConfigOptions struct {

	// CredentialsFiles are the shared credentials files
	CredentialsFiles []string

	// ConfigFiles are the shared config files
	ConfigFiles []string

	// Logger is the logger used to log shared config behavior
	Logger logging.Logger
}

// LoadSharedConfigProfile retrieves the configuration from the list of files
// using the profile provided. The order the files are listed will determine
// precedence. Values in subsequent files will overwrite values defined in
// earlier files.
//
// For example, given two files A and B. Both define credentials. If the order
// of the files are A then B, B's credential values will be used instead of A's.
//
// If config files are not set, SDK will default to using a file at location `.aws/config` if present.
// If credentials files are not set, SDK will default to using a file at location `.aws/credentials` if present.
// No default files are set, if files set to an empty slice.
//
// You can read more about shared config and credentials file location at
// https://docs.aws.amazon.com/credref/latest/refdocs/file-location.html#file-location
//
func LoadSharedConfigProfile(ctx context.Context, profile string, optFns ...func(*LoadSharedConfigOptions)) (SharedConfig, error) {
	var option LoadSharedConfigOptions
	for _, fn := range optFns {
		fn(&option)
	}

	if option.ConfigFiles == nil {
		option.ConfigFiles = DefaultSharedConfigFiles
	}

	if option.CredentialsFiles == nil {
		option.CredentialsFiles = DefaultSharedCredentialsFiles
	}

	// load shared configuration sections from shared configuration INI options
	configSections, err := loadIniFiles(option.ConfigFiles)
	if err != nil {
		return SharedConfig{}, err
	}

	// check for profile prefix and drop duplicates or invalid profiles
	err = processConfigSections(ctx, configSections, option.Logger)
	if err != nil {
		return SharedConfig{}, err
	}

	// load shared credentials sections from shared credentials INI options
	credentialsSections, err := loadIniFiles(option.CredentialsFiles)
	if err != nil {
		return SharedConfig{}, err
	}

	// check for profile prefix and drop duplicates or invalid profiles
	err = processCredentialsSections(ctx, credentialsSections, option.Logger)
	if err != nil {
		return SharedConfig{}, err
	}

	err = mergeSections(configSections, credentialsSections)
	if err != nil {
		return SharedConfig{}, err
	}

	cfg := SharedConfig{}
	profiles := map[string]struct{}{}
	if err = cfg.setFromIniSections(profiles, profile, configSections, option.Logger); err != nil {
		return SharedConfig{}, err
	}

	return cfg, nil
}

func processConfigSections(ctx context.Context, sections ini.Sections, logger logging.Logger) error {
	for _, section := range sections.List() {
		// drop profiles without prefix for config files
		if !strings.HasPrefix(section, profilePrefix) && !strings.EqualFold(section, "default") {
			// drop this section, as invalid profile name
			sections.DeleteSection(section)

			if logger != nil {
				logger.Logf(logging.Debug,
					"A profile defined with name `%v` is ignored. For use within a shared configuration file, "+
						"a non-default profile must have `profile ` prefixed to the profile name.\n",
					section,
				)
			}
		}
	}

	// rename sections to remove `profile ` prefixing to match with credentials file.
	// if default is already present, it will be dropped.
	for _, section := range sections.List() {
		if strings.HasPrefix(section, profilePrefix) {
			v, ok := sections.GetSection(section)
			if !ok {
				return fmt.Errorf("error processing profiles within the shared configuration files")
			}

			// delete section with profile as prefix
			sections.DeleteSection(section)

			// set the value to non-prefixed name in sections.
			section = strings.TrimPrefix(section, profilePrefix)
			if sections.HasSection(section) {
				oldSection, _ := sections.GetSection(section)
				v.Logs = append(v.Logs,
					fmt.Sprintf("A default profile prefixed with `profile ` found in %s, "+
						"overrided non-prefixed default profile from %s", v.SourceFile, oldSection.SourceFile))
			}

			// assign non-prefixed name to section
			v.Name = section
			sections.SetSection(section, v)
		}
	}
	return nil
}

func processCredentialsSections(ctx context.Context, sections ini.Sections, logger logging.Logger) error {
	for _, section := range sections.List() {
		// drop profiles with prefix for credential files
		if strings.HasPrefix(section, profilePrefix) {
			// drop this section, as invalid profile name
			sections.DeleteSection(section)

			if logger != nil {
				logger.Logf(logging.Debug,
					"The profile defined with name `%v` is ignored. A profile with the `profile ` prefix is invalid "+
						"for the shared credentials file.\n",
					section,
				)
			}
		}
	}
	return nil
}

func loadIniFiles(filenames []string) (ini.Sections, error) {
	mergedSections := ini.NewSections()

	for _, filename := range filenames {
		sections, err := ini.OpenFile(filename)
		var v *ini.UnableToReadFile
		if ok := errors.As(err, &v); ok {
			// Skip files which can't be opened and read for whatever reason.
			// We treat such files as empty, and do not fall back to other locations.
			continue
		} else if err != nil {
			return ini.Sections{}, SharedConfigLoadError{Filename: filename, Err: err}
		}

		// mergeSections into mergedSections
		err = mergeSections(mergedSections, sections)
		if err != nil {
			return ini.Sections{}, SharedConfigLoadError{Filename: filename, Err: err}
		}
	}

	return mergedSections, nil
}

// mergeSections merges source section properties into destination section properties
func mergeSections(dst, src ini.Sections) error {
	for _, sectionName := range src.List() {
		srcSection, _ := src.GetSection(sectionName)

		if (!srcSection.Has(accessKeyIDKey) && srcSection.Has(secretAccessKey)) ||
			(srcSection.Has(accessKeyIDKey) && !srcSection.Has(secretAccessKey)) {
			srcSection.Errors = append(srcSection.Errors,
				fmt.Errorf("partial credentials found for profile %v", sectionName))
		}

		if !dst.HasSection(sectionName) {
			dst.SetSection(sectionName, srcSection)
			continue
		}

		// merge with destination srcSection
		dstSection, _ := dst.GetSection(sectionName)

		// errors should be overriden if any
		dstSection.Errors = srcSection.Errors

		// Access key id update
		if srcSection.Has(accessKeyIDKey) && srcSection.Has(secretAccessKey) {
			accessKey := srcSection.String(accessKeyIDKey)
			secretKey := srcSection.String(secretAccessKey)

			if dstSection.Has(accessKeyIDKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding credentials value for aws access key id, "+
						"and aws secret access key, defined in %v, with values found in a duplicate profile "+
						"defined at file %v. \n",
						sectionName, dstSection.SourceFile[accessKeyIDKey],
						srcSection.SourceFile[accessKeyIDKey]))
			}

			// update access key
			v, err := ini.NewStringValue(accessKey)
			if err != nil {
				return fmt.Errorf("error merging access key, %w", err)
			}
			dstSection.UpdateValue(accessKeyIDKey, v)

			// update secret key
			v, err = ini.NewStringValue(secretKey)
			if err != nil {
				return fmt.Errorf("error merging secret key, %w", err)
			}
			dstSection.UpdateValue(secretAccessKey, v)

			// update session token
			if srcSection.Has(sessionTokenKey) {
				sessionKey := srcSection.String(sessionTokenKey)

				val, e := ini.NewStringValue(sessionKey)
				if e != nil {
					return fmt.Errorf("error merging session key, %w", e)
				}

				if dstSection.Has(sessionTokenKey) {
					dstSection.Logs = append(dstSection.Logs,
						fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
							"with a %v value found in a duplicate profile defined at file %v. \n",
							sectionName, sessionTokenKey, dstSection.SourceFile[sessionTokenKey],
							sessionTokenKey, srcSection.SourceFile[sessionTokenKey]))
				}

				dstSection.UpdateValue(sessionTokenKey, val)
				dstSection.UpdateSourceFile(sessionTokenKey, srcSection.SourceFile[sessionTokenKey])
			}

			// update source file to reflect where the static creds came from
			dstSection.UpdateSourceFile(accessKeyIDKey, srcSection.SourceFile[accessKeyIDKey])
			dstSection.UpdateSourceFile(secretAccessKey, srcSection.SourceFile[secretAccessKey])
		}

		if srcSection.Has(roleArnKey) {
			key := srcSection.String(roleArnKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging roleArnKey, %w", err)
			}

			if dstSection.Has(roleArnKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, roleArnKey, dstSection.SourceFile[roleArnKey],
						roleArnKey, srcSection.SourceFile[roleArnKey]))
			}

			dstSection.UpdateValue(roleArnKey, val)
			dstSection.UpdateSourceFile(roleArnKey, srcSection.SourceFile[roleArnKey])
		}

		if srcSection.Has(sourceProfileKey) {
			key := srcSection.String(sourceProfileKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging sourceProfileKey, %w", err)
			}

			if dstSection.Has(sourceProfileKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, sourceProfileKey, dstSection.SourceFile[sourceProfileKey],
						sourceProfileKey, srcSection.SourceFile[sourceProfileKey]))
			}

			dstSection.UpdateValue(sourceProfileKey, val)
			dstSection.UpdateSourceFile(sourceProfileKey, srcSection.SourceFile[sourceProfileKey])
		}

		if srcSection.Has(credentialSourceKey) {
			key := srcSection.String(credentialSourceKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging credentialSourceKey, %w", err)
			}

			if dstSection.Has(credentialSourceKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, credentialSourceKey, dstSection.SourceFile[credentialSourceKey],
						credentialSourceKey, srcSection.SourceFile[credentialSourceKey]))
			}

			dstSection.UpdateValue(credentialSourceKey, val)
			dstSection.UpdateSourceFile(credentialSourceKey, srcSection.SourceFile[credentialSourceKey])
		}

		if srcSection.Has(externalIDKey) {
			key := srcSection.String(externalIDKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging externalIDKey, %w", err)
			}

			if dstSection.Has(externalIDKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, externalIDKey, dstSection.SourceFile[externalIDKey],
						externalIDKey, srcSection.SourceFile[externalIDKey]))
			}

			dstSection.UpdateValue(externalIDKey, val)
			dstSection.UpdateSourceFile(externalIDKey, srcSection.SourceFile[externalIDKey])
		}

		if srcSection.Has(mfaSerialKey) {
			key := srcSection.String(mfaSerialKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging mfaSerialKey, %w", err)
			}

			if dstSection.Has(mfaSerialKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, mfaSerialKey, dstSection.SourceFile[mfaSerialKey],
						mfaSerialKey, srcSection.SourceFile[mfaSerialKey]))
			}

			dstSection.UpdateValue(mfaSerialKey, val)
			dstSection.UpdateSourceFile(mfaSerialKey, srcSection.SourceFile[mfaSerialKey])
		}

		if srcSection.Has(roleSessionNameKey) {
			key := srcSection.String(roleSessionNameKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging roleSessionNameKey, %w", err)
			}

			if dstSection.Has(roleSessionNameKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, roleSessionNameKey, dstSection.SourceFile[roleSessionNameKey],
						roleSessionNameKey, srcSection.SourceFile[roleSessionNameKey]))
			}

			dstSection.UpdateValue(roleSessionNameKey, val)
			dstSection.UpdateSourceFile(roleSessionNameKey, srcSection.SourceFile[roleSessionNameKey])
		}

		// role duration seconds key update
		if srcSection.Has(roleDurationSecondsKey) {
			roleDurationSeconds := srcSection.Int(roleDurationSecondsKey)
			v, err := ini.NewIntValue(roleDurationSeconds)
			if err != nil {
				return fmt.Errorf("error merging role duration seconds key, %w", err)
			}
			dstSection.UpdateValue(roleDurationSecondsKey, v)

			dstSection.UpdateSourceFile(roleDurationSecondsKey, srcSection.SourceFile[roleDurationSecondsKey])
		}

		if srcSection.Has(regionKey) {
			key := srcSection.String(regionKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging regionKey, %w", err)
			}

			if dstSection.Has(regionKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, regionKey, dstSection.SourceFile[regionKey],
						regionKey, srcSection.SourceFile[regionKey]))
			}

			dstSection.UpdateValue(regionKey, val)
			dstSection.UpdateSourceFile(regionKey, srcSection.SourceFile[regionKey])
		}

		if srcSection.Has(enableEndpointDiscoveryKey) {
			key := srcSection.String(enableEndpointDiscoveryKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging enableEndpointDiscoveryKey, %w", err)
			}

			if dstSection.Has(enableEndpointDiscoveryKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, enableEndpointDiscoveryKey, dstSection.SourceFile[enableEndpointDiscoveryKey],
						enableEndpointDiscoveryKey, srcSection.SourceFile[enableEndpointDiscoveryKey]))
			}

			dstSection.UpdateValue(enableEndpointDiscoveryKey, val)
			dstSection.UpdateSourceFile(enableEndpointDiscoveryKey, srcSection.SourceFile[enableEndpointDiscoveryKey])
		}

		if srcSection.Has(credentialProcessKey) {
			key := srcSection.String(credentialProcessKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging credentialProcessKey, %w", err)
			}

			if dstSection.Has(credentialProcessKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, credentialProcessKey, dstSection.SourceFile[credentialProcessKey],
						credentialProcessKey, srcSection.SourceFile[credentialProcessKey]))
			}

			dstSection.UpdateValue(credentialProcessKey, val)
			dstSection.UpdateSourceFile(credentialProcessKey, srcSection.SourceFile[credentialProcessKey])
		}

		if srcSection.Has(webIdentityTokenFileKey) {
			key := srcSection.String(webIdentityTokenFileKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging webIdentityTokenFileKey, %w", err)
			}

			if dstSection.Has(webIdentityTokenFileKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, webIdentityTokenFileKey, dstSection.SourceFile[webIdentityTokenFileKey],
						webIdentityTokenFileKey, srcSection.SourceFile[webIdentityTokenFileKey]))
			}

			dstSection.UpdateValue(webIdentityTokenFileKey, val)
			dstSection.UpdateSourceFile(webIdentityTokenFileKey, srcSection.SourceFile[webIdentityTokenFileKey])
		}

		if srcSection.Has(s3UseARNRegionKey) {
			key := srcSection.String(s3UseARNRegionKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging s3UseARNRegionKey, %w", err)
			}

			if dstSection.Has(s3UseARNRegionKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, s3UseARNRegionKey, dstSection.SourceFile[s3UseARNRegionKey],
						s3UseARNRegionKey, srcSection.SourceFile[s3UseARNRegionKey]))
			}

			dstSection.UpdateValue(s3UseARNRegionKey, val)
			dstSection.UpdateSourceFile(s3UseARNRegionKey, srcSection.SourceFile[s3UseARNRegionKey])
		}

		if srcSection.Has(s3DisableMultiRegionAccessPointsKey) {
			key := srcSection.String(s3DisableMultiRegionAccessPointsKey)
			val, err := ini.NewStringValue(key)
			if err != nil {
				return fmt.Errorf("error merging s3DisableMultiRegionAccessPointsKey, %w", err)
			}

			if dstSection.Has(s3DisableMultiRegionAccessPointsKey) {
				dstSection.Logs = append(dstSection.Logs,
					fmt.Sprintf("For profile: %v, overriding %v value, defined in %v "+
						"with a %v value found in a duplicate profile defined at file %v. \n",
						sectionName, s3DisableMultiRegionAccessPointsKey, dstSection.SourceFile[s3DisableMultiRegionAccessPointsKey],
						s3DisableMultiRegionAccessPointsKey, srcSection.SourceFile[s3DisableMultiRegionAccessPointsKey]))
			}

			dstSection.UpdateValue(s3DisableMultiRegionAccessPointsKey, val)
			dstSection.UpdateSourceFile(s3DisableMultiRegionAccessPointsKey, srcSection.SourceFile[s3DisableMultiRegionAccessPointsKey])
		}

		// set srcSection on dst srcSection
		dst = dst.SetSection(sectionName, dstSection)
	}

	return nil
}

// Returns an error if all of the files fail to load. If at least one file is
// successfully loaded and contains the profile, no error will be returned.
func (c *SharedConfig) setFromIniSections(profiles map[string]struct{}, profile string,
	sections ini.Sections, logger logging.Logger) error {
	c.Profile = profile

	section, ok := sections.GetSection(profile)
	if !ok {
		return SharedConfigProfileNotExistError{
			Profile: profile,
		}
	}

	// if logs are appended to the section, log them
	if section.Logs != nil && logger != nil {
		for _, log := range section.Logs {
			logger.Logf(logging.Debug, log)
		}
	}

	// set config from the provided ini section
	err := c.setFromIniSection(profile, section)
	if err != nil {
		return fmt.Errorf("error fetching config from profile, %v, %w", profile, err)
	}

	if _, ok := profiles[profile]; ok {
		// if this is the second instance of the profile the Assume Role
		// options must be cleared because they are only valid for the
		// first reference of a profile. The self linked instance of the
		// profile only have credential provider options.
		c.clearAssumeRoleOptions()
	} else {
		// First time a profile has been seen, It must either be a assume role
		// credentials, or SSO. Assert if the credential type requires a role ARN,
		// the ARN is also set, or validate that the SSO configuration is complete.
		if err := c.validateCredentialsConfig(profile); err != nil {
			return err
		}
	}

	// if not top level profile and has credentials, return with credentials.
	if len(profiles) != 0 && c.Credentials.HasKeys() {
		return nil
	}

	profiles[profile] = struct{}{}

	// validate no colliding credentials type are present
	if err := c.validateCredentialType(); err != nil {
		return err
	}

	// Link source profiles for assume roles
	if len(c.SourceProfileName) != 0 {
		// Linked profile via source_profile ignore credential provider
		// options, the source profile must provide the credentials.
		c.clearCredentialOptions()

		srcCfg := &SharedConfig{}
		err := srcCfg.setFromIniSections(profiles, c.SourceProfileName, sections, logger)
		if err != nil {
			// SourceProfileName that doesn't exist is an error in configuration.
			if _, ok := err.(SharedConfigProfileNotExistError); ok {
				err = SharedConfigAssumeRoleError{
					RoleARN: c.RoleARN,
					Profile: c.SourceProfileName,
					Err:     err,
				}
			}
			return err
		}

		if !srcCfg.hasCredentials() {
			return SharedConfigAssumeRoleError{
				RoleARN: c.RoleARN,
				Profile: c.SourceProfileName,
			}
		}

		c.Source = srcCfg
	}

	return nil
}

// setFromIniSection loads the configuration from the profile section defined in
// the provided ini file. A SharedConfig pointer type value is used so that
// multiple config file loadings can be chained.
//
// Only loads complete logically grouped values, and will not set fields in cfg
// for incomplete grouped values in the config. Such as credentials. For example
// if a config file only includes aws_access_key_id but no aws_secret_access_key
// the aws_access_key_id will be ignored.
func (c *SharedConfig) setFromIniSection(profile string, section ini.Section) error {
	if len(section.Name) == 0 {
		sources := make([]string, 0)
		for _, v := range section.SourceFile {
			sources = append(sources, v)
		}

		return fmt.Errorf("parsing error : could not find profile section name after processing files: %v", sources)
	}

	if len(section.Errors) != 0 {
		var errStatement string
		for i, e := range section.Errors {
			errStatement = fmt.Sprintf("%d, %v\n", i+1, e.Error())
		}
		return fmt.Errorf("Error using profile: \n %v", errStatement)
	}

	// Assume Role
	updateString(&c.RoleARN, section, roleArnKey)
	updateString(&c.ExternalID, section, externalIDKey)
	updateString(&c.MFASerial, section, mfaSerialKey)
	updateString(&c.RoleSessionName, section, roleSessionNameKey)
	updateString(&c.SourceProfileName, section, sourceProfileKey)
	updateString(&c.CredentialSource, section, credentialSourceKey)
	updateString(&c.Region, section, regionKey)

	// AWS Single Sign-On (AWS SSO)
	updateString(&c.SSOAccountID, section, ssoAccountIDKey)
	updateString(&c.SSORegion, section, ssoRegionKey)
	updateString(&c.SSORoleName, section, ssoRoleNameKey)
	updateString(&c.SSOStartURL, section, ssoStartURL)

	if section.Has(roleDurationSecondsKey) {
		d := time.Duration(section.Int(roleDurationSecondsKey)) * time.Second
		c.RoleDurationSeconds = &d
	}

	updateString(&c.CredentialProcess, section, credentialProcessKey)
	updateString(&c.WebIdentityTokenFile, section, webIdentityTokenFileKey)

	updateEndpointDiscoveryType(&c.EnableEndpointDiscovery, section, enableEndpointDiscoveryKey)
	updateBoolPtr(&c.S3UseARNRegion, section, s3UseARNRegionKey)
	updateBoolPtr(&c.S3DisableMultiRegionAccessPoints, section, s3DisableMultiRegionAccessPointsKey)

	if err := updateEC2MetadataServiceEndpointMode(&c.EC2IMDSEndpointMode, section, ec2MetadataServiceEndpointModeKey); err != nil {
		return fmt.Errorf("failed to load %s from shared config, %v", ec2MetadataServiceEndpointModeKey, err)
	}
	updateString(&c.EC2IMDSEndpoint, section, ec2MetadataServiceEndpointKey)

	updateUseDualStackEndpoint(&c.UseDualStackEndpoint, section, useDualStackEndpoint)
	updateUseFIPSEndpoint(&c.UseFIPSEndpoint, section, useFIPSEndpointKey)

	// Shared Credentials
	creds := aws.Credentials{
		AccessKeyID:     section.String(accessKeyIDKey),
		SecretAccessKey: section.String(secretAccessKey),
		SessionToken:    section.String(sessionTokenKey),
		Source:          fmt.Sprintf("SharedConfigCredentials: %s", section.SourceFile[accessKeyIDKey]),
	}

	if creds.HasKeys() {
		c.Credentials = creds
	}

	return nil
}

func updateEC2MetadataServiceEndpointMode(endpointMode *imds.EndpointModeState, section ini.Section, key string) error {
	if !section.Has(key) {
		return nil
	}
	value := section.String(key)
	return endpointMode.SetFromString(value)
}

func (c *SharedConfig) validateCredentialsConfig(profile string) error {
	if err := c.validateCredentialsRequireARN(profile); err != nil {
		return err
	}

	return nil
}

func (c *SharedConfig) validateCredentialsRequireARN(profile string) error {
	var credSource string

	switch {
	case len(c.SourceProfileName) != 0:
		credSource = sourceProfileKey
	case len(c.CredentialSource) != 0:
		credSource = credentialSourceKey
	case len(c.WebIdentityTokenFile) != 0:
		credSource = webIdentityTokenFileKey
	}

	if len(credSource) != 0 && len(c.RoleARN) == 0 {
		return CredentialRequiresARNError{
			Type:    credSource,
			Profile: profile,
		}
	}

	return nil
}

func (c *SharedConfig) validateCredentialType() error {
	// Only one or no credential type can be defined.
	if !oneOrNone(
		len(c.SourceProfileName) != 0,
		len(c.CredentialSource) != 0,
		len(c.CredentialProcess) != 0,
		len(c.WebIdentityTokenFile) != 0,
	) {
		return fmt.Errorf("only one credential type may be specified per profile: source profile, credential source, credential process, web identity token, or sso")
	}

	return nil
}

func (c *SharedConfig) validateSSOConfiguration() error {
	if !c.hasSSOConfiguration() {
		return nil
	}

	var missing []string
	if len(c.SSOAccountID) == 0 {
		missing = append(missing, ssoAccountIDKey)
	}

	if len(c.SSORegion) == 0 {
		missing = append(missing, ssoRegionKey)
	}

	if len(c.SSORoleName) == 0 {
		missing = append(missing, ssoRoleNameKey)
	}

	if len(c.SSOStartURL) == 0 {
		missing = append(missing, ssoStartURL)
	}

	if len(missing) > 0 {
		return fmt.Errorf("profile %q is configured to use SSO but is missing required configuration: %s",
			c.Profile, strings.Join(missing, ", "))
	}

	return nil
}

func (c *SharedConfig) hasCredentials() bool {
	switch {
	case len(c.SourceProfileName) != 0:
	case len(c.CredentialSource) != 0:
	case len(c.CredentialProcess) != 0:
	case len(c.WebIdentityTokenFile) != 0:
	case c.hasSSOConfiguration():
	case c.Credentials.HasKeys():
	default:
		return false
	}

	return true
}

func (c *SharedConfig) hasSSOConfiguration() bool {
	switch {
	case len(c.SSOAccountID) != 0:
	case len(c.SSORegion) != 0:
	case len(c.SSORoleName) != 0:
	case len(c.SSOStartURL) != 0:
	default:
		return false
	}
	return true
}

func (c *SharedConfig) clearAssumeRoleOptions() {
	c.RoleARN = ""
	c.ExternalID = ""
	c.MFASerial = ""
	c.RoleSessionName = ""
	c.SourceProfileName = ""
}

func (c *SharedConfig) clearCredentialOptions() {
	c.CredentialSource = ""
	c.CredentialProcess = ""
	c.WebIdentityTokenFile = ""
	c.Credentials = aws.Credentials{}
	c.SSOAccountID = ""
	c.SSORegion = ""
	c.SSORoleName = ""
	c.SSOStartURL = ""
}

// SharedConfigLoadError is an error for the shared config file failed to load.
type SharedConfigLoadError struct {
	Filename string
	Err      error
}

// Unwrap returns the underlying error that caused the failure.
func (e SharedConfigLoadError) Unwrap() error {
	return e.Err
}

func (e SharedConfigLoadError) Error() string {
	return fmt.Sprintf("failed to load shared config file, %s, %v", e.Filename, e.Err)
}

// SharedConfigProfileNotExistError is an error for the shared config when
// the profile was not find in the config file.
type SharedConfigProfileNotExistError struct {
	Filename []string
	Profile  string
	Err      error
}

// Unwrap returns the underlying error that caused the failure.
func (e SharedConfigProfileNotExistError) Unwrap() error {
	return e.Err
}

func (e SharedConfigProfileNotExistError) Error() string {
	return fmt.Sprintf("failed to get shared config profile, %s", e.Profile)
}

// SharedConfigAssumeRoleError is an error for the shared config when the
// profile contains assume role information, but that information is invalid
// or not complete.
type SharedConfigAssumeRoleError struct {
	Profile string
	RoleARN string
	Err     error
}

// Unwrap returns the underlying error that caused the failure.
func (e SharedConfigAssumeRoleError) Unwrap() error {
	return e.Err
}

func (e SharedConfigAssumeRoleError) Error() string {
	return fmt.Sprintf("failed to load assume role %s, of profile %s, %v",
		e.RoleARN, e.Profile, e.Err)
}

// CredentialRequiresARNError provides the error for shared config credentials
// that are incorrectly configured in the shared config or credentials file.
type CredentialRequiresARNError struct {
	// type of credentials that were configured.
	Type string

	// Profile name the credentials were in.
	Profile string
}

// Error satisfies the error interface.
func (e CredentialRequiresARNError) Error() string {
	return fmt.Sprintf(
		"credential type %s requires role_arn, profile %s",
		e.Type, e.Profile,
	)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return os.Getenv("USERPROFILE")
	}

	// *nix
	return os.Getenv("HOME")
}

func oneOrNone(bs ...bool) bool {
	var count int

	for _, b := range bs {
		if b {
			count++
			if count > 1 {
				return false
			}
		}
	}

	return true
}

// updateString will only update the dst with the value in the section key, key
// is present in the section.
func updateString(dst *string, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}
	*dst = section.String(key)
}

// updateBool will only update the dst with the value in the section key, key
// is present in the section.
func updateBool(dst *bool, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}
	*dst = section.Bool(key)
}

// updateBoolPtr will only update the dst with the value in the section key,
// key is present in the section.
func updateBoolPtr(dst **bool, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}
	*dst = new(bool)
	**dst = section.Bool(key)
}

// updateEndpointDiscoveryType will only update the dst with the value in the section, if
// a valid key and corresponding EndpointDiscoveryType is found.
func updateEndpointDiscoveryType(dst *aws.EndpointDiscoveryEnableState, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}

	value := section.String(key)
	if len(value) == 0 {
		return
	}

	switch {
	case strings.EqualFold(value, endpointDiscoveryDisabled):
		*dst = aws.EndpointDiscoveryDisabled
	case strings.EqualFold(value, endpointDiscoveryEnabled):
		*dst = aws.EndpointDiscoveryEnabled
	case strings.EqualFold(value, endpointDiscoveryAuto):
		*dst = aws.EndpointDiscoveryAuto
	}
}

// updateEndpointDiscoveryType will only update the dst with the value in the section, if
// a valid key and corresponding EndpointDiscoveryType is found.
func updateUseDualStackEndpoint(dst *aws.DualStackEndpointState, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}

	if section.Bool(key) {
		*dst = aws.DualStackEndpointStateEnabled
	} else {
		*dst = aws.DualStackEndpointStateDisabled
	}

	return
}

// updateEndpointDiscoveryType will only update the dst with the value in the section, if
// a valid key and corresponding EndpointDiscoveryType is found.
func updateUseFIPSEndpoint(dst *aws.FIPSEndpointState, section ini.Section, key string) {
	if !section.Has(key) {
		return
	}

	if section.Bool(key) {
		*dst = aws.FIPSEndpointStateEnabled
	} else {
		*dst = aws.FIPSEndpointStateDisabled
	}

	return
}
