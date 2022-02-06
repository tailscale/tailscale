package config

import (
	"context"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
)

// sharedConfigProfileProvider provides access to the shared config profile
// name external configuration value.
type sharedConfigProfileProvider interface {
	getSharedConfigProfile(ctx context.Context) (string, bool, error)
}

// getSharedConfigProfile searches the configs for a sharedConfigProfileProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getSharedConfigProfile(ctx context.Context, configs configs) (value string, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(sharedConfigProfileProvider); ok {
			value, found, err = p.getSharedConfigProfile(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// sharedConfigFilesProvider provides access to the shared config filesnames
// external configuration value.
type sharedConfigFilesProvider interface {
	getSharedConfigFiles(ctx context.Context) ([]string, bool, error)
}

// getSharedConfigFiles searches the configs for a sharedConfigFilesProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getSharedConfigFiles(ctx context.Context, configs configs) (value []string, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(sharedConfigFilesProvider); ok {
			value, found, err = p.getSharedConfigFiles(ctx)
			if err != nil || found {
				break
			}
		}
	}

	return
}

// sharedCredentialsFilesProvider provides access to the shared credentials filesnames
// external configuration value.
type sharedCredentialsFilesProvider interface {
	getSharedCredentialsFiles(ctx context.Context) ([]string, bool, error)
}

// getSharedCredentialsFiles searches the configs for a sharedCredentialsFilesProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getSharedCredentialsFiles(ctx context.Context, configs configs) (value []string, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(sharedCredentialsFilesProvider); ok {
			value, found, err = p.getSharedCredentialsFiles(ctx)
			if err != nil || found {
				break
			}
		}
	}

	return
}

// customCABundleProvider provides access to the custom CA bundle PEM bytes.
type customCABundleProvider interface {
	getCustomCABundle(ctx context.Context) (io.Reader, bool, error)
}

// getCustomCABundle searches the configs for a customCABundleProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getCustomCABundle(ctx context.Context, configs configs) (value io.Reader, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(customCABundleProvider); ok {
			value, found, err = p.getCustomCABundle(ctx)
			if err != nil || found {
				break
			}
		}
	}

	return
}

// regionProvider provides access to the region external configuration value.
type regionProvider interface {
	getRegion(ctx context.Context) (string, bool, error)
}

// getRegion searches the configs for a regionProvider and returns the value
// if found. Returns an error if a provider fails before a value is found.
func getRegion(ctx context.Context, configs configs) (value string, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(regionProvider); ok {
			value, found, err = p.getRegion(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// ec2IMDSRegionProvider provides access to the ec2 imds region
// configuration value
type ec2IMDSRegionProvider interface {
	getEC2IMDSRegion(ctx context.Context) (string, bool, error)
}

// getEC2IMDSRegion searches the configs for a ec2IMDSRegionProvider and
// returns the value if found. Returns an error if a provider fails before
// a value is found.
func getEC2IMDSRegion(ctx context.Context, configs configs) (region string, found bool, err error) {
	for _, cfg := range configs {
		if provider, ok := cfg.(ec2IMDSRegionProvider); ok {
			region, found, err = provider.getEC2IMDSRegion(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// credentialsProviderProvider provides access to the credentials external
// configuration value.
type credentialsProviderProvider interface {
	getCredentialsProvider(ctx context.Context) (aws.CredentialsProvider, bool, error)
}

// getCredentialsProvider searches the configs for a credentialsProviderProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getCredentialsProvider(ctx context.Context, configs configs) (p aws.CredentialsProvider, found bool, err error) {
	for _, cfg := range configs {
		if provider, ok := cfg.(credentialsProviderProvider); ok {
			p, found, err = provider.getCredentialsProvider(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// processCredentialOptions is an interface for retrieving a function for setting
// the processcreds.Options.
type processCredentialOptions interface {
	getProcessCredentialOptions(ctx context.Context) (func(*processcreds.Options), bool, error)
}

// getProcessCredentialOptions searches the slice of configs and returns the first function found
func getProcessCredentialOptions(ctx context.Context, configs configs) (f func(*processcreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(processCredentialOptions); ok {
			f, found, err = p.getProcessCredentialOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// ec2RoleCredentialOptionsProvider is an interface for retrieving a function
// for setting the ec2rolecreds.Provider options.
type ec2RoleCredentialOptionsProvider interface {
	getEC2RoleCredentialOptions(ctx context.Context) (func(*ec2rolecreds.Options), bool, error)
}

// getEC2RoleCredentialProviderOptions searches the slice of configs and returns the first function found
func getEC2RoleCredentialProviderOptions(ctx context.Context, configs configs) (f func(*ec2rolecreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(ec2RoleCredentialOptionsProvider); ok {
			f, found, err = p.getEC2RoleCredentialOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// defaultRegionProvider is an interface for retrieving a default region if a region was not resolved from other sources
type defaultRegionProvider interface {
	getDefaultRegion(ctx context.Context) (string, bool, error)
}

// getDefaultRegion searches the slice of configs and returns the first fallback region found
func getDefaultRegion(ctx context.Context, configs configs) (value string, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(defaultRegionProvider); ok {
			value, found, err = p.getDefaultRegion(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// endpointCredentialOptionsProvider is an interface for retrieving a function for setting
// the endpointcreds.ProviderOptions.
type endpointCredentialOptionsProvider interface {
	getEndpointCredentialOptions(ctx context.Context) (func(*endpointcreds.Options), bool, error)
}

// getEndpointCredentialProviderOptions searches the slice of configs and returns the first function found
func getEndpointCredentialProviderOptions(ctx context.Context, configs configs) (f func(*endpointcreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(endpointCredentialOptionsProvider); ok {
			f, found, err = p.getEndpointCredentialOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// webIdentityRoleCredentialOptionsProvider is an interface for retrieving a function for setting
// the stscreds.WebIdentityRoleProvider.
type webIdentityRoleCredentialOptionsProvider interface {
	getWebIdentityRoleCredentialOptions(ctx context.Context) (func(*stscreds.WebIdentityRoleOptions), bool, error)
}

// getWebIdentityCredentialProviderOptions searches the slice of configs and returns the first function found
func getWebIdentityCredentialProviderOptions(ctx context.Context, configs configs) (f func(*stscreds.WebIdentityRoleOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(webIdentityRoleCredentialOptionsProvider); ok {
			f, found, err = p.getWebIdentityRoleCredentialOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// assumeRoleCredentialOptionsProvider is an interface for retrieving a function for setting
// the stscreds.AssumeRoleOptions.
type assumeRoleCredentialOptionsProvider interface {
	getAssumeRoleCredentialOptions(ctx context.Context) (func(*stscreds.AssumeRoleOptions), bool, error)
}

// getAssumeRoleCredentialProviderOptions searches the slice of configs and returns the first function found
func getAssumeRoleCredentialProviderOptions(ctx context.Context, configs configs) (f func(*stscreds.AssumeRoleOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(assumeRoleCredentialOptionsProvider); ok {
			f, found, err = p.getAssumeRoleCredentialOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// HTTPClient is an HTTP client implementation
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// httpClientProvider is an interface for retrieving HTTPClient
type httpClientProvider interface {
	getHTTPClient(ctx context.Context) (HTTPClient, bool, error)
}

// getHTTPClient searches the slice of configs and returns the HTTPClient set on configs
func getHTTPClient(ctx context.Context, configs configs) (client HTTPClient, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(httpClientProvider); ok {
			client, found, err = p.getHTTPClient(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// apiOptionsProvider is an interface for retrieving APIOptions
type apiOptionsProvider interface {
	getAPIOptions(ctx context.Context) ([]func(*middleware.Stack) error, bool, error)
}

// getAPIOptions searches the slice of configs and returns the APIOptions set on configs
func getAPIOptions(ctx context.Context, configs configs) (apiOptions []func(*middleware.Stack) error, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(apiOptionsProvider); ok {
			// retrieve APIOptions from configs and set it on cfg
			apiOptions, found, err = p.getAPIOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// endpointResolverProvider is an interface for retrieving an aws.EndpointResolver from a configuration source
type endpointResolverProvider interface {
	getEndpointResolver(ctx context.Context) (aws.EndpointResolver, bool, error)
}

// getEndpointResolver searches the provided config sources for a EndpointResolverFunc that can be used
// to configure the aws.Config.EndpointResolver value.
func getEndpointResolver(ctx context.Context, configs configs) (f aws.EndpointResolver, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(endpointResolverProvider); ok {
			f, found, err = p.getEndpointResolver(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// endpointResolverWithOptionsProvider is an interface for retrieving an aws.EndpointResolverWithOptions from a configuration source
type endpointResolverWithOptionsProvider interface {
	getEndpointResolverWithOptions(ctx context.Context) (aws.EndpointResolverWithOptions, bool, error)
}

// getEndpointResolver searches the provided config sources for a EndpointResolverFunc that can be used
// to configure the aws.Config.EndpointResolver value.
func getEndpointResolverWithOptions(ctx context.Context, configs configs) (f aws.EndpointResolverWithOptions, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(endpointResolverWithOptionsProvider); ok {
			f, found, err = p.getEndpointResolverWithOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// loggerProvider is an interface for retrieving a logging.Logger from a configuration source.
type loggerProvider interface {
	getLogger(ctx context.Context) (logging.Logger, bool, error)
}

// getLogger searches the provided config sources for a logging.Logger that can be used
// to configure the aws.Config.Logger value.
func getLogger(ctx context.Context, configs configs) (l logging.Logger, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(loggerProvider); ok {
			l, found, err = p.getLogger(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// clientLogModeProvider is an interface for retrieving the aws.ClientLogMode from a configuration source.
type clientLogModeProvider interface {
	getClientLogMode(ctx context.Context) (aws.ClientLogMode, bool, error)
}

func getClientLogMode(ctx context.Context, configs configs) (m aws.ClientLogMode, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(clientLogModeProvider); ok {
			m, found, err = p.getClientLogMode(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// retryProvider is an configuration provider for custom Retryer.
type retryProvider interface {
	getRetryer(ctx context.Context) (func() aws.Retryer, bool, error)
}

func getRetryer(ctx context.Context, configs configs) (v func() aws.Retryer, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(retryProvider); ok {
			v, found, err = p.getRetryer(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// logConfigurationWarningsProvider is an configuration provider for
// retrieving a boolean indicating whether configuration issues should
// be logged when loading from config sources
type logConfigurationWarningsProvider interface {
	getLogConfigurationWarnings(ctx context.Context) (bool, bool, error)
}

func getLogConfigurationWarnings(ctx context.Context, configs configs) (v bool, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(logConfigurationWarningsProvider); ok {
			v, found, err = p.getLogConfigurationWarnings(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}

// ssoCredentialOptionsProvider is an interface for retrieving a function for setting
// the ssocreds.Options.
type ssoCredentialOptionsProvider interface {
	getSSOProviderOptions(context.Context) (func(*ssocreds.Options), bool, error)
}

func getSSOProviderOptions(ctx context.Context, configs configs) (v func(options *ssocreds.Options), found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(ssoCredentialOptionsProvider); ok {
			v, found, err = p.getSSOProviderOptions(ctx)
			if err != nil || found {
				break
			}
		}
	}
	return
}
