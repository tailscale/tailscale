package ssocreds

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// ProviderName is the name of the provider used to specify the source of credentials.
const ProviderName = "SSOProvider"

var defaultCacheLocation func() string

func defaultCacheLocationImpl() string {
	return filepath.Join(getHomeDirectory(), ".aws", "sso", "cache")
}

func init() {
	defaultCacheLocation = defaultCacheLocationImpl
}

// GetRoleCredentialsAPIClient is a API client that implements the GetRoleCredentials operation.
type GetRoleCredentialsAPIClient interface {
	GetRoleCredentials(ctx context.Context, params *sso.GetRoleCredentialsInput, optFns ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error)
}

// Options is the Provider options structure.
type Options struct {
	// The Client which is configured for the AWS Region where the AWS SSO user portal is located.
	Client GetRoleCredentialsAPIClient

	// The AWS account that is assigned to the user.
	AccountID string

	// The role name that is assigned to the user.
	RoleName string

	// The URL that points to the organization's AWS Single Sign-On (AWS SSO) user portal.
	StartURL string
}

// Provider is an AWS credential provider that retrieves temporary AWS credentials by exchanging an SSO login token.
type Provider struct {
	options Options
}

// New returns a new AWS Single Sign-On (AWS SSO) credential provider. The provided client is expected to be configured
// for the AWS Region where the AWS SSO user portal is located.
func New(client GetRoleCredentialsAPIClient, accountID, roleName, startURL string, optFns ...func(options *Options)) *Provider {
	options := Options{
		Client:    client,
		AccountID: accountID,
		RoleName:  roleName,
		StartURL:  startURL,
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Provider{
		options: options,
	}
}

// Retrieve retrieves temporary AWS credentials from the configured Amazon Single Sign-On (AWS SSO) user portal
// by exchanging the accessToken present in ~/.aws/sso/cache.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	tokenFile, err := loadTokenFile(p.options.StartURL)
	if err != nil {
		return aws.Credentials{}, err
	}

	output, err := p.options.Client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: &tokenFile.AccessToken,
		AccountId:   &p.options.AccountID,
		RoleName:    &p.options.RoleName,
	})
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(output.RoleCredentials.AccessKeyId),
		SecretAccessKey: aws.ToString(output.RoleCredentials.SecretAccessKey),
		SessionToken:    aws.ToString(output.RoleCredentials.SessionToken),
		Expires:         time.Unix(0, output.RoleCredentials.Expiration*int64(time.Millisecond)).UTC(),
		CanExpire:       true,
		Source:          ProviderName,
	}, nil
}

func getCacheFileName(url string) (string, error) {
	hash := sha1.New()
	_, err := hash.Write([]byte(url))
	if err != nil {
		return "", err
	}
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil))) + ".json", nil
}

type rfc3339 time.Time

func (r *rfc3339) UnmarshalJSON(bytes []byte) error {
	var value string

	if err := json.Unmarshal(bytes, &value); err != nil {
		return err
	}

	parse, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("expected RFC3339 timestamp: %w", err)
	}

	*r = rfc3339(parse)

	return nil
}

type token struct {
	AccessToken string  `json:"accessToken"`
	ExpiresAt   rfc3339 `json:"expiresAt"`
	Region      string  `json:"region,omitempty"`
	StartURL    string  `json:"startUrl,omitempty"`
}

func (t token) Expired() bool {
	return sdk.NowTime().Round(0).After(time.Time(t.ExpiresAt))
}

// InvalidTokenError is the error type that is returned if loaded token has expired or is otherwise invalid.
// To refresh the SSO session run aws sso login with the corresponding profile.
type InvalidTokenError struct {
	Err error
}

func (i *InvalidTokenError) Unwrap() error {
	return i.Err
}

func (i *InvalidTokenError) Error() string {
	const msg = "the SSO session has expired or is invalid"
	if i.Err == nil {
		return msg
	}
	return msg + ": " + i.Err.Error()
}

func loadTokenFile(startURL string) (t token, err error) {
	key, err := getCacheFileName(startURL)
	if err != nil {
		return token{}, &InvalidTokenError{Err: err}
	}

	fileBytes, err := ioutil.ReadFile(filepath.Join(defaultCacheLocation(), key))
	if err != nil {
		return token{}, &InvalidTokenError{Err: err}
	}

	if err := json.Unmarshal(fileBytes, &t); err != nil {
		return token{}, &InvalidTokenError{Err: err}
	}

	if len(t.AccessToken) == 0 {
		return token{}, &InvalidTokenError{}
	}

	if t.Expired() {
		return token{}, &InvalidTokenError{Err: fmt.Errorf("access token is expired")}
	}

	return t, nil
}
