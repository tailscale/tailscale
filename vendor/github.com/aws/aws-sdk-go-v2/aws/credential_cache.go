package aws

import (
	"context"
	"sync/atomic"
	"time"

	sdkrand "github.com/aws/aws-sdk-go-v2/internal/rand"
	"github.com/aws/aws-sdk-go-v2/internal/sync/singleflight"
)

// CredentialsCacheOptions are the options
type CredentialsCacheOptions struct {

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// An ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired. This can cause an
	// increased number of requests to refresh the credentials to occur.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration

	// ExpiryWindowJitterFrac provides a mechanism for randomizing the expiration of credentials
	// within the configured ExpiryWindow by a random percentage. Valid values are between 0.0 and 1.0.
	//
	// As an example if ExpiryWindow is 60 seconds and ExpiryWindowJitterFrac is 0.5 then credentials will be set to
	// expire between 30 to 60 seconds prior to their actual expiration time.
	//
	// If ExpiryWindow is 0 or less then ExpiryWindowJitterFrac is ignored.
	// If ExpiryWindowJitterFrac is 0 then no randomization will be applied to the window.
	// If ExpiryWindowJitterFrac < 0 the value will be treated as 0.
	// If ExpiryWindowJitterFrac > 1 the value will be treated as 1.
	ExpiryWindowJitterFrac float64
}

// CredentialsCache provides caching and concurrency safe credentials retrieval
// via the provider's retrieve method.
type CredentialsCache struct {
	// provider is the CredentialProvider implementation to be wrapped by the CredentialCache.
	provider CredentialsProvider

	options CredentialsCacheOptions
	creds   atomic.Value
	sf      singleflight.Group
}

// NewCredentialsCache returns a CredentialsCache that wraps provider. Provider is expected to not be nil. A variadic
// list of one or more functions can be provided to modify the CredentialsCache configuration. This allows for
// configuration of credential expiry window and jitter.
func NewCredentialsCache(provider CredentialsProvider, optFns ...func(options *CredentialsCacheOptions)) *CredentialsCache {
	options := CredentialsCacheOptions{}

	for _, fn := range optFns {
		fn(&options)
	}

	if options.ExpiryWindow < 0 {
		options.ExpiryWindow = 0
	}

	if options.ExpiryWindowJitterFrac < 0 {
		options.ExpiryWindowJitterFrac = 0
	} else if options.ExpiryWindowJitterFrac > 1 {
		options.ExpiryWindowJitterFrac = 1
	}

	return &CredentialsCache{
		provider: provider,
		options:  options,
	}
}

// Retrieve returns the credentials. If the credentials have already been
// retrieved, and not expired the cached credentials will be returned. If the
// credentials have not been retrieved yet, or expired the provider's Retrieve
// method will be called.
//
// Returns and error if the provider's retrieve method returns an error.
func (p *CredentialsCache) Retrieve(ctx context.Context) (Credentials, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	resCh := p.sf.DoChan("", func() (interface{}, error) {
		return p.singleRetrieve(&suppressedContext{ctx})
	})
	select {
	case res := <-resCh:
		return res.Val.(Credentials), res.Err
	case <-ctx.Done():
		return Credentials{}, &RequestCanceledError{Err: ctx.Err()}
	}
}

func (p *CredentialsCache) singleRetrieve(ctx context.Context) (interface{}, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	creds, err := p.provider.Retrieve(ctx)
	if err == nil {
		if creds.CanExpire {
			randFloat64, err := sdkrand.CryptoRandFloat64()
			if err != nil {
				return Credentials{}, err
			}
			jitter := time.Duration(randFloat64 * p.options.ExpiryWindowJitterFrac * float64(p.options.ExpiryWindow))
			creds.Expires = creds.Expires.Add(-(p.options.ExpiryWindow - jitter))
		}

		p.creds.Store(&creds)
	}

	return creds, err
}

func (p *CredentialsCache) getCreds() *Credentials {
	v := p.creds.Load()
	if v == nil {
		return nil
	}

	c := v.(*Credentials)
	if c != nil && c.HasKeys() && !c.Expired() {
		return c
	}

	return nil
}

// Invalidate will invalidate the cached credentials. The next call to Retrieve
// will cause the provider's Retrieve method to be called.
func (p *CredentialsCache) Invalidate() {
	p.creds.Store((*Credentials)(nil))
}
