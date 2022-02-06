package retry

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
)

// BackoffDelayer provides the interface for determining the delay to before
// another request attempt, that previously failed.
type BackoffDelayer interface {
	BackoffDelay(attempt int, err error) (time.Duration, error)
}

// BackoffDelayerFunc provides a wrapper around a function to determine the
// backoff delay of an attempt retry.
type BackoffDelayerFunc func(int, error) (time.Duration, error)

// BackoffDelay returns the delay before attempt to retry a request.
func (fn BackoffDelayerFunc) BackoffDelay(attempt int, err error) (time.Duration, error) {
	return fn(attempt, err)
}

const (
	// DefaultMaxAttempts is the maximum of attempts for an API request
	DefaultMaxAttempts int = 3

	// DefaultMaxBackoff is the maximum back off delay between attempts
	DefaultMaxBackoff time.Duration = 20 * time.Second
)

// Default retry token quota values.
const (
	DefaultRetryRateTokens  uint = 500
	DefaultRetryCost        uint = 5
	DefaultRetryTimeoutCost uint = 10
	DefaultNoRetryIncrement uint = 1
)

// DefaultRetryableHTTPStatusCodes is the default set of HTTP status codes the SDK
// should consider as retryable errors.
var DefaultRetryableHTTPStatusCodes = map[int]struct{}{
	500: {},
	502: {},
	503: {},
	504: {},
}

// DefaultRetryableErrorCodes provides the set of API error codes that should
// be retried.
var DefaultRetryableErrorCodes = map[string]struct{}{
	"RequestTimeout":          {},
	"RequestTimeoutException": {},

	// Throttled status codes
	"Throttling":                             {},
	"ThrottlingException":                    {},
	"ThrottledException":                     {},
	"RequestThrottledException":              {},
	"TooManyRequestsException":               {},
	"ProvisionedThroughputExceededException": {},
	"TransactionInProgressException":         {},
	"RequestLimitExceeded":                   {},
	"BandwidthLimitExceeded":                 {},
	"LimitExceededException":                 {},
	"RequestThrottled":                       {},
	"SlowDown":                               {},
	"PriorRequestNotComplete":                {},
	"EC2ThrottledException":                  {},
}

// DefaultRetryables provides the set of retryable checks that are used by
// default.
var DefaultRetryables = []IsErrorRetryable{
	NoRetryCanceledError{},
	RetryableError{},
	RetryableConnectionError{},
	RetryableHTTPStatusCode{
		Codes: DefaultRetryableHTTPStatusCodes,
	},
	RetryableErrorCode{
		Codes: DefaultRetryableErrorCodes,
	},
}

// StandardOptions provides the functional options for configuring the standard
// retryable, and delay behavior.
type StandardOptions struct {
	MaxAttempts int
	MaxBackoff  time.Duration
	Backoff     BackoffDelayer

	Retryables []IsErrorRetryable
	Timeouts   []IsErrorTimeout

	RateLimiter      RateLimiter
	RetryCost        uint
	RetryTimeoutCost uint
	NoRetryIncrement uint
}

// RateLimiter provides the interface for limiting the rate of request retries
// allowed by the retrier.
type RateLimiter interface {
	GetToken(ctx context.Context, cost uint) (releaseToken func() error, err error)
	AddTokens(uint) error
}

// Standard is the standard retry pattern for the SDK. It uses a set of
// retryable checks to determine of the failed request should be retried, and
// what retry delay should be used.
type Standard struct {
	options StandardOptions

	timeout   IsErrorTimeout
	retryable IsErrorRetryable
	backoff   BackoffDelayer
}

// NewStandard initializes a standard retry behavior with defaults that can be
// overridden via functional options.
func NewStandard(fnOpts ...func(*StandardOptions)) *Standard {
	o := StandardOptions{
		MaxAttempts: DefaultMaxAttempts,
		MaxBackoff:  DefaultMaxBackoff,
		Retryables:  DefaultRetryables,

		RateLimiter:      ratelimit.NewTokenRateLimit(DefaultRetryRateTokens),
		RetryCost:        DefaultRetryCost,
		RetryTimeoutCost: DefaultRetryTimeoutCost,
		NoRetryIncrement: DefaultNoRetryIncrement,
	}
	for _, fn := range fnOpts {
		fn(&o)
	}

	backoff := o.Backoff
	if backoff == nil {
		backoff = NewExponentialJitterBackoff(o.MaxBackoff)
	}

	rs := make([]IsErrorRetryable, len(o.Retryables))
	copy(rs, o.Retryables)

	ts := make([]IsErrorTimeout, len(o.Timeouts))
	copy(ts, o.Timeouts)

	return &Standard{
		options:   o,
		backoff:   backoff,
		retryable: IsErrorRetryables(rs),
		timeout:   IsErrorTimeouts(ts),
	}
}

// MaxAttempts returns the maximum number of attempts that can be made for a
// request before failing.
func (s *Standard) MaxAttempts() int {
	return s.options.MaxAttempts
}

// IsErrorRetryable returns if the error is can be retried or not. Should not
// consider the number of attempts made.
func (s *Standard) IsErrorRetryable(err error) bool {
	return s.retryable.IsErrorRetryable(err).Bool()
}

// RetryDelay returns the delay to use before another request attempt is made.
func (s *Standard) RetryDelay(attempt int, err error) (time.Duration, error) {
	return s.backoff.BackoffDelay(attempt, err)
}

// GetInitialToken returns the initial request token that can increment the
// retry token pool if the request is successful.
func (s *Standard) GetInitialToken() func(error) error {
	return releaseToken(s.incrementTokens).release
}

func (s *Standard) incrementTokens() error {
	return s.options.RateLimiter.AddTokens(s.options.NoRetryIncrement)
}

// GetRetryToken attempts to deduct the retry cost from the retry token pool.
// Returning the token release function, or error.
func (s *Standard) GetRetryToken(ctx context.Context, err error) (func(error) error, error) {
	cost := s.options.RetryCost
	if s.timeout.IsErrorTimeout(err).Bool() {
		cost = s.options.RetryTimeoutCost
	}

	fn, err := s.options.RateLimiter.GetToken(ctx, cost)
	if err != nil {
		return nil, err
	}

	return releaseToken(fn).release, nil
}

type releaseToken func() error

func (f releaseToken) release(err error) error {
	if err != nil {
		return nil
	}

	return f()
}
