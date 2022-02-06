package retry

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddle "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithymiddle "github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http"
)

// RequestCloner is a function that can take an input request type and clone the request
// for use in a subsequent retry attempt
type RequestCloner func(interface{}) interface{}

type retryMetadata struct {
	AttemptNum       int
	AttemptTime      time.Time
	MaxAttempts      int
	AttemptClockSkew time.Duration
}

// Attempt is a Smithy FinalizeMiddleware that handles retry attempts using the provided
// Retryer implementation
type Attempt struct {
	// Enable the logging of retry attempts performed by the SDK.
	// This will include logging retry attempts, unretryable errors, and when max attempts are reached.
	LogAttempts bool

	retryer       aws.Retryer
	requestCloner RequestCloner
}

// NewAttemptMiddleware returns a new Attempt retry middleware.
func NewAttemptMiddleware(retryer aws.Retryer, requestCloner RequestCloner, optFns ...func(*Attempt)) *Attempt {
	m := &Attempt{retryer: retryer, requestCloner: requestCloner}
	for _, fn := range optFns {
		fn(m)
	}
	return m
}

// ID returns the middleware identifier
func (r *Attempt) ID() string {
	return "Retry"
}

func (r Attempt) logf(logger logging.Logger, classification logging.Classification, format string, v ...interface{}) {
	if !r.LogAttempts {
		return
	}
	logger.Logf(classification, format, v...)
}

// HandleFinalize utilizes the provider Retryer implementation to attempt retries over the next handler
func (r Attempt) HandleFinalize(ctx context.Context, in smithymiddle.FinalizeInput, next smithymiddle.FinalizeHandler) (
	out smithymiddle.FinalizeOutput, metadata smithymiddle.Metadata, err error,
) {
	var attemptNum int
	var attemptClockSkew time.Duration
	var attemptResults AttemptResults

	maxAttempts := r.retryer.MaxAttempts()

	for {
		attemptNum++
		attemptInput := in
		attemptInput.Request = r.requestCloner(attemptInput.Request)

		attemptCtx := setRetryMetadata(ctx, retryMetadata{
			AttemptNum:       attemptNum,
			AttemptTime:      sdk.NowTime().UTC(),
			MaxAttempts:      maxAttempts,
			AttemptClockSkew: attemptClockSkew,
		})

		var attemptResult AttemptResult

		out, attemptResult, err = r.handleAttempt(attemptCtx, attemptInput, next)

		var ok bool
		attemptClockSkew, ok = awsmiddle.GetAttemptSkew(attemptResult.ResponseMetadata)
		if !ok {
			attemptClockSkew = 0
		}

		shouldRetry := attemptResult.Retried

		// add attempt metadata to list of all attempt metadata
		attemptResults.Results = append(attemptResults.Results, attemptResult)

		if !shouldRetry {
			// Ensure the last response's metadata is used as the bases for result
			// metadata returned by the stack.
			metadata = attemptResult.ResponseMetadata.Clone()

			break
		}
	}

	addAttemptResults(&metadata, attemptResults)
	return out, metadata, err
}

// handleAttempt handles an individual request attempt.
func (r Attempt) handleAttempt(ctx context.Context, in smithymiddle.FinalizeInput, next smithymiddle.FinalizeHandler) (
	out smithymiddle.FinalizeOutput, attemptResult AttemptResult, err error,
) {
	defer func() {
		attemptResult.Err = err
	}()

	relRetryToken := r.retryer.GetInitialToken()
	logger := smithymiddle.GetLogger(ctx)
	service, operation := awsmiddle.GetServiceID(ctx), awsmiddle.GetOperationName(ctx)

	retryMetadata, _ := getRetryMetadata(ctx)
	attemptNum := retryMetadata.AttemptNum
	maxAttempts := retryMetadata.MaxAttempts

	if attemptNum > 1 {
		if rewindable, ok := in.Request.(interface{ RewindStream() error }); ok {
			if rewindErr := rewindable.RewindStream(); rewindErr != nil {
				err = fmt.Errorf("failed to rewind transport stream for retry, %w", rewindErr)
				return out, attemptResult, err
			}
		}

		r.logf(logger, logging.Debug, "retrying request %s/%s, attempt %d", service, operation, attemptNum)
	}

	var metadata smithymiddle.Metadata
	out, metadata, err = next.HandleFinalize(ctx, in)
	attemptResult.ResponseMetadata = metadata

	if releaseError := relRetryToken(err); releaseError != nil && err != nil {
		err = fmt.Errorf("failed to release token after request error, %w", err)
		return out, attemptResult, err
	}

	if err == nil {
		return out, attemptResult, err
	}

	retryable := r.retryer.IsErrorRetryable(err)
	if !retryable {
		r.logf(logger, logging.Debug, "request failed with unretryable error %v", err)
		return out, attemptResult, err
	}

	// set retryable to true
	attemptResult.Retryable = true

	if maxAttempts > 0 && attemptNum >= maxAttempts {
		r.logf(logger, logging.Debug, "max retry attempts exhausted, max %d", maxAttempts)
		err = &MaxAttemptsError{
			Attempt: attemptNum,
			Err:     err,
		}
		return out, attemptResult, err
	}

	relRetryToken, reqErr := r.retryer.GetRetryToken(ctx, err)
	if reqErr != nil {
		return out, attemptResult, reqErr
	}

	retryDelay, reqErr := r.retryer.RetryDelay(attemptNum, err)
	if reqErr != nil {
		return out, attemptResult, reqErr
	}

	if reqErr = sdk.SleepWithContext(ctx, retryDelay); reqErr != nil {
		err = &aws.RequestCanceledError{Err: reqErr}
		return out, attemptResult, err
	}

	attemptResult.Retried = true

	return out, attemptResult, err
}

// MetricsHeader attaches SDK request metric header for retries to the transport
type MetricsHeader struct{}

// ID returns the middleware identifier
func (r *MetricsHeader) ID() string {
	return "RetryMetricsHeader"
}

// HandleFinalize attaches the sdk request metric header to the transport layer
func (r MetricsHeader) HandleFinalize(ctx context.Context, in smithymiddle.FinalizeInput, next smithymiddle.FinalizeHandler) (
	out smithymiddle.FinalizeOutput, metadata smithymiddle.Metadata, err error,
) {
	retryMetadata, _ := getRetryMetadata(ctx)

	const retryMetricHeader = "Amz-Sdk-Request"
	var parts []string

	parts = append(parts, "attempt="+strconv.Itoa(retryMetadata.AttemptNum))
	if retryMetadata.MaxAttempts != 0 {
		parts = append(parts, "max="+strconv.Itoa(retryMetadata.MaxAttempts))
	}

	var ttl time.Time
	if deadline, ok := ctx.Deadline(); ok {
		ttl = deadline
	}

	// Only append the TTL if it can be determined.
	if !ttl.IsZero() && retryMetadata.AttemptClockSkew > 0 {
		const unixTimeFormat = "20060102T150405Z"
		ttl = ttl.Add(retryMetadata.AttemptClockSkew)
		parts = append(parts, "ttl="+ttl.Format(unixTimeFormat))
	}

	switch req := in.Request.(type) {
	case *http.Request:
		req.Header[retryMetricHeader] = append(req.Header[retryMetricHeader][:0], strings.Join(parts, "; "))
	default:
		return out, metadata, fmt.Errorf("unknown transport type %T", req)
	}

	return next.HandleFinalize(ctx, in)
}

type retryMetadataKey struct{}

// getRetryMetadata retrieves retryMetadata from the context and a bool
// indicating if it was set.
//
// Scoped to stack values. Use github.com/aws/smithy-go/middleware#ClearStackValues
// to clear all stack values.
func getRetryMetadata(ctx context.Context) (metadata retryMetadata, ok bool) {
	metadata, ok = middleware.GetStackValue(ctx, retryMetadataKey{}).(retryMetadata)
	return metadata, ok
}

// setRetryMetadata sets the retryMetadata on the context.
//
// Scoped to stack values. Use github.com/aws/smithy-go/middleware#ClearStackValues
// to clear all stack values.
func setRetryMetadata(ctx context.Context, metadata retryMetadata) context.Context {
	return middleware.WithStackValue(ctx, retryMetadataKey{}, metadata)
}

// AddRetryMiddlewaresOptions is the set of options that can be passed to AddRetryMiddlewares for configuring retry
// associated middleware.
type AddRetryMiddlewaresOptions struct {
	Retryer aws.Retryer

	// Enable the logging of retry attempts performed by the SDK.
	// This will include logging retry attempts, unretryable errors, and when max attempts are reached.
	LogRetryAttempts bool
}

// AddRetryMiddlewares adds retry middleware to operation middleware stack
func AddRetryMiddlewares(stack *smithymiddle.Stack, options AddRetryMiddlewaresOptions) error {
	attempt := NewAttemptMiddleware(options.Retryer, http.RequestCloner, func(middleware *Attempt) {
		middleware.LogAttempts = options.LogRetryAttempts
	})

	if err := stack.Finalize.Add(attempt, smithymiddle.After); err != nil {
		return err
	}
	if err := stack.Finalize.Add(&MetricsHeader{}, smithymiddle.After); err != nil {
		return err
	}
	return nil
}
