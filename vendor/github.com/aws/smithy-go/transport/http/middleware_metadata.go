package http

import (
	"context"

	"github.com/aws/smithy-go/middleware"
)

type (
	hostnameImmutableKey struct{}
	hostPrefixDisableKey struct{}
)

// GetHostnameImmutable retrieves if the endpoint hostname should be considered
// immutable or not.
//
// Scoped to stack values. Use middleware#ClearStackValues to clear all stack
// values.
func GetHostnameImmutable(ctx context.Context) (v bool) {
	v, _ = middleware.GetStackValue(ctx, hostnameImmutableKey{}).(bool)
	return v
}

// SetHostnameImmutable sets or modifies if the request's endpoint hostname
// should be considered immutable or not.
//
// Scoped to stack values. Use middleware#ClearStackValues to clear all stack
// values.
func SetHostnameImmutable(ctx context.Context, value bool) context.Context {
	return middleware.WithStackValue(ctx, hostnameImmutableKey{}, value)
}

// IsEndpointHostPrefixDisabled retrieves if the hostname prefixing is
// disabled.
//
// Scoped to stack values. Use middleware#ClearStackValues to clear all stack
// values.
func IsEndpointHostPrefixDisabled(ctx context.Context) (v bool) {
	v, _ = middleware.GetStackValue(ctx, hostPrefixDisableKey{}).(bool)
	return v
}

// DisableEndpointHostPrefix sets or modifies if the request's endpoint host
// prefixing to be disabled. If value is set to true, endpoint host prefixing
// will be disabled.
//
// Scoped to stack values. Use middleware#ClearStackValues to clear all stack
// values.
func DisableEndpointHostPrefix(ctx context.Context, value bool) context.Context {
	return middleware.WithStackValue(ctx, hostPrefixDisableKey{}, value)
}
