package http

import (
	"context"
	"fmt"

	"github.com/aws/smithy-go/middleware"
)

type headerValue struct {
	header string
	value  string
	append bool
}

type headerValueHelper struct {
	headerValues []headerValue
}

func (h *headerValueHelper) addHeaderValue(value headerValue) {
	h.headerValues = append(h.headerValues, value)
}

func (h *headerValueHelper) ID() string {
	return "HTTPHeaderHelper"
}

func (h *headerValueHelper) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
	req, ok := in.Request.(*Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	for _, value := range h.headerValues {
		if value.append {
			req.Header.Add(value.header, value.value)
		} else {
			req.Header.Set(value.header, value.value)
		}
	}

	return next.HandleBuild(ctx, in)
}

func getOrAddHeaderValueHelper(stack *middleware.Stack) (*headerValueHelper, error) {
	id := (*headerValueHelper)(nil).ID()
	m, ok := stack.Build.Get(id)
	if !ok {
		m = &headerValueHelper{}
		err := stack.Build.Add(m, middleware.After)
		if err != nil {
			return nil, err
		}
	}

	requestUserAgent, ok := m.(*headerValueHelper)
	if !ok {
		return nil, fmt.Errorf("%T for %s middleware did not match expected type", m, id)
	}

	return requestUserAgent, nil
}

// AddHeaderValue returns a stack mutator that adds the header value pair to header.
// Appends to any existing values if present.
func AddHeaderValue(header string, value string) func(stack *middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		helper, err := getOrAddHeaderValueHelper(stack)
		if err != nil {
			return err
		}
		helper.addHeaderValue(headerValue{header: header, value: value, append: true})
		return nil
	}
}

// SetHeaderValue returns a stack mutator that adds the header value pair to header.
// Replaces any existing values if present.
func SetHeaderValue(header string, value string) func(stack *middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		helper, err := getOrAddHeaderValueHelper(stack)
		if err != nil {
			return err
		}
		helper.addHeaderValue(headerValue{header: header, value: value, append: false})
		return nil
	}
}
