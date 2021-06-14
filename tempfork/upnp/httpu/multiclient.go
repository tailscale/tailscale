package httpu

import (
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// MultiClient dispatches requests out to all the delegated clients.
type MultiClient struct {
	// The HTTPU clients to delegate to.
	delegates []ClientInterface
}

var _ ClientInterface = &MultiClient{}

// NewMultiClient creates a new MultiClient that delegates to all the given
// clients.
func NewMultiClient(delegates []ClientInterface) *MultiClient {
	return &MultiClient{
		delegates: delegates,
	}
}

// Do implements ClientInterface.Do.
func (mc *MultiClient) Do(
	req *http.Request,
	timeout time.Duration,
	numSends int,
) ([]*http.Response, error) {
	tasks := &errgroup.Group{}

	results := make(chan []*http.Response)
	tasks.Go(func() error {
		defer close(results)
		return mc.sendRequests(results, req, timeout, numSends)
	})

	var responses []*http.Response
	tasks.Go(func() error {
		for rs := range results {
			responses = append(responses, rs...)
		}
		return nil
	})

	return responses, tasks.Wait()
}

func (mc *MultiClient) sendRequests(
	results chan<- []*http.Response,
	req *http.Request,
	timeout time.Duration,
	numSends int,
) error {
	tasks := &errgroup.Group{}
	for _, d := range mc.delegates {
		d := d // copy for closure
		tasks.Go(func() error {
			responses, err := d.Do(req, timeout, numSends)
			if err != nil {
				return err
			}
			results <- responses
			return nil
		})
	}
	return tasks.Wait()
}
