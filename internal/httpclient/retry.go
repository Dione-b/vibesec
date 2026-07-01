package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type retryRoundTripper struct {
	base http.RoundTripper
	opts Options
}

func newRetryRoundTripper(base http.RoundTripper, opts Options) http.RoundTripper {
	if opts.Retries <= 0 {
		return base
	}
	return &retryRoundTripper{base: base, opts: opts}
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := r.opts.Retries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		cloned, err := cloneRequest(req)
		if err != nil {
			return nil, err
		}

		resp, err := r.base.RoundTrip(cloned)
		if err != nil {
			lastErr = err
			if !isRetryableError(err) || attempt == attempts-1 {
				return nil, err
			}
			r.wait(req.Context(), attempt)
			continue
		}

		if !isRetryableStatus(resp.StatusCode) || attempt == attempts-1 {
			return resp, nil
		}

		drainBody(resp.Body)
		lastErr = fmt.Errorf("retryable status %d", resp.StatusCode)
		r.wait(req.Context(), attempt)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("request failed after retries")
}

func (r *retryRoundTripper) wait(ctx context.Context, attempt int) {
	backoff := r.opts.RetryBackoff * time.Duration(1<<attempt)
	timer := time.NewTimer(backoff)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return false
}
