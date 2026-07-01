package httpclient

import (
	"compress/gzip"
	"io"
	"net/http"

	"github.com/andybalholm/brotli"
)

func decodeGzip(reader io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

func decodeBrotli(reader io.Reader) ([]byte, error) {
	return io.ReadAll(brotli.NewReader(reader))
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func drainBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
