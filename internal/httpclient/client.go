package httpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dionebastos/vibesec/internal/config"
)

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	URL        string
	Proto      string
}

func (r *Response) ContentType() string {
	if r == nil {
		return ""
	}
	return r.Headers.Get("Content-Type")
}

type Client struct {
	http    *http.Client
	options Options
}

func New(opts Options) (*Client, error) {
	opts.applyDefaults()
	transport, err := buildTransport(opts)
	if err != nil {
		return nil, err
	}

	inner := &http.Client{
		Timeout:       opts.Timeout,
		Transport:     newRetryRoundTripper(transport, opts),
		Jar:           newCookieJar(),
		CheckRedirect: redirectPolicy(opts.MaxRedirects),
	}

	return &Client{http: inner, options: opts}, nil
}

func NewFromConfig(cfg *config.Config) (*Client, error) {
	return New(OptionsFromConfig(cfg))
}

func (c *Client) HTTPClient() *http.Client {
	return c.http
}

func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Head(ctx context.Context, rawURL string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Do(req *http.Request) (*Response, error) {
	c.prepareRequest(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	headers := resp.Header.Clone()
	stripContentEncoding(headers)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		URL:        resp.Request.URL.String(),
		Proto:      resp.Proto,
	}, nil
}

func (c *Client) prepareRequest(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.options.UserAgent)
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, br")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
}

func stripContentEncoding(headers http.Header) {
	headers.Del("Content-Encoding")
	headers.Del("Content-Length")
}

func readBody(resp *http.Response) ([]byte, error) {
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	reader := io.Reader(resp.Body)

	switch {
	case strings.Contains(encoding, "br"):
		decoded, err := decodeBrotli(reader)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case strings.Contains(encoding, "gzip"):
		decoded, err := decodeGzip(reader)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return io.ReadAll(reader)
	}
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		cloned := req.Clone(req.Context())
		cloned.Body = body
		return cloned, nil
	}
	if req.Body == nil {
		return req.Clone(req.Context()), nil
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	cloned := req.Clone(req.Context())
	cloned.Body = io.NopCloser(bytes.NewReader(data))
	cloned.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return cloned, nil
}
