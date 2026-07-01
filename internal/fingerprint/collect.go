package fingerprint

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func Analyze(target string, resp *httpclient.Response) (*Result, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	result := &Result{
		Server:    strings.TrimSpace(resp.Headers.Get("Server")),
		PoweredBy: strings.TrimSpace(resp.Headers.Get("X-Powered-By")),
		Cookies:   parseCookies(resp.Headers),
	}

	result.Infra = detectInfra(resp.Headers, resp.URL)
	result.Frameworks = detectFrameworks(resp.Headers, resp.Body)
	result.TLS = probeTLS(parsed.Hostname())
	result.BuildStack()
	return result, nil
}

func parseCookies(headers http.Header) []CookieInfo {
	var cookies []CookieInfo
	for _, raw := range headers.Values("Set-Cookie") {
		name := cookieName(raw)
		if name == "" {
			continue
		}
		lower := strings.ToLower(raw)
		cookies = append(cookies, CookieInfo{
			Name:     name,
			Secure:   strings.Contains(lower, "secure"),
			HttpOnly: strings.Contains(lower, "httponly"),
			SameSite: parseSameSite(lower),
		})
	}
	return cookies
}

func cookieName(raw string) string {
	part := strings.TrimSpace(strings.Split(raw, ";")[0])
	if part == "" {
		return ""
	}
	name, _, ok := strings.Cut(part, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func cookieValue(raw string) string {
	part := strings.TrimSpace(strings.Split(raw, ";")[0])
	_, value, ok := strings.Cut(part, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func parseSameSite(raw string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "samesite=") {
			return strings.TrimPrefix(part, "samesite=")
		}
	}
	return ""
}

func probeTLS(hostname string) TLSInfo {
	if hostname == "" {
		return TLSInfo{}
	}

	addr := net.JoinHostPort(hostname, "443")
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return TLSInfo{}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info := TLSInfo{
		Version: tlsVersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		info.Issuer = state.PeerCertificates[0].Issuer.String()
	}
	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%x", version)
	}
}
