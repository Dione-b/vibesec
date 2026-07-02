package httpclient

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, n)
		}
	}
}

var metadataHosts = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.aws.internal",
	"100.100.100.200",
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, m := range metadataHosts {
		if h == m {
			return true
		}
	}
	return false
}

var internalHostSuffixes = []string{
	".internal",
	".local",
	".localhost",
	".intranet",
}

func isInternalHostname(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	for _, suffix := range internalHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

func ValidateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("target host is required")
	}

	if isMetadataHost(host) {
		return fmt.Errorf("target is a cloud metadata endpoint")
	}

	if isInternalHostname(host) {
		return fmt.Errorf("target is an internal hostname")
	}

	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("target is a private/internal IP address")
		}
	}

	if strings.Contains(host, "%") || strings.Contains(host, "..") {
		return fmt.Errorf("invalid target hostname")
	}

	return nil
}

func IsAllowedRedirectHost(host string) bool {
	if host == "" {
		return false
	}
	if isMetadataHost(host) {
		return false
	}
	if isInternalHostname(host) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !isPrivateIP(ip)
	}
	return true
}
