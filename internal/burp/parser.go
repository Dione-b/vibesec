package burp

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

type issuesDocument struct {
	XMLName xml.Name    `xml:"issues"`
	Issues  []issueNode `xml:"issue"`
}

type issueNode struct {
	Name        string `xml:"name"`
	Severity    string `xml:"severity"`
	Confidence  string `xml:"confidence"`
	Host        string `xml:"host"`
	Path        string `xml:"path"`
	Location    string `xml:"location"`
	Detail      string `xml:"issueDetail"`
	Remediation string `xml:"remediationBackground"`
}

func ParseFile(path string) (*Result, error) {
	if strings.TrimSpace(path) == "" {
		return &Result{Status: StatusSkipped, Summary: "no burp file configured"}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open burp file: %w", err)
	}
	defer file.Close()

	return ParseReader(file, path)
}

func ParseReader(reader io.Reader, source string) (*Result, error) {
	var doc issuesDocument
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse burp xml: %w", err)
	}

	result := &Result{
		Source: source,
		Status: StatusOK,
	}
	for _, node := range doc.Issues {
		result.Issues = append(result.Issues, Issue{
			Name:        strings.TrimSpace(node.Name),
			Severity:    strings.TrimSpace(node.Severity),
			Confidence:  strings.TrimSpace(node.Confidence),
			Host:        strings.TrimSpace(node.Host),
			Path:        strings.TrimSpace(node.Path),
			Location:    strings.TrimSpace(node.Location),
			Detail:      strings.TrimSpace(node.Detail),
			Remediation: strings.TrimSpace(node.Remediation),
		})
	}
	result.Summary = fmt.Sprintf("%d issues imported", len(result.Issues))
	return result, nil
}
