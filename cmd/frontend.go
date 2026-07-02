package cmd

import "net/http"

// FrontendHandler is optionally set by main to serve the embedded frontend.
var FrontendHandler func() http.Handler
