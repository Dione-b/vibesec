package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed frontend/dist
var frontendAssets embed.FS

func frontendHandler() http.Handler {
	sub, err := fs.Sub(frontendAssets, "frontend/dist")
	if err != nil {
		return nil
	}
	return spaHandler(sub)
}

// spaHandler serves static files with SPA fallback to index.html.
func spaHandler(files fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to open the requested file; if not found serve index.html
		f, err := files.Open(r.URL.Path)
		if err != nil {
			r.URL.Path = "/"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})
}
