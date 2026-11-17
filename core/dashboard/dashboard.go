package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var indexHTML []byte

// Serve writes the embedded dashboard page. The caller is responsible for
// gating this route: it must only be reachable on the admin-secret path
// (/_bProxy/<adminsecret>/dashboard), following the v1 API mounting pattern.
// The page itself fetches all data through the existing API v2 endpoints
// using the API secret supplied by the operator in the browser; it never
// receives or embeds any secret from the server.
func Serve(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Write(indexHTML)
}
