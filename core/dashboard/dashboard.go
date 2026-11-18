package dashboard

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed index.html
var indexHTML []byte

//go:embed manifest.webmanifest
var manifestJSON []byte

//go:embed sw.js
var serviceWorkerJS []byte

//go:embed icons/icon-192.png
var icon192 []byte

//go:embed icons/icon-512.png
var icon512 []byte

//go:embed icons/icon-180.png
var icon180 []byte

//go:embed icons/icon-maskable-512.png
var iconMaskable512 []byte

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

// shellAsset is one PWA shell file: bytes, content type, and the
// cache directive it is served with. Icons are immutable
// versioned content (long cache); the manifest is never cached;
// the service worker revalidates every load so updates apply.
type shellAsset struct {
	data        []byte
	contentType string
	cache       string
}

// shellAssets maps the path suffix (after the admin-secret prefix)
// of each PWA shell asset. The shell contains no secrets and no
// live data: the manifest, the service worker, and the icons.
// API responses are never shell assets; the service worker never
// caches them either.
var shellAssets = map[string]shellAsset{
	"manifest.webmanifest":        {manifestJSON, "application/manifest+json", "no-store"},
	"sw.js":                       {serviceWorkerJS, "text/javascript; charset=utf-8", "no-cache"},
	"icons/icon-192.png":          {icon192, "image/png", "public, max-age=86400"},
	"icons/icon-512.png":          {icon512, "image/png", "public, max-age=86400"},
	"icons/icon-180.png":          {icon180, "image/png", "public, max-age=86400"},
	"icons/icon-maskable-512.png": {iconMaskable512, "image/png", "public, max-age=86400"},
}

// ServeAsset serves a PWA shell asset when path is one of the
// known asset paths under the admin-secret prefix, and reports
// whether it served anything. It refuses when no admin secret is
// configured, so the assets can never become unauthenticated.
// Callers invoke it at the same dispatch sites as Serve.
func ServeAsset(writer http.ResponseWriter, path, adminSecret string) bool {
	asset, ok := shellAssetFor(path, adminSecret)
	if !ok {
		return false
	}
	writer.Header().Set("Content-Type", asset.contentType)
	writer.Header().Set("Cache-Control", asset.cache)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Write(asset.data)
	return true
}

// IsShellAsset reports whether path is a PWA shell asset under
// the admin-secret prefix. The challenge-flow exemption uses it:
// shell-asset requests are dashboard traffic, authenticated by
// the secret path segment exactly like the dashboard page, not
// visitor traffic.
func IsShellAsset(path, adminSecret string) bool {
	_, ok := shellAssetFor(path, adminSecret)
	return ok
}

func shellAssetFor(path, adminSecret string) (shellAsset, bool) {
	if adminSecret == "" {
		return shellAsset{}, false
	}
	prefix := "/_bProxy/" + adminSecret + "/"
	if !strings.HasPrefix(path, prefix) {
		return shellAsset{}, false
	}
	asset, ok := shellAssets[strings.TrimPrefix(path, prefix)]
	return asset, ok
}
