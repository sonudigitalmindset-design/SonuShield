package dashboard

import (
	_ "embed"
	"html"
	"net/http"
	"sonushield/core/domains"
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
//
// brand is the proxy-wide operator branding (see domains.Branding).
// When set, it replaces the wordmark, the page title, the brand mark,
// and the accent color. It NEVER touches the About footer, the
// credits text, or any GPL attribution: those have no placeholders
// and are served verbatim. With empty branding the output is the
// built-in page, byte for byte.
func Serve(writer http.ResponseWriter, brand domains.Branding) {
	brand = brand.Sanitized()
	title := "SonuShield Dashboard"
	name := "SonuShield"
	mark := defaultBrandMark
	style := ""
	if brand.DisplayName != "" {
		name = html.EscapeString(brand.DisplayName)
		title = name + " Dashboard"
	}
	if brand.LogoURL != "" {
		mark = `<img src="` + html.EscapeString(brand.LogoURL) + `" alt="" style="height:28px;width:auto;max-width:140px;object-fit:contain">`
	}
	if brand.AccentColor != "" {
		style = `<style>:root[data-theme="dark"],:root[data-theme="light"]{--accent:` + brand.AccentColor + `;--accent-hover:` + brand.AccentColor + `;--accent-text:` + brand.AccentColor + `}</style>`
	}
	page := string(indexHTML)
	page = strings.ReplaceAll(page, "__BRAND_TITLE__", title)
	page = strings.ReplaceAll(page, "__BRAND_MARK__", mark)
	page = strings.ReplaceAll(page, "__BRAND_NAME__", name)
	page = strings.ReplaceAll(page, "__BRAND_STYLE__", style)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Write([]byte(page))
}

// defaultBrandMark is the built-in shield mark shown in the
// dashboard top bar when the operator configures no logo.
const defaultBrandMark = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 8.6-8 11-4.6-2.4-8-6-8-11V5l8-3z" fill="#f6821f"/><path d="M8.5 12l2.4 2.4 4.7-4.7" stroke="#1a1206" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`

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
