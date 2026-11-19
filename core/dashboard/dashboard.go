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

//go:embed vendor/three-r128.min.js
var threeJS []byte

//go:embed fonts/PlusJakartaSans-Regular.woff2
var fontPlusJakartaSansRegular []byte

//go:embed fonts/PlusJakartaSans-Medium.woff2
var fontPlusJakartaSansMedium []byte

//go:embed fonts/PlusJakartaSans-SemiBold.woff2
var fontPlusJakartaSansSemiBold []byte

//go:embed fonts/PlusJakartaSans-Bold.woff2
var fontPlusJakartaSansBold []byte

//go:embed fonts/JetBrainsMono-Regular.woff2
var fontJetBrainsMonoRegular []byte

//go:embed fonts/JetBrainsMono-Medium.woff2
var fontJetBrainsMonoMedium []byte

//go:embed fonts/JetBrainsMono-Bold.woff2
var fontJetBrainsMonoBold []byte

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
	writePage(writer, render(brand, ""))
}

// ServeControlPlane writes the same dashboard page for the control
// plane: one UI codebase, two serving modes. The only difference is
// the bootstrap script injected in <head>: it sets
// window.SONUSHIELD_CP, which switches the page to session-cookie
// authentication, node-prefixed API calls, and the node switcher
// and accounts views. The caller (the control plane) is
// responsible for session gating. bootstrap must be JSON
// produced by encoding/json (which escapes <, > and & inside
// strings, so it is safe in a <script> block); it must never
// contain secrets, and is injected verbatim.
func ServeControlPlane(writer http.ResponseWriter, brand domains.Branding, bootstrapJSON string) {
	script := `<script>window.SONUSHIELD_CP=` + bootstrapJSON + `;</script>`
	writePage(writer, render(brand, script))
}

func writePage(writer http.ResponseWriter, page string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Write([]byte(page))
}

func render(brand domains.Branding, cpBootstrap string) string {
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
	page = strings.ReplaceAll(page, "__CP_BOOTSTRAP__", cpBootstrap)
	return page
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
	// Self-hosted UI fonts (OFL, latin subset; see fonts/ for the
	// license texts). Immutable versioned content like the icons.
	"vendor/three-r128.min.js":          {threeJS, "text/javascript; charset=utf-8", "public, max-age=86400"},
	"fonts/PlusJakartaSans-Regular.woff2":   {fontPlusJakartaSansRegular, "font/woff2", "public, max-age=86400"},
	"fonts/PlusJakartaSans-Medium.woff2":    {fontPlusJakartaSansMedium, "font/woff2", "public, max-age=86400"},
	"fonts/PlusJakartaSans-SemiBold.woff2":  {fontPlusJakartaSansSemiBold, "font/woff2", "public, max-age=86400"},
	"fonts/PlusJakartaSans-Bold.woff2":      {fontPlusJakartaSansBold, "font/woff2", "public, max-age=86400"},
	"fonts/JetBrainsMono-Regular.woff2": {fontJetBrainsMonoRegular, "font/woff2", "public, max-age=86400"},
	"fonts/JetBrainsMono-Medium.woff2":  {fontJetBrainsMonoMedium, "font/woff2", "public, max-age=86400"},
	"fonts/JetBrainsMono-Bold.woff2":    {fontJetBrainsMonoBold, "font/woff2", "public, max-age=86400"},
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

// ServeAssetSuffix serves a PWA shell asset by its path suffix
// (e.g. "manifest.webmanifest", "sw.js", "icons/icon-192.png") and
// reports whether it served anything. This is the control-plane
// variant: the dashboard is served from the control host root, so
// the shell assets live at root paths. The caller is responsible
// for session gating, exactly as for ServeControlPlane.
func ServeAssetSuffix(writer http.ResponseWriter, suffix string) bool {
	asset, ok := shellAssets[suffix]
	if !ok {
		return false
	}
	writer.Header().Set("Content-Type", asset.contentType)
	writer.Header().Set("Cache-Control", asset.cache)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Write(asset.data)
	return true
}
