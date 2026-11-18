package server

// Optional response optimization (Batch 6): Brotli compression
// and on-the-fly image optimization. Both are off by default and
// neither changes what a client receives semantically: Brotli is
// negotiated per response via Accept-Encoding, and image
// optimization only resizes images wider than the configured
// bound, preserving the format.
//
// Hook order in ModifyResponseHook (headers.go) matters and is
// documented there:
//   - Image optimization runs BEFORE the edge-cache store, so the
//     cache stores (and later serves) the optimized bytes and a
//     repeated request costs no re-encode. Optimization is
//     deterministic per URL (no request-header negotiation), so
//     one stored form serves every client.
//   - Brotli runs AFTER the cache store, so the cache stores the
//     origin's uncompressed bytes and cache hits are served
//     uncompressed. A client that accepts Brotli gets compressed
//     responses on cache misses and plain ones on cache hits;
//     both are correct, compression being optional per response.
//
// Shared guards for both features: GET requests only, no
// Authorization header (authenticated traffic is never altered),
// no upgrade requests, 2xx responses only, and Cache-Control:
// no-transform is honored (the origin forbids transformation).
// Either feature fails open: on any error, oversize body, or
// resource bound, the original response passes through
// byte-identical.
//
// Brotli bounds: responses up to 1 MB, compression level 5, only
// compressible content types (text, JSON, JavaScript, XML, SVG).
// A compressed result no smaller than the original is discarded.
// The ETag is weakened (the representation changed) and
// Content-MD5 is dropped; Vary: Accept-Encoding is added.
//
// Image bounds: inputs up to 5 MB, decoded images up to 16
// megapixels, at most 4 concurrent optimizations (overflow
// passes through unoptimized). Only JPEG and PNG are touched,
// and only when wider than imageOptimizeMaxWidth (default 1920):
// narrower images pass through byte-identical, so no quality is
// ever lost and no CPU is spent on images that need nothing.
// Wider images are resized to the bound and re-encoded in their
// original format (JPEG at imageOptimizeQuality, default 80;
// PNG losslessly, preserving transparency). There is no format
// conversion (no WebP/AVIF): the Content-Type is preserved.
// ETag and Content-MD5 are dropped (the bytes changed).

import (
	"bytes"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"golang.org/x/image/draw"

	"sonushield/core/domains"
)

// Brotli limits: fixed, documented above.
const (
	brotliMaxBytes = 1 << 20 // 1 MB
	brotliLevel    = 5
)

// Image optimization limits and defaults. Zero in the config
// means "unset" and selects the default.
const (
	imageOptimizeMaxBytes    = 5 << 20 // 5 MB input cap
	imageOptimizeMaxPixels   = 16000000 // 16 megapixels
	imageOptimizeMaxParallel = 4
	imageOptimizeDefaultMaxWidth = 1920
	imageOptimizeMinMaxWidth     = 16
	imageOptimizeMaxMaxWidth     = 4096
	imageOptimizeDefaultQuality  = 80
	imageOptimizeMinQuality      = 40
	imageOptimizeMaxQuality      = 95
)

// imageOptimizeSem bounds concurrent image optimizations. It is
// acquired non-blockingly: when all slots are busy the response
// passes through unoptimized instead of queueing.
var imageOptimizeSem = make(chan struct{}, imageOptimizeMaxParallel)

// imageOptimizeParams resolves the effective width bound and JPEG
// quality for a domain, applying defaults for unset values and
// clamping the rest. Clamps run in the int domain (see
// memoryPowParams for why).
func imageOptimizeParams(settings domains.DomainSettings) (maxWidth, quality int) {
	maxWidth = imageOptimizeDefaultMaxWidth
	if settings.ImageOptimizeMaxWidth != 0 {
		maxWidth = settings.ImageOptimizeMaxWidth
		if maxWidth < imageOptimizeMinMaxWidth {
			maxWidth = imageOptimizeMinMaxWidth
		}
		if maxWidth > imageOptimizeMaxMaxWidth {
			maxWidth = imageOptimizeMaxMaxWidth
		}
	}
	quality = imageOptimizeDefaultQuality
	if settings.ImageOptimizeQuality != 0 {
		quality = settings.ImageOptimizeQuality
		if quality < imageOptimizeMinQuality {
			quality = imageOptimizeMinQuality
		}
		if quality > imageOptimizeMaxQuality {
			quality = imageOptimizeMaxQuality
		}
	}
	return maxWidth, quality
}

// optimizableRequest reports whether a request is eligible for
// response optimization: GET, unauthenticated, not an upgrade.
func optimizableRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.Method == http.MethodGet && req.Header.Get("Authorization") == "" && !isUpgradeRequest(req)
}

// cacheControlHasNoTransform reports whether a Cache-Control value
// carries the no-transform directive.
func cacheControlHasNoTransform(value string) bool {
	for _, directive := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-transform") {
			return true
		}
	}
	return false
}

// acceptsBrotli reports whether the request's Accept-Encoding
// accepts Brotli. An explicit "br" entry wins over "*" (including
// an explicit q=0, which refuses Brotli even when "*" is present).
func acceptsBrotli(req *http.Request) bool {
	brQ, starQ := -1.0, -1.0
	for _, part := range strings.Split(req.Header.Get("Accept-Encoding"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		token := part
		q := 1.0
		if i := strings.IndexByte(part, ';'); i >= 0 {
			token = strings.TrimSpace(part[:i])
			for _, param := range strings.Split(part[i+1:], ";") {
				param = strings.TrimSpace(param)
				if strings.HasPrefix(param, "q=") {
					if v, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64); err == nil {
						q = v
					}
				}
			}
		}
		switch strings.ToLower(token) {
		case "br":
			brQ = q
		case "*":
			starQ = q
		}
	}
	if brQ >= 0 {
		return brQ > 0
	}
	return starQ > 0
}

// compressibleContentType reports whether a response Content-Type
// is worth Brotli-compressing: text formats and structured-text
// formats. Binary formats (already-compressed media, archives,
// fonts) are excluded.
func compressibleContentType(contentType string) bool {
	media := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if media == "" {
		return false
	}
	if strings.HasPrefix(media, "text/") {
		return true
	}
	switch media {
	case "application/json", "application/javascript",
		"application/xml", "application/rss+xml",
		"application/atom+xml", "application/manifest+json",
		"application/ld+json", "application/x-javascript",
		"image/svg+xml":
		return true
	}
	return strings.HasSuffix(media, "+json") || strings.HasSuffix(media, "+xml")
}

// weakenETag turns a strong ETag into a weak one, in place. Weak
// and missing ETags are left alone.
func weakenETag(h http.Header) {
	etag := h.Get("ETag")
	if strings.HasPrefix(etag, `"`) {
		h.Set("ETag", "W/"+etag)
	}
}

// addVaryToken appends a token to the Vary header unless it (or
// "*") is already present.
func addVaryToken(h http.Header, token string) {
	for _, existing := range splitHeaderList(h.Get("Vary")) {
		if strings.EqualFold(existing, token) || existing == "*" {
			return
		}
	}
	if h.Get("Vary") == "" {
		h.Set("Vary", token)
	} else {
		h.Set("Vary", h.Get("Vary")+", "+token)
	}
}

// readCappedBody reads resp.Body up to limit+1 bytes. It reports
// the bytes read and whether the body was fully consumed within
// the limit. On a read error the partial bytes are returned with
// ok=false and the caller must restore via MultiReader; on
// success the original body is closed and the caller owns the
// bytes.
func readCappedBody(resp *http.Response, limit int64) (body []byte, ok bool) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return body, false
	}
	if int64(len(body)) > limit {
		return body, false
	}
	resp.Body.Close()
	return body, true
}

// restoreResponseBody replaces resp.Body with bytes the caller owns.
func restoreResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
}

// applyBrotli compresses a compressible response with Brotli when
// every guard passes. It never returns an error and never leaves
// a response damaged: any failure restores the original bytes.
func applyBrotli(resp *http.Response, settings domains.DomainSettings) {
	if !settings.Brotli || resp == nil || resp.Body == nil || !optimizableRequest(resp.Request) {
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.StatusCode == http.StatusNoContent {
		return
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return
	}
	if cacheControlHasNoTransform(resp.Header.Get("Cache-Control")) {
		return
	}
	if !compressibleContentType(resp.Header.Get("Content-Type")) {
		return
	}
	if !acceptsBrotli(resp.Request) {
		return
	}
	body, ok := readCappedBody(resp, brotliMaxBytes)
	if !ok {
		// Oversized or read error: restore the bytes read plus
		// the unread remainder behind them.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return
	}
	if len(body) == 0 {
		restoreResponseBody(resp, body)
		return
	}
	var compressed bytes.Buffer
	writer := brotli.NewWriterLevel(&compressed, brotliLevel)
	if _, err := writer.Write(body); err != nil {
		restoreResponseBody(resp, body)
		return
	}
	if err := writer.Close(); err != nil {
		restoreResponseBody(resp, body)
		return
	}
	if compressed.Len() >= len(body) {
		restoreResponseBody(resp, body)
		return
	}
	restoreResponseBody(resp, compressed.Bytes())
	resp.ContentLength = int64(compressed.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(compressed.Len()))
	resp.Header.Set("Content-Encoding", "br")
	resp.Header.Del("Content-MD5")
	weakenETag(resp.Header)
	addVaryToken(resp.Header, "Accept-Encoding")
}

// optimizableImageType reports whether a Content-Type is a JPEG
// or PNG image, returning the format name ("jpeg" or "png").
func optimizableImageType(contentType string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])) {
	case "image/jpeg", "image/jpg":
		return "jpeg", true
	case "image/png":
		return "png", true
	default:
		return "", false
	}
}

// applyImageOptimization resizes an over-wide JPEG/PNG response
// to the configured width bound and re-encodes it in its original
// format. Images at or below the bound, and every failure mode,
// pass through byte-identical.
func applyImageOptimization(resp *http.Response, settings domains.DomainSettings) {
	if !settings.ImageOptimize || resp == nil || resp.Body == nil || !optimizableRequest(resp.Request) {
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.StatusCode == http.StatusNoContent {
		return
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return
	}
	if cacheControlHasNoTransform(resp.Header.Get("Cache-Control")) {
		return
	}
	format, ok := optimizableImageType(resp.Header.Get("Content-Type"))
	if !ok {
		return
	}
	// CPU bound: never queue behind other optimizations.
	select {
	case imageOptimizeSem <- struct{}{}:
		defer func() { <-imageOptimizeSem }()
	default:
		return
	}
	body, ok := readCappedBody(resp, imageOptimizeMaxBytes)
	if !ok {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
		return
	}
	if len(body) == 0 {
		restoreResponseBody(resp, body)
		return
	}
	maxWidth, quality := imageOptimizeParams(settings)
	config, decodedFormat, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil || decodedFormat != format {
		restoreResponseBody(resp, body)
		return
	}
	if config.Width <= maxWidth {
		// At or below the bound: nothing to do, no recompress.
		restoreResponseBody(resp, body)
		return
	}
	if int64(config.Width)*int64(config.Height) > imageOptimizeMaxPixels {
		restoreResponseBody(resp, body)
		return
	}
	src, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		restoreResponseBody(resp, body)
		return
	}
	newHeight := config.Height * maxWidth / config.Width
	if newHeight < 1 {
		newHeight = 1
	}
	dstRect := image.Rect(0, 0, maxWidth, newHeight)
	var dst draw.Image
	if format == "png" {
		dst = image.NewNRGBA(dstRect) // preserves transparency
	} else {
		dst = image.NewRGBA(dstRect)
	}
	draw.CatmullRom.Scale(dst, dstRect, src, src.Bounds(), draw.Over, nil)
	var encoded bytes.Buffer
	if format == "png" {
		err = png.Encode(&encoded, dst)
	} else {
		err = jpeg.Encode(&encoded, dst, &jpeg.Options{Quality: quality})
	}
	if err != nil || encoded.Len() == 0 || encoded.Len() >= len(body) {
		restoreResponseBody(resp, body)
		return
	}
	restoreResponseBody(resp, encoded.Bytes())
	resp.ContentLength = int64(encoded.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(encoded.Len()))
	resp.Header.Del("Content-MD5")
	resp.Header.Del("ETag")
}
