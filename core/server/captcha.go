package server

// Captcha challenge serving, shared by the Stage 3 switch case and
// by challenge rotation (Batch 6), which may serve the captcha page
// for a Stage 2 suspicion level. Moved verbatim out of the
// middleware switch so both callers serve byte-identical pages.
//
// The captcha sets a cookie named <ip>_3__bProxy_v whose value is
// the answer plus the public part; together they equal the
// encrypted challenge token, so the substring cookie check in the
// middleware accepts it exactly as it accepts the Stage 1 and
// Stage 2 cookies. Verification reuses the existing
// /_bProxy/verified endpoint; rotation adds no new endpoint.

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"net/http"

	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/utils"
)

// serveCaptchaChallenge renders the captcha page for a challenge:
// it splits the encrypted token into the secret part (the answer)
// and the public part, generates (or reuses a cached) captcha and
// mask image, and serves the built-in page or the validated custom
// captcha template. It always writes a response.
func serveCaptchaChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, encryptedIP, ip string, buffer *bytes.Buffer) {
	secretPart := encryptedIP[:6]
	publicPart := encryptedIP[6:]

	captchaData := ""
	maskData := ""
	captchaCache, captchaExists := firewall.CacheImgs.Load(secretPart)

	if !captchaExists {
		randomShift := rand.Intn(50) - 25
		captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
		randomColor := uint8(rand.Intn(255))
		utils.AddLabel(captchaImg, 0, 18, publicPart[6:], color.RGBA{61, 140, 64, 20})
		utils.AddLabel(captchaImg, rand.Intn(90), rand.Intn(30), publicPart[:6], color.RGBA{255, randomColor, randomColor, 100})
		utils.AddLabel(captchaImg, rand.Intn(25), rand.Intn(20)+10, secretPart, color.RGBA{61, 140, 64, 255})

		amplitude := float64(rand.Intn(10)+10) / 10.0
		period := float64(37) / 5.0
		displacement := func(x, y int) (int, int) {
			dx := amplitude * math.Sin(float64(y)/period)
			dy := amplitude * math.Sin(float64(x)/period)
			return x + int(dx), y + int(dy)
		}
		captchaImg = utils.WarpImg(captchaImg, displacement)

		maskImg := image.NewRGBA(captchaImg.Bounds())
		draw.Draw(maskImg, maskImg.Bounds(), image.Transparent, image.Point{}, draw.Src)

		numTriangles := rand.Intn(20) + 10

		blacklist := make(map[[2]int]bool) // We use this to keep track of already overwritten pixels.
		// it's slightly more performant to not do this but can lead to unsolvable captchas

		for i := 0; i < numTriangles; i++ {
			size := rand.Intn(5) + 10
			x := rand.Intn(captchaImg.Bounds().Dx() - size)
			y := rand.Intn(captchaImg.Bounds().Dy() - size)
			blacklist = utils.DrawTriangle(blacklist, captchaImg, maskImg, x, y, size, randomShift)
		}

		var captchaBuf, maskBuf bytes.Buffer
		if err := png.Encode(&captchaBuf, captchaImg); err != nil {
			SendResponse(errorMessage("Failed to encode captcha: "+err.Error()), buffer, writer)
			return
		}
		if err := png.Encode(&maskBuf, maskImg); err != nil {
			SendResponse(errorMessage("Failed to encode captchaMask: "+err.Error()), buffer, writer)
			return
		}

		captchaData = base64.StdEncoding.EncodeToString(captchaBuf.Bytes())
		maskData = base64.StdEncoding.EncodeToString(maskBuf.Bytes())

		firewall.CacheImgs.Store(secretPart, [2]string{captchaData, maskData})
	} else {
		captchaDataTmp := captchaCache.([2]string)
		captchaData = captchaDataTmp[0]
		maskData = captchaDataTmp[1]
	}

	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
	//Built-in page text is English/Hindi by Accept-Language; a
	//validated custom template replaces the visible part.
	pageStr := stringsFor(request)
	if tpl := settings.PageTemplates; tpl != nil && tpl.Captcha != "" {
		SendResponse(renderCaptchaTemplate(tpl.Captcha, pageStr, ip, publicPart, captchaData, maskData), buffer, writer)
	} else {
		SendResponse(captchaPage(pageStr, resolveBranding(settings), ip, publicPart, captchaData, maskData), buffer, writer)
	}
	return
}
