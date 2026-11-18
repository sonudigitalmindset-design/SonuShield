package server

// Challenge, captcha, provider-verification, and waiting-room
// pages (Batch 5).
//
// The built-in pages live here as builders over a small string
// table with English and Hindi text. The language is picked from
// the request's Accept-Language header: the first (highest
// priority) tag starting with "hi" selects Hindi, anything else
// falls back to English. The English output is byte-identical to
// the pages the proxy served before this change.
//
// Operator-customizable templates (config pageTemplates) replace
// the visible part of the PoW, captcha, and waiting-room pages.
// Templates use a fixed placeholder set and are substituted as
// data (HTML-escaped); <script> tags are stripped at load time,
// and the server appends the same fixed solver scripts the
// built-in pages use, so a template can never change the
// challenge flow itself. A template missing its required
// placeholders is disabled at load time with a warning and the
// built-in page is served instead. The Turnstile/hCaptcha
// provider page is not customizable: it carries the provider
// widget and its fixed flow.
//
// The terse plain-text block messages (blockMessage and friends)
// stay English in every language: they are short diagnostics, not
// pages. Custom templates may be written in any language.

import (
	"html"
	"net/http"
	"strconv"
	"strings"
)

// pageStrings holds the visitor-visible text of the built-in
// pages in one language. The captcha heading carries <b> markup
// (as the original page did); captchaMessage is the same text
// without markup, for the {{message}} template placeholder.
type pageStrings struct {
	lang string

	powTitle   string
	powMessage string
	powSubtext string

	captchaHeading     string
	captchaMessage     string
	captchaPlaceholder string
	captchaSubmit      string
	captchaSuccess     string
	captchaFailure     string
	captchaWhy         string
	captchaWhyBody     string

	verifyTitle   string
	verifyMessage string
	verifyFailed  string
	verifyNoJS    string

	waitTitle string
	waitBody1 string
	waitPos   string
	waitBody2 string
}

var pageStringsEn = pageStrings{
	lang: "en",

	powTitle:   "Completing challenge ...",
	powMessage: "Completing challenge ...",
	powSubtext: "The process is automatic and shouldn't take too long. Please be patient.",

	captchaHeading:     "Drag the <b>slider</b> and enter the <b>green</b> text you see in the picture",
	captchaMessage:     "Drag the slider and enter the green text you see in the picture",
	captchaPlaceholder: "Solution",
	captchaSubmit:      "Submit",
	captchaSuccess:     "Success! Redirecting ...",
	captchaFailure:     "Failed! Please try again.",
	captchaWhy:         "Why am I seeing this page?",
	captchaWhyBody:     "The website you are trying to visit needs to make sure that you are not a bot. This is a common security measure to protect websites from automated spam and abuse. By entering the characters you see in the picture, you are helping to verify that you are a real person.",

	verifyTitle:   "Verifying&hellip;",
	verifyMessage: "Please wait while we verify your browser.",
	verifyFailed:  "Verification failed. Please reload and try again.",
	verifyNoJS:    "JavaScript is required to verify your browser.",

	waitTitle: "Please wait",
	waitBody1: "This site is busy right now. You are in line and this page will refresh automatically.",
	waitPos:   "Position ",
	waitBody2: "Please do not refresh manually — your place in line is kept automatically.",
}

var pageStringsHi = pageStrings{
	lang: "hi",

	powTitle:   "चुनौती पूरी की जा रही है ...",
	powMessage: "चुनौती पूरी की जा रही है ...",
	powSubtext: "यह प्रक्रिया स्वचालित है और इसमें अधिक समय नहीं लगेगा। कृपया धैर्य रखें।",

	captchaHeading:     "<b>स्लाइडर</b> खींचें और चित्र में दिख रहा <b>हरा</b> पाठ दर्ज करें",
	captchaMessage:     "स्लाइडर खींचें और चित्र में दिख रहा हरा पाठ दर्ज करें",
	captchaPlaceholder: "उत्तर",
	captchaSubmit:      "जमा करें",
	captchaSuccess:     "सफलता! पुनर्निर्देशित किया जा रहा है ...",
	captchaFailure:     "असफल! कृपया पुनः प्रयास करें।",
	captchaWhy:         "मुझे यह पृष्ठ क्यों दिख रहा है?",
	captchaWhyBody:     "आप जिस वेबसाइट पर जाने का प्रयास कर रहे हैं, वह यह सुनिश्चित करना चाहती है कि आप बॉट नहीं हैं। यह वेबसाइटों को स्वचालित स्पैम और दुरुपयोग से बचाने का एक सामान्य सुरक्षा उपाय है। चित्र में दिख रहे अक्षरों को दर्ज करके आप यह सत्यापित करने में सहायता कर रहे हैं कि आप एक वास्तविक व्यक्ति हैं।",

	verifyTitle:   "सत्यापित किया जा रहा है&hellip;",
	verifyMessage: "कृपया प्रतीक्षा करें, हम आपके ब्राउज़र को सत्यापित कर रहे हैं।",
	verifyFailed:  "सत्यापन विफल रहा। कृपया पृष्ठ पुनः लोड करके पुनः प्रयास करें।",
	verifyNoJS:    "आपके ब्राउज़र को सत्यापित करने के लिए JavaScript आवश्यक है।",

	waitTitle: "कृपया प्रतीक्षा करें",
	waitBody1: "यह साइट अभी व्यस्त है। आप कतार में हैं और यह पृष्ठ स्वचालित रूप से रीफ्रेश होगा।",
	waitPos:   "स्थान ",
	waitBody2: "कृपया मैन्युअल रूप से रीफ्रेश न करें — कतार में आपका स्थान स्वचालित रूप से सुरक्षित है।",
}

// pageLang picks the page language from Accept-Language: the
// first (highest-priority) tag starting with "hi" selects Hindi;
// anything else, including a missing header, falls back to
// English.
func pageLang(req *http.Request) string {
	if req == nil {
		return "en"
	}
	accept := req.Header.Get("Accept-Language")
	if accept == "" {
		return "en"
	}
	first := strings.SplitN(accept, ",", 2)[0]
	tag := strings.TrimSpace(strings.SplitN(first, ";", 2)[0])
	if len(tag) >= 2 && strings.EqualFold(tag[:2], "hi") &&
		(len(tag) == 2 || tag[2] == '-' || tag[2] == '_') {
		return "hi"
	}
	return "en"
}

// stringsForLang returns the string table for a language code,
// defaulting to English.
func stringsForLang(lang string) pageStrings {
	if lang == "hi" {
		return pageStringsHi
	}
	return pageStringsEn
}

// stringsFor returns the string table for a request.
func stringsFor(req *http.Request) pageStrings {
	return stringsForLang(pageLang(req))
}

// powPage renders the built-in Stage 2 proof-of-work page.
func powPage(s pageStrings, publicSalt, hashedEncryptedIP string, difficulty int) string {
	return powPageHead(s, publicSalt, hashedEncryptedIP) + powSolverScript(publicSalt, hashedEncryptedIP, difficulty)
}

// captchaPage renders the built-in Stage 3 captcha page.
func captchaPage(s pageStrings, ip, publicPart, captchaData, maskData string) string {
	return captchaPageHead(s) + captchaSolverScript(ip, publicPart, captchaData, maskData)
}

// renderPowTemplate applies a validated custom PoW template:
// placeholders are substituted as escaped data, then the fixed
// solver script is appended.
func renderPowTemplate(tpl string, s pageStrings, publicSalt, hashedEncryptedIP string, difficulty int) string {
	out := tpl
	out = strings.ReplaceAll(out, "{{publicSalt}}", html.EscapeString(publicSalt))
	out = strings.ReplaceAll(out, "{{challenge}}", html.EscapeString(hashedEncryptedIP))
	out = strings.ReplaceAll(out, "{{difficulty}}", strconv.Itoa(difficulty))
	out = strings.ReplaceAll(out, "{{message}}", html.EscapeString(s.powMessage))
	return out + powSolverScript(publicSalt, hashedEncryptedIP, difficulty)
}

// renderCaptchaTemplate applies a validated custom captcha
// template: placeholders are substituted as escaped data, then
// the fixed captcha script is appended. The template's HTML must
// provide the element IDs the script uses (captcha, mask,
// captcha-slider, text, successMessage, failMessage, box,
// center); see docs/configuration.md.
func renderCaptchaTemplate(tpl string, s pageStrings, ip, publicPart, captchaData, maskData string) string {
	out := tpl
	out = strings.ReplaceAll(out, "{{captchaImage}}", html.EscapeString(captchaData))
	out = strings.ReplaceAll(out, "{{maskImage}}", html.EscapeString(maskData))
	out = strings.ReplaceAll(out, "{{publicPart}}", html.EscapeString(publicPart))
	out = strings.ReplaceAll(out, "{{message}}", html.EscapeString(s.captchaMessage))
	return out + captchaSolverScript(ip, publicPart, captchaData, maskData)
}

// renderWaitingTemplate applies a validated custom waiting-room
// template: the queue position and the localized message are
// substituted as escaped data.
func renderWaitingTemplate(tpl string, s pageStrings, position int) string {
	out := tpl
	out = strings.ReplaceAll(out, "{{position}}", strconv.Itoa(position))
	out = strings.ReplaceAll(out, "{{message}}", html.EscapeString(s.waitBody1))
	return out
}

// powPageHead renders the visible part of the built-in Stage 2 page, up to the solver script.
func powPageHead(s pageStrings, publicSalt, hashedEncryptedIP string) string {
	return `<!doctypehtml><html lang=` +
		s.lang +
		`><meta charset=UTF-8><meta content="width=device-width,initial-scale=1"name=viewport><title>` +
		s.powTitle +
		`</title><style>body,html{height:100%;width:100%;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center;background-color:#f0f0f0;font-family:Arial,sans-serif}.loader{display:flex;justify-content:space-around;align-items:center;width:100px;height:100px}.loader div{width:20px;height:20px;background-color:#333;border-radius:50%;animation:bounce .6s infinite alternate}.loader div:nth-child(2){animation-delay:.2s}.loader div:nth-child(3){animation-delay:.4s}@keyframes bounce{to{transform:translateY(-30px)}}.message{text-align:center;margin-top:20px;color:#333}.subtext{text-align:center;color:#666;font-size:.9em;margin-top:5px}.placeholder-container{width:25%;text-align:center;margin:10px 0}.placeholder-label{font-weight:700;margin-bottom:5px}.placeholder{background-color:#e0e0e0;padding:10px;border-radius:5px;word-break:break-all;font-family:monospace;cursor:pointer;}</style><div class=loader><div></div><div></div><div></div></div><div class=message><p>` +
		s.powMessage +
		`<div class=subtext>` +
		s.powSubtext +
		`</div></div><div class=placeholder-container><div class=placeholder-label>publicSalt:</div><div class=placeholder id=publicSalt onclick='ctc("publicSalt")'><span>` +
		publicSalt +
		`</span></div></div><div class=placeholder-container><div class=placeholder-label>challenge:</div><div class=placeholder id=challenge onclick='ctc("challenge")'><span>` +
		hashedEncryptedIP +
		`</span></div></div><script>function ctc(t){navigator.clipboard.writeText(document.getElementById(t).innerText)}</script>`
}

// powSolverScript is the fixed proof-of-work solver appended to the built-in page and to custom PoW templates alike. The balooPow CDN script is unchanged (see the fork/vendor note in the roadmap).
func powSolverScript(publicSalt, hashedEncryptedIP string, difficulty int) string {
	return `<script src="https://cdn.jsdelivr.net/gh/41Baloo/balooPow@main/balooPow.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js"></script><script>function solved(e){document.cookie="_2__bProxy_v=` +
		publicSalt +
		`"+e.solution+"; SameSite=Lax; path=/; Secure",location.href=location.href}new BalooPow("` +
		publicSalt +
		`",` +
		strconv.Itoa(difficulty) +
		`,"` +
		hashedEncryptedIP +
		`",!1).Solve().then(e=>{if(e.match == ""){solved(e)}else alert("Navigator Missmatch ("+e.match+"). Please contact @ddosmitigation")});</script>`
}

// captchaPageHead renders the visible part of the built-in Stage 3 page, up to the solver script.
func captchaPageHead(s pageStrings) string {
	return `<style>body{background-color:#f5f5f5;font-family:Arial,sans-serif}.center{display:flex;align-items:center;justify-content:center;height:100vh}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px}canvas{display:block;margin:0 auto;max-width:100%;width:100%;height:auto}input[type=text]{width:100%;padding:12px 20px;margin:8px 0;box-sizing:border-box;border:2px solid #ccc;border-radius:4px}button{width:100%;background-color:#4caf50;color:#fff;padding:14px 20px;margin:8px 0;border:none;border-radius:4px;cursor:pointer}button:hover{background-color:#45a049}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px;transition:height .1s;position:block}.box *{transition:opacity .1s}.success{background-color:#dff0d8;border:1px solid #d6e9c6;border-radius:4px;color:#3c763d;padding:20px}.failure{background-color:#f0d8d8;border:1px solid #e9c6c6;border-radius:4px;color:#763c3c;padding:20px}.collapsible{background-color:#f5f5f5;color:#444;cursor:pointer;padding:18px;width:100%;border:none;text-align:left;outline:0;font-size:15px}.collapsible:after{content:'\002B';color:#777;font-weight:700;float:right;margin-left:5px}.collapsible.active:after{content:"\2212"}.collapsible:hover{background-color:#e5e5e5}.collapsible-content{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .2s ease-out;background-color:#f5f5f5}.captcha-wrapper{position:relative;width:100%;height:200px}.captcha-wrapper canvas{position:absolute}input[type=range]{-webkit-appearance:none;width:100%;height:25px;background:#ddd;outline:0;opacity:.7;transition:opacity .2s;border-radius:4px;margin:8px 0}input[type=range]:hover{opacity:1}input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}input[type=range]::-moz-range-thumb{width:25px;height:25px;background:#4caf50;cursor:pointer;border-radius:50%}</style><div class=center id=center><div class=box id=box><h1>` +
		s.captchaHeading +
		`</h1><div class=captcha-wrapper><canvas height=37 id=captcha width=100></canvas><canvas height=37 id=mask width=100></canvas></div><input id=captcha-slider max=50 min=-50 type=range><form onsubmit="return checkAnswer(event)"><input id=text type=text maxlength=6 placeholder=` +
		s.captchaPlaceholder +
		` required> <button type=submit>` +
		s.captchaSubmit +
		`</button></form><div class=success id=successMessage style=display:none>` +
		s.captchaSuccess +
		`</div><div class=failure id=failMessage style=display:none>` +
		s.captchaFailure +
		`</div><button class=collapsible>` +
		s.captchaWhy +
		`</button><div class=collapsible-content><p>` +
		s.captchaWhyBody +
		`</div></div></div>`
}

// captchaSolverScript is the fixed captcha logic appended to the built-in page and to custom captcha templates alike.
func captchaSolverScript(ip, publicPart, captchaData, maskData string) string {
	return `<script>let captcha_canvas=document.getElementById("captcha"),captcha_ctx=captcha_canvas.getContext("2d"),mask_canvas=document.getElementById("mask"),mask_ctx=mask_canvas.getContext("2d"),slider=document.getElementById("captcha-slider"),demo_slider=!1,demo_val=1;var i,captcha_image=new Image,mask_image=new Image;function checkAnswer(e){e.preventDefault();var a=document.getElementById("text").value;document.cookie="` +
		ip +
		`_3__bProxy_v="+a+"` +
		publicPart +
		`; SameSite=Lax; path=/; Secure",fetch("https://"+location.hostname+"/_bProxy/verified").then(function(e){return e.text()}).then(function(e){"verified"===e?(document.getElementById("successMessage").style.display="block",setInterval(function(){var e=document.getElementById("box"),a=e.offsetHeight,t=setInterval(function(){a-=20,e.style.height=a+"px";for(var c=e.children,s=0;s<c.length;s++)c[s].style.opacity=0;a<=0&&(e.style.height="0",e.remove(),clearInterval(t),location.href=location.href)},20)},1e3)):(document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3))}).catch(function(e){document.getElementById("failMessage").style.display="block",setInterval(function(){location.href=location.href},1e3)})}captcha_image.onload=function(){captcha_ctx.drawImage(captcha_image,(captcha_canvas.width-captcha_image.width)/2,(captcha_canvas.height-captcha_image.height)/2)},captcha_image.src="data:image/png;base64,` +
		captchaData +
		`",mask_image.onload=function(){mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2,(mask_canvas.height-mask_image.height)/2)},mask_image.src="data:image/png;base64,` +
		maskData +
		`";let demo_int=setInterval(()=>{if(!demo_slider){clearInterval(demo_int);return}slider.value<=-50&&(demo_val=1),slider.value>=50&&(demo_val=-1),slider.value=parseInt(slider.value)+demo_val,updateCaptcha()},50);function updateCaptcha(){let e=parseInt(slider.value);mask_ctx.clearRect(0,0,mask_canvas.width,mask_canvas.height),mask_ctx.drawImage(mask_image,(mask_canvas.width-mask_image.width)/2+e,0)}slider.oninput=function(){demo_slider=!1,updateCaptcha()};var coll=document.getElementsByClassName("collapsible");for(i=0;i<coll.length;i++)coll[i].addEventListener("click",function(){this.classList.toggle("active");var e=this.nextElementSibling;e.style.maxHeight?e.style.maxHeight=null:e.style.maxHeight=e.scrollHeight+"px"});</script>`
}

// providerPage renders the built-in Turnstile/hCaptcha verification page. The widget script is built by the caller; this function only places it.
func providerPage(s pageStrings, nonce, widgetScript string) string {
	return `<!doctype html><html lang="` +
		s.lang +
		`"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
		s.verifyTitle +
		`</title><style>body{font-family:Arial,sans-serif;color:#333;display:flex;height:100vh;margin:0;align-items:center;justify-content:center;background:#f5f5f5}p{text-align:center}</style></head><body><p id="msg">` +
		s.verifyMessage +
		`</p><form id="v" method="post" action="/_bProxy/challenge-verify"><input type="hidden" name="nonce" value="` +
		html.EscapeString(nonce) +
		`"><input type="hidden" name="token" id="token"></form><div id="widget"></div><script>function onSolved(t){document.getElementById("token").value=t;document.getElementById("v").submit();}function onError(){document.getElementById("msg").textContent="` +
		s.verifyFailed +
		`";}</script>` +
		widgetScript +
		`<noscript><p>` +
		s.verifyNoJS +
		`</p></noscript></body></html>`
}

// waitingPage renders the built-in waiting-room page.
func waitingPage(s pageStrings, position int) string {
	return `<!doctype html><html lang="` +
		s.lang +
		`"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5"><meta name="robots" content="noindex"><title>` +
		s.waitTitle +
		`</title><style>body{font-family:Arial,sans-serif;background:#f5f5f5;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fff;border:1px solid #ddd;border-radius:4px;padding:32px;max-width:420px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#666}.pos{font-size:36px;font-weight:bold;color:#111;margin:16px 0}</style></head><body><div class="box"><h1>` +
		s.waitTitle +
		`</h1><p>` +
		s.waitBody1 +
		`</p><div class="pos">` +
		s.waitPos + strconv.Itoa(position) +
		`</div><p>` +
		s.waitBody2 +
		`</p></div></body></html>`
}
