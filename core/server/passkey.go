package server

// Passkey challenge serving (Batch 8).
//
// When a domain enables passkeys with an RP ID and at least one
// enrolled credential, Stage 3 serves a WebAuthn assertion page
// instead of the captcha. The flow mirrors the provider
// challenge: a single-use nonce bound to the client's IP, TLS
// fingerprint, and User-Agent, together with the WebAuthn
// challenge bytes and the encrypted token the client must end
// up holding, is stored server-side; the browser's
// navigator.credentials.get() call produces an assertion that
// is POSTed to /_bProxy/passkey-verify; on success the server
// sets the same __bProxy_v cookie the other challenges set.
//
// The page carries no product branding and the verification
// endpoint renders no page. With no enrolled credentials the
// captcha is served instead, so passkeys can never strand a
// visitor. The registration ceremony is not implemented:
// credentials are enrolled through the control API.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"sonushield/core/domains"
	"sonushield/core/logging"
)

type pendingPasskey struct {
	challenge   []byte
	encryptedIP string
	redirectURL string
	ip          string
	tlsFp       string
	userAgent   string
	expires     time.Time
}

// pendingPasskeys holds not-yet-verified passkey challenges,
// keyed by nonce. Entries are single-use and expire after 10
// minutes.
var pendingPasskeys = sync.Map{}

const passkeyNonceTTL = 10 * time.Minute

// PasskeyConfigured reports whether a domain can serve the
// passkey challenge: enabled, with an RP ID, and at least one
// enrolled credential.
func PasskeyConfigured(settings domains.DomainSettings) bool {
	if !settings.Passkey.Enabled || settings.Passkey.RPID == "" {
		return false
	}
	return settings.Passkeys != nil && settings.Passkeys.Count() > 0
}

func storePendingPasskey(entry pendingPasskey) (nonce string, challenge []byte, ok bool) {
	nonceBytes := make([]byte, 32)
	challenge = make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", nil, false
	}
	if _, err := rand.Read(challenge); err != nil {
		return "", nil, false
	}
	nonce = hex.EncodeToString(nonceBytes)
	entry.challenge = challenge
	entry.expires = time.Now().Add(passkeyNonceTTL)
	pendingPasskeys.Store(nonce, entry)

	// Opportunistic purge so a flood of challenge pages cannot
	// grow the map without bound. Lazy expiry on lookup handles
	// the rest.
	count := 0
	pendingPasskeys.Range(func(_, _ any) bool {
		count++
		return count <= 4096
	})
	if count > 4096 {
		now := time.Now()
		pendingPasskeys.Range(func(key, value any) bool {
			if entry, ok := value.(pendingPasskey); ok && now.After(entry.expires) {
				pendingPasskeys.Delete(key)
			}
			return true
		})
	}
	return nonce, challenge, true
}

func takePendingPasskey(nonce, ip, tlsFp, userAgent string) (pendingPasskey, bool) {
	value, ok := pendingPasskeys.LoadAndDelete(nonce)
	if !ok {
		return pendingPasskey{}, false
	}
	entry, ok := value.(pendingPasskey)
	if !ok || time.Now().After(entry.expires) {
		return pendingPasskey{}, false
	}
	if entry.ip != ip || entry.tlsFp != tlsFp || entry.userAgent != userAgent {
		return pendingPasskey{}, false
	}
	return entry, true
}

// ServePasskeyChallenge renders the WebAuthn assertion page for
// a Stage 3 request. It returns false (rendering nothing) only
// when nonce generation fails, in which case the caller falls
// back to the captcha page.
func ServePasskeyChallenge(writer http.ResponseWriter, request *http.Request, settings domains.DomainSettings, domainName, encryptedIP, ip, tlsFp string) bool {
	nonce, challenge, ok := storePendingPasskey(pendingPasskey{
		encryptedIP: encryptedIP,
		redirectURL: request.URL.RequestURI(),
		ip:          ip,
		tlsFp:       tlsFp,
		userAgent:   request.UserAgent(),
	})
	if !ok {
		return false
	}
	writer.Header().Set("Content-Type", "text/html")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	fmt.Fprint(writer, withBehaviorScript(passkeyPage(stringsFor(request), nonce, challenge, settings.Passkey.RPID, settings.Passkeys.CredentialIDs()), settings, domainName))
	return true
}

// passkeyPage renders the assertion page. The script attempts
// the WebAuthn call on load and offers a button for browsers
// that require a user gesture. All embedded values are JSON
// encoded, never interpolated raw.
func passkeyPage(s pageStrings, nonce string, challenge []byte, rpID string, credentialIDs []string) string {
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)
	idsJSON, _ := json.Marshal(credentialIDs)
	return `<!DOCTYPE html><html lang="` + s.lang + `"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + s.passkeyTitle + `</title><style>body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#222;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:32px;max-width:420px;text-align:center;animation:cardIn .5s cubic-bezier(.22,1,.36,1)}@keyframes cardIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@media (prefers-reduced-motion:reduce){.card{animation:none}}h1{font-size:20px;margin:0 0 12px}p{color:#555}button{font-size:16px;padding:10px 24px;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer;transition:background-color .15s cubic-bezier(.22,1,.36,1),border-color .15s cubic-bezier(.22,1,.36,1)}button:hover{background:#f0f0f0}#msg{color:#a00;min-height:1.2em}</style></head><body><div class="card"><h1>` + s.passkeyTitle + `</h1><p>` + s.passkeyMessage + `</p><p><button type="button" id="go">` + s.passkeyButton + `</button></p><p id="msg"></p><noscript><p>` + s.passkeyNoJS + `</p></noscript></div><script>
var NONCE=` + strconv.Quote(nonce) + `;
var CHALLENGE=` + strconv.Quote(challengeB64) + `;
var RPID=` + strconv.Quote(rpID) + `;
var IDS=` + string(idsJSON) + `;
function b64urlToBuf(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var bin=atob(s);var buf=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);return buf;}
function bufToB64url(buf){var bin="";var bytes=new Uint8Array(buf);for(var i=0;i<bytes.length;i++)bin+=String.fromCharCode(bytes[i]);return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function fail(){document.getElementById("msg").textContent=` + strconv.Quote(s.passkeyFailed) + `;}
function run(){
  if(!window.PublicKeyCredential){fail();return;}
  var allow=IDS.map(function(id){return {type:"public-key",id:b64urlToBuf(id)};});
  navigator.credentials.get({publicKey:{challenge:b64urlToBuf(CHALLENGE),rpId:RPID,allowCredentials:allow,userVerification:"preferred"}}).then(function(cred){
    var r=cred.response;
    return fetch("/_bProxy/passkey-verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nonce:NONCE,id:cred.id,clientDataJSON:bufToB64url(r.clientDataJSON),authenticatorData:bufToB64url(r.authenticatorData),signature:bufToB64url(r.signature)})});
  }).then(function(resp){
    if(!resp.ok){fail();return null;}
    return resp.json();
  }).then(function(data){
    if(data&&data.redirect){window.location=data.redirect;}
    else if(data){fail();}
  }).catch(fail);
}
document.getElementById("go").addEventListener("click",run);
run();
</script></body></html>`
}

// HandlePasskeyVerify answers POST /_bProxy/passkey-verify. It
// always writes a response (JSON with the redirect URL on
// success, a generic error otherwise) and reports whether it
// handled the request.
func HandlePasskeyVerify(writer http.ResponseWriter, request *http.Request, domainName, ip, tlsFp string) bool {
	if request.URL.Path != "/_bProxy/passkey-verify" {
		return false
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 64<<10))
	if err != nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "Bad request.")
		return true
	}
	var assertion struct {
		Nonce             string `json:"nonce"`
		ID                string `json:"id"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
	}
	if err := json.Unmarshal(body, &assertion); err != nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "Bad request.")
		return true
	}
	entry, ok := takePendingPasskey(assertion.Nonce, ip, tlsFp, request.UserAgent())
	if !ok {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}
	uncasted, ok := domains.DomainsMap.Load(domainName)
	if !ok {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, "404 Not Found")
		return true
	}
	settings, _ := uncasted.(domains.DomainSettings)
	clientDataJSON, errCD := base64.RawURLEncoding.DecodeString(assertion.ClientDataJSON)
	authData, errAD := base64.RawURLEncoding.DecodeString(assertion.AuthenticatorData)
	signature, errSig := base64.RawURLEncoding.DecodeString(assertion.Signature)
	verified := errCD == nil && errAD == nil && errSig == nil &&
		settings.Passkeys != nil && settings.Passkeys.VerifyAssertion(settings.Passkey.RPID, settings.Passkey.Origins, entry.challenge, assertion.ID, clientDataJSON, authData, signature)
	if !verified {
		logging.Log(logging.Entry{Event: "challenge", Domain: domainName, IP: ip, Action: "passkey_failed", Method: request.Method, Path: "/_bProxy/passkey-verify", UserAgent: request.UserAgent()})
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusForbidden)
		fmt.Fprint(writer, "Verification failed.")
		return true
	}
	// Same cookie the other challenge flows set, then back to
	// the original URL (the page navigates there).
	writer.Header().Set("Set-Cookie", "__bProxy_v="+entry.encryptedIP+"; SameSite=Lax; path=/; Secure")
	writer.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]string{"redirect": entry.redirectURL})
	writer.Write(resp)
	return true
}
