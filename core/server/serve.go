package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"sonushield/core/domains"
	"sonushield/core/firewall"
	"sonushield/core/metrics"
	"sonushield/core/pnc"
	"sonushield/core/proxy"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var (
	transportMap = sync.Map{}
	bufferPool   = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

func Serve() {

	defer pnc.PanicHndl()

	//GitOps sync loop (Batch 5). Started once; inert unless the
	//operator enables proxy.gitops.
	StartGitOpsWatcher()

	if domains.Config.Proxy.Cloudflare {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		service.SetKeepAlivesEnabled(true)
		service.Handler = http.HandlerFunc(Middleware)

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	} else {

		service := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":80",
			MaxHeaderBytes:    1 << 20,
		}
		serviceH := &http.Server{
			IdleTimeout:       proxy.IdleTimeoutDuration,
			ReadTimeout:       proxy.ReadTimeoutDuration,
			WriteTimeout:      proxy.WriteTimeoutDuration,
			ReadHeaderTimeout: proxy.ReadHeaderTimeoutDuration,
			ConnState:         firewall.OnStateChange,
			Addr:              ":443",
			TLSConfig: &tls.Config{
				GetConfigForClient: firewall.Fingerprint,
				GetCertificate:     domains.GetCertificate,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				CurvePreferences:   tlsCurvePreferences(),
			},
			MaxHeaderBytes: 1 << 20,
		}

		http2.ConfigureServer(service, &http2.Server{})
		http2.ConfigureServer(serviceH, &http2.Server{})

		service.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Let's Encrypt HTTP-01 challenges (autoSSL only). Answered
			// before the domain lookup and HTTPS redirect: the
			// challenge must be served over plain HTTP. When auto
			// SSL is disabled this returns false immediately.
			if domains.HandleACMEChallenge(w, r) {
				return
			}

			firewall.Mutex.RLock()
			domainData, domainFound := domains.DomainsData[r.Host]
			firewall.Mutex.RUnlock()

			if !domainFound {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, unknownHostMessage(r.Host))
				return
			}

			firewall.Mutex.Lock()
			domainData = domains.DomainsData[r.Host]
			domainData.TotalRequests++
			domains.DomainsData[r.Host] = domainData
			firewall.Mutex.Unlock()

			http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)
		})

		service.SetKeepAlivesEnabled(true)
		serviceH.Handler = http.HandlerFunc(Middleware)

		go func() {
			defer pnc.PanicHndl()
			if err := serviceH.ListenAndServeTLS("", ""); err != nil {
				panic(err)
			}
		}()

		if err := service.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer bufferPool.Put(buffer)

	//Use Proxy Read Timeout
	transport := getTripperForDomain(req.Host)

	//Backend selection (Batch 4): the pool picks one backend per
	//attempt. A single-backend pool always picks the same backend,
	//so single-backend configs behave exactly as before. On a
	//transport error the request is retried on another backend
	//when its body can be replayed; non-replayable bodies are
	//never retried, so a POST is never duplicated by failover.
	pool := backendPoolFor(req.Host)
	attempts := 1
	if pool != nil && pool.Size() > 1 {
		attempts = pool.Size()
	}

	var resp *http.Response
	var err error
	backendStart := time.Now()
	for attempt := 0; attempt < attempts; attempt++ {
		var backend *domains.Backend
		if pool != nil {
			backend = pool.Pick()
			if backend == nil {
				err = errAllBackendsDown
				break
			}
			req.URL.Scheme = pool.Scheme
			req.URL.Host = backend.Addr
			pool.TrackStart(backend)
		}
		resp, err = transport.RoundTrip(req)
		if pool != nil && backend != nil {
			pool.TrackEnd(backend)
		}
		if err == nil {
			if pool != nil && backend != nil {
				pool.MarkOK(backend)
			}
			break
		}
		if pool != nil && backend != nil {
			pool.MarkFailed(backend)
		}
		if attempt+1 >= attempts || !requestReplayable(req) {
			break
		}
		if req.GetBody != nil {
			if body, bodyErr := req.GetBody(); bodyErr == nil {
				req.Body = body
			} else {
				break
			}
		}
	}
	metrics.ObserveBackend(req.Host, time.Since(backendStart), err == nil)

	//Connection to backend failed. When every backend is down and
	//the edge cache holds a stale copy, serve it clearly marked
	//instead of the error page.
	if err != nil {
		if stale := staleFallbackResponse(req, pool); stale != nil {
			return stale, nil
		}
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}

		buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
		buffer.WriteString(errMsg) // Page Title
		buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error: `)
		buffer.WriteString(errMsg) // Page Body
		buffer.WriteString(`</h1><p>Sorry, there was an error connecting to the backend. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	//Connection was successfull, got bad response tho
	if resp.StatusCode > 499 && resp.StatusCode < 600 {

		limitReader := io.LimitReader(resp.Body, 1024*1024) // 1 MB for instance
		errBody, errErr := io.ReadAll(limitReader)

		//Metering (Batch 5): the backend error body is read and
		//discarded here, so count what arrived.
		addDomainBytes(req.Host, 0, int64(len(errBody)))

		// Close the original body
		resp.Body.Close()

		errMsg := ""
		if errErr == nil && len(errBody) > 0 {
			errMsg = string(errBody)
			if int64(len(errBody)) == 1024*1024 {
				errMsg += `<p>( Error message truncated. )</p>`
			}
		}

		if errErr == nil && len(errBody) != 0 {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error:`)
			buffer.WriteString(`</h1><p>Sorry, the backend returned this error.</p><iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"srcdoc="`)
			buffer.WriteString(errMsg)
			buffer.WriteString(`"></iframe><a onclick="location.reload()">Reload page</a></div></div></body></html>`)

		} else {

			buffer.WriteString(`<!DOCTYPE html><html><head><title>Error: `)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>`)
			buffer.WriteString(resp.Status)
			buffer.WriteString(`</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick="location.reload()">Reload page</a></div></div></body></html>`)
		}

		resp.Body.Close()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
		}, nil
	}

	//Metering (Batch 5): count response bytes per domain. The
	//wrapper flushes its total when the body is closed, after
	//the cache hook and the client copy have read through it.
	resp.Body = &meteringReader{ReadCloser: resp.Body, domain: req.Host}

	return resp, nil
}

var defaultTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)
	},
	TLSHandshakeTimeout: 10 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	IdleConnTimeout:     90 * time.Second,
	MaxIdleConns:        10,
	MaxConnsPerHost:     10,
}

// Origin pool defaults (Batch 6). These match defaultTransport
// exactly, so a domain with no pool keys behaves as before: it
// shares defaultTransport.
const (
	poolDefaultMaxIdleConns        = 10
	poolDefaultMaxIdleConnsPerHost = 2 // Go's DefaultMaxIdleConnsPerHost
	poolDefaultMaxConnsPerHost     = 10
	poolDefaultIdleConnTimeoutSec  = 90
	poolMaxIdleConnTimeoutSec      = 3600
)

// poolTransportFor builds a dedicated origin Transport for a
// domain from its pool settings, or returns nil when the domain
// configures no pool key (the shared defaultTransport is used).
// A non-positive value selects the default for that limit; the
// idle timeout is clamped to 1..3600 seconds. The dialer, TLS
// handshake timeout, and TLS config match defaultTransport.
func poolTransportFor(settings domains.DomainSettings) *http.Transport {
	if settings.PoolMaxIdleConns == 0 && settings.PoolMaxIdleConnsPerHost == 0 &&
		settings.PoolMaxConnsPerHost == 0 && settings.PoolIdleConnTimeout == 0 {
		return nil
	}
	maxIdle := poolDefaultMaxIdleConns
	if settings.PoolMaxIdleConns > 0 {
		maxIdle = settings.PoolMaxIdleConns
	}
	maxIdlePerHost := poolDefaultMaxIdleConnsPerHost
	if settings.PoolMaxIdleConnsPerHost > 0 {
		maxIdlePerHost = settings.PoolMaxIdleConnsPerHost
	}
	maxConns := poolDefaultMaxConnsPerHost
	if settings.PoolMaxConnsPerHost > 0 {
		maxConns = settings.PoolMaxConnsPerHost
	}
	idleTimeout := poolDefaultIdleConnTimeoutSec
	if settings.PoolIdleConnTimeout > 0 {
		idleTimeout = settings.PoolIdleConnTimeout
		if idleTimeout > poolMaxIdleConnTimeoutSec {
			idleTimeout = poolMaxIdleConnTimeoutSec
		}
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout:     time.Duration(idleTimeout) * time.Second,
		MaxIdleConns:        maxIdle,
		MaxIdleConnsPerHost: maxIdlePerHost,
		MaxConnsPerHost:     maxConns,
	}
}

// resetOriginTransports drops every cached per-domain Transport
// so the next request resolves a fresh one from the current
// settings. Called at the end of a config reload. In-flight
// requests keep the Transport pointer they already hold; idle
// connections on dropped Transports close at their idle timeout.
func resetOriginTransports() {
	transportMap.Range(func(key, _ any) bool {
		transportMap.Delete(key)
		return true
	})
}

func getTripperForDomain(domain string) *http.Transport {
	if transport, ok := transportMap.Load(domain); ok {
		return transport.(*http.Transport)
	}
	transport := defaultTransport
	if uncasted, ok := domains.DomainsMap.Load(domain); ok {
		if settings, ok := uncasted.(domains.DomainSettings); ok {
			if dedicated := poolTransportFor(settings); dedicated != nil {
				transport = dedicated
			}
		}
	}
	actual, _ := transportMap.LoadOrStore(domain, transport)
	return actual.(*http.Transport)
}

type RoundTripper struct {
}
