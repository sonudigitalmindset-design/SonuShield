package server

// Per-domain bandwidth metering (Batch 5).
//
// The counters are estimates, not billing-grade measurements:
// request bytes come from Content-Length (chunked bodies count
// only what the transport reports, headers are excluded), and
// response bytes are counted as backend bodies are read through
// the metering wrapper. Cache-served responses count their
// stored body size. Challenge pages, block pages, error pages,
// and WebSocket traffic are not counted. Counters live in
// DomainData, reset by reload like the other counters, and feed
// the per-tenant usage API.

import (
	"io"
	"sonushield/core/domains"
	"sonushield/core/firewall"
)

// addDomainBytes adds estimated traffic to one domain's
// counters. It follows the same DomainData copy discipline as
// the rest of the request path.
func addDomainBytes(domain string, in, out int64) {
	if in == 0 && out == 0 {
		return
	}
	firewall.Mutex.Lock()
	data := domains.DomainsData[domain]
	data.BytesIn += in
	data.BytesOut += out
	domains.DomainsData[domain] = data
	firewall.Mutex.Unlock()
}

// meteringReader counts the bytes read from a backend response
// body and flushes the total to the domain's counters when the
// body is closed. The wrapper sits outside the cache hook, so a
// cacheable body is counted once when the hook drains it, and
// the client copy reads the hook's replacement buffer
// uncounted. A body that is never closed (abandoned mid-copy)
// keeps its partial count unflushed: an underestimate, accepted
// for an estimate.
type meteringReader struct {
	io.ReadCloser
	domain string
	n      int64
	done   bool
}

func (m *meteringReader) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	m.n += int64(n)
	return n, err
}

func (m *meteringReader) Close() error {
	if !m.done {
		m.done = true
		addDomainBytes(m.domain, 0, m.n)
	}
	return m.ReadCloser.Close()
}
