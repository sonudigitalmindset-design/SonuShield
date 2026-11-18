# HTTP/3 (QUIC)

When `proxy.http3` is enabled, SonuShield serves HTTP/3
over QUIC on UDP in addition to HTTP/1.1 and HTTP/2 over
TCP. The same middleware handles every request, so stages,
challenges, firewall rules, and rate limits apply to
HTTP/3 traffic exactly as they do to TCP traffic.

```json
"proxy": {
  "http3": {
    "enabled": true,
    "addr": ""
  }
}
```

`addr` overrides the UDP listen address; empty means
`:443`, the same port number as the TCP TLS listener (UDP
and TCP port numbers are independent, so both listeners
coexist). Disabled by default. Ignored in Cloudflare mode,
where there is no TLS listener — Cloudflare terminates
HTTP/3 at the edge.

## Discovery

HTTPS responses carry `Alt-Svc: h3=":443"; ma=86400` when
HTTP/3 is enabled, so browsers learn the endpoint without
any configuration. The header is never sent on HTTP/3
responses themselves or in Cloudflare mode.

## TLS and fingerprinting

The QUIC listener uses the same TLS configuration as the
TCP listener: per-SNI certificate selection, the same
ClientHello fingerprint hook (quic-go honors
`GetConfigForClient`, so the legacy TLS fingerprint and
JA4 populate for QUIC handshakes too, keyed by the UDP
remote address), and the same curve preferences, including
post-quantum X25519MLKEM768 unless disabled.

**0-RTT early data is never accepted.** 0-RTT requests are
replayable, and replayed requests must not bypass the
challenge flow. This is stated explicitly in code so a
future library default change cannot silently enable it.

## The `ip.quic` rule field

Every HTTP/3 request carries a QUIC fingerprint in the
`ip.quic` firewall rule field; TCP requests get an empty
value. Example rule (config file or API):

```
ip.quic contains "q1:00000001"
```

Format: `q1:<quic-version>:<tls-version>-<cipher>:<alpn>:
<flags>`, e.g. `q1:00000001:13-1301:h3:0000`. The flags
are four 0/1 bits: session resumed, 0-RTT used, QUIC
datagrams advertised by the peer, stream-reset partial
delivery advertised by the peer. All four are real peer
signals from the handshake.

### What is NOT in the fingerprint

quic-go's public API does not expose the raw QUIC
transport parameters (initial_max_data, max_idle_timeout,
max_streams, ack_delay_exponent, and the rest), packet-level
behavior, or version-negotiation attempts, so none of those
are in the fingerprint. They are documented here as
unobservable rather than guessed. GSO status is also
excluded: it describes the local socket, not the client.
Passive OS fingerprinting does not apply to QUIC (there is
no TCP_INFO on a UDP socket), so `ip.os` and `ip.tcpinfo`
stay empty for HTTP/3 requests.

## Limits, stated plainly

- **WebSocket over HTTP/3 is not supported.** RFC 9220
  extended CONNECT cannot be hijacked the way HTTP/1.1
  upgrades can; WebSocket upgrade requests over HTTP/3
  are declined with 502, the same as over HTTP/2.
  WebSocket clients should use the TCP listener.
- **The UDP listener fails open.** If UDP port 443 cannot
  bind, one generic line is logged and the proxy keeps
  serving TCP. A bind failure never stops the proxy.
- **Verification.** The development VM blocks UDP
  `sendmsg` entirely (even on loopback), so a real QUIC
  handshake over sockets could not run here, and no such
  claim is made. What is verified: (1) an in-process
  end-to-end test (`core/server/http3_e2e_test.go`)
  serves the exact production `http3.Server` over an
  in-memory packet connection and drives it with a real
  quic-go client — the QUIC + TLS 1.3 handshake, the
  ClientHello fingerprint hook (legacy + JA4), the
  `ip.quic` fingerprint value (`q1:00000001:13-1301:h3:0000`
  in the test), and gofilter rule matching against it
  all pass; (2) the Batch 3 smoke harness verifies the
  live proxy binds the UDP listener, serves Alt-Svc, and
  does not match `ip.quic` rules for TCP traffic. UDP
  socket delivery and browser interop were NOT tested;
  verify both against your own deployment before
  enabling HTTP/3 in production.
- **No ECH.** As with the TCP listener, Go has no
  server-side Encrypted ClientHello support; the SNI in
  the QUIC handshake is visible to network observers. See
  `core/server/tls.go`.
