# Features

Every SonuShield feature, with an animated diagram and an advanced explanation: how it works, its exact configuration, and its honest limits. Diagrams are animated schematics (SMIL only, so they animate on GitHub) — each one shows its feature's mechanism in motion.

**46 features across 3 groups published so far.** The remaining groups are rendered and verified one by one and will land here in follow-up commits — nothing is listed before its diagram has been render-checked. No feature here is aspirational: every claim traces to code or existing documentation, and limits state plainly what is disabled by default, mock-verified, or untested.

## Detection & Fingerprinting

How SonuShield identifies clients and scores requests before deciding anything.

- [TLS Fingerprinting](features/detection.md#tls-fingerprinting)
- [JA4 Fingerprinting](features/detection.md#ja4-fingerprinting)
- [sh1 HTTP Fingerprint](features/detection.md#sh1-http-fingerprint)
- [HTTP/2 Fingerprinting](features/detection.md#http2-fingerprinting)
- [QUIC Fingerprinting (ip.quic)](features/detection.md#quic-fingerprinting)
- [Passive OS Fingerprinting](features/detection.md#os-fingerprinting)
- [Geo / ASN Rules](features/detection.md#geo-asn-rules)
- [IP Reputation](features/detection.md#ip-reputation)
- [Cross-Domain Reputation Sharing](features/detection.md#shared-reputation)
- [Risk Score (ip.risk)](features/detection.md#risk-score)
- [Timing & Behavior Detection](features/detection.md#timing-detection)
- [Mouse / Scroll Behavior Check](features/detection.md#behavior-check)
- [Fake Search-Bot Verification](features/detection.md#fake-bot-check)
- [Honeypot Endpoints](features/detection.md#honeypot)
- [Canary Tokens](features/detection.md#canary-tokens)
- [Invisible Markers](features/detection.md#invisible-markers)
- [Credential Stuffing Detection](features/detection.md#credential-stuffing)
- [Session Hijack Detection](features/detection.md#session-hijack)
- [ML Anomaly Detector (experimental)](features/detection.md#anomaly-detector)

## Edge, Caching & Performance

Rate limits, queues, caches, backends, and the request path under load.

- [Rate Limits](features/performance.md#rate-limits)
- [Waiting Room](features/performance.md#waiting-room)
- [Fair Queuing](features/performance.md#fair-queuing)
- [Edge Cache](features/performance.md#edge-cache)
- [Cache Analytics & Purge](features/performance.md#cache-analytics)
- [Origin Pooling & Stampede Guard](features/performance.md#origin-pooling)
- [Load Balancing & Failover](features/performance.md#lb-failover)
- [WebSocket Proxying](features/performance.md#websocket-proxying)
- [Brotli & Image Optimization](features/performance.md#brotli-image-optimize)
- [Payload Limits](features/performance.md#payload-limits)
- [Slowloris & Smuggling Guards](features/performance.md#slowloris-guards)
- [Shadow Mode](features/performance.md#shadow-mode)

## Operations & Management

Running, configuring, and managing the proxy day to day.

- [Dashboard & Control Panel](features/operations.md#dashboard-control-panel)
- [Dashboard Hindi / English & PWA](features/operations.md#dashboard-i18n-pwa)
- [Config Rollback](features/operations.md#config-rollback)
- [GitOps](features/operations.md#gitops)
- [Setup Wizard](features/operations.md#setup-wizard)
- [Domain Templates & Bulk Import](features/operations.md#domain-templates)
- [CLI, Helm Chart & Installer](features/operations.md#cli-helm-installer)
- [Config Validator & CI](features/operations.md#config-validator)
- [Backup & Migrate](features/operations.md#backup-migrate)
- [WordPress & Hosting-Panel Plugins](features/operations.md#wordpress-plugins)
- [Visual Rule Builder](features/operations.md#visual-rule-builder)
- [Two-Person Approval](features/operations.md#two-person-approval)
- [Privacy Mode](features/operations.md#privacy-mode)
- [On-Call Rotation](features/operations.md#on-call)
- [API v1 & v2](features/operations.md#api-v1-v2)

---

New here? Start with [How It Works](how-it-works.md), then [Configuration](configuration.md) for the full key reference. SonuShield is a fork of [balooProxy](https://github.com/41Baloo/balooProxy) by 41Baloo, rebuilt by Sonu Digital Mindset — see the [README](../README.md) for attribution.
