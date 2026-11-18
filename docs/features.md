# Features

Every SonuShield feature, with an animated diagram and an advanced explanation: how it works, its exact configuration, and its honest limits. Diagrams are animated schematics (SMIL only, so they animate on GitHub) — each one shows its feature's mechanism in motion.

**114 features** across 9 groups. No feature here is aspirational: every claim traces to code or existing documentation, and limits state plainly what is disabled by default, mock-verified, or untested.

For the whole story in one picture, see [How an Attack Is Stopped](how-an-attack-is-stopped.md) — a plain-English walkthrough with a two-lane animated diagram of the visitor's journey and the attacker's journey through all 16 defense layers.

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

## Challenges

The staged challenges visitors may meet, and the ways they adapt.

- [Staged Challenges](features/challenges.md#staged-challenges)
- [Adaptive Proof-of-Work](features/challenges.md#adaptive-pow)
- [Memory-Hard Proof-of-Work (Argon2id)](features/challenges.md#memory-hard-pow)
- [Challenge Rotation](features/challenges.md#challenge-rotation)
- [Turnstile / hCaptcha Challenges](features/challenges.md#challenge-providers)
- [Passkey Challenge (WebAuthn)](features/challenges.md#passkey-challenge)
- [Custom Challenge Pages + Hindi](features/challenges.md#custom-challenge-pages)
- [Quiet Mode](features/challenges.md#quiet-mode)
- [Challenge-Flow Exemption](features/challenges.md#challenge-exemption)

## Firewall Rules & Enforcement

The rule engine, its testing tools, and the enforcement layers around it.

- [gofilter Firewall Rules](features/firewall.md#gofilter-firewall)
- [Rule Simulator & Dry-Run](features/firewall.md#rule-simulator)
- [Firewall Export / Import](features/firewall.md#firewall-export-import)
- [Edge Rules Engine](features/firewall.md#edge-rules)
- [Community Rule Packs](features/firewall.md#community-packs)
- [Cloudflare Settings Import](features/firewall.md#cloudflare-import)
- [Nginx / Apache Import](features/firewall.md#nginx-apache-import)
- [WAF-lite](features/firewall.md#waf-lite)
- [Tarpit](features/firewall.md#tarpit)
- [IP Manager](features/firewall.md#ip-manager)
- [Per-Session Limits](features/firewall.md#per-session-limits)
- [Scheduled Rules & Maintenance Windows](features/firewall.md#scheduled-rules)
- [Signed URLs & Hotlink Protection](features/firewall.md#signed-urls)

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

## API & Origin Security

Guards for API routes, origins, and the traffic between proxy and backend.

- [API Protection (JWT, Keys, GraphQL)](features/api-security.md#api-protection)
- [Mobile App Attestation](features/api-security.md#mobile-attestation)
- [OpenAPI Request Validation](features/api-security.md#openapi-validation)
- [DLP Scanning](features/api-security.md#dlp-scanning)
- [CSP Report Collector](features/api-security.md#csp-reports)
- [Origin Lock](features/api-security.md#origin-lock)
- [Security Headers & CORS](features/api-security.md#security-headers)
- [Form Spam Guard](features/api-security.md#form-spam-guard)
- [Threat Sharing Network](features/api-security.md#threat-sharing)

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

## Observability & Alerts

Metrics, logs, reports, alerts, and external monitoring signals.

- [Prometheus Metrics](features/observability.md#prometheus-metrics)
- [Telegram & Email Alerts](features/observability.md#alerts)
- [Twilio WhatsApp / SMS Alerts](features/observability.md#twilio-alerts)
- [Attack Reports](features/observability.md#attack-reports)
- [Structured JSON Logs](features/observability.md#structured-logs)
- [Log Search](features/observability.md#log-search)
- [Attack Map](features/observability.md#attack-map)
- [Status Page & Health Endpoint](features/observability.md#status-page)
- [Latency / TTFB & SLA](features/observability.md#latency-sla)
- [Attack Timeline & Postmortem](features/observability.md#attack-timeline)
- [Security Grade Scan](features/observability.md#security-grade)
- [Certificate & Subdomain Alerts](features/observability.md#cert-alerts)
- [BGP Alerts](features/observability.md#bgp-alerts)
- [Live Log Tail (SSE)](features/observability.md#live-log-tail)
- [Real-User Monitoring (RUM)](features/observability.md#rum-beacon)
- [Synthetic Checks](features/observability.md#synthetic-checks)

## Platform, Tenancy & Billing

Multi-tenancy, the control plane, accounts, branding, and billing hooks.

- [Control Plane Service](features/platform.md#control-plane)
- [Accounts & Roles (Control Plane)](features/platform.md#accounts-roles)
- [SSO on the Control Host](features/platform.md#sso-control-host)
- [Node Switcher](features/platform.md#node-switcher)
- [Dashboard Mode](features/platform.md#dashboard-mode)
- [Multi-Tenancy](features/platform.md#multi-tenancy)
- [Metering](features/platform.md#metering)
- [Roles & Audit Log](features/platform.md#roles-audit)
- [SSO / OIDC Dashboard Login](features/platform.md#sso-oidc)
- [White-Label Branding](features/platform.md#white-label)
- [Stripe Billing Hooks](features/platform.md#stripe-hooks)
- [Public API & SDKs](features/platform.md#public-api-sdks)
- [Webhooks & SIEM Export](features/platform.md#webhooks-siem)

## Resilience & Transports

Deployment modes, shared state, transports, and upstream protection.

- [Redis Shared Rate-Limit & Cache](features/resilience.md#redis-shared-state)
- [HTTP/3 & QUIC](features/resilience.md#http3)
- [Cloudflare Auto Under Attack Mode](features/resilience.md#cf-auto-uam)
- [Automatic SSL (Let's Encrypt)](features/resilience.md#auto-ssl)
- [Post-Quantum TLS (X25519MLKEM768)](features/resilience.md#pq-tls)
- [Scrubbing-Center Hooks](features/resilience.md#scrubbing-hooks)
- [Terminal HUD](features/resilience.md#terminal-hud)
- [Cloudflare Mode](features/resilience.md#cloudflare-mode)

---

New here? Start with [How It Works](how-it-works.md), then [Configuration](configuration.md) for the full key reference. SonuShield is a fork of [balooProxy](https://github.com/41Baloo/balooProxy) by 41Baloo, rebuilt by Sonu Digital Mindset — see the [README](../README.md) for attribution.
