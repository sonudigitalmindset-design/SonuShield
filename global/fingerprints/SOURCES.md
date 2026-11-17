# Fingerprint Lists — Sources and Provenance

At startup the proxy fetches the JSON files in this directory and uses them
to replace the built-in fingerprint maps. If a fetch fails, the built-in
maps (in `core/firewall/fingerprint.go`) are kept, so the proxy still works
offline. The built-in maps are kept in sync with these files.

## Legacy (custom-format) lists

- `known_fingerprints.json` — fingerprints of major browsers.
- `bot_fingerprints.json` — fingerprints of known bots, tools, and crawlers.
- `malicious_fingerprints.json` — fingerprints that are blocked outright.

These values use SonuShield's own fingerprint format (cipher suites and
supported curves from the TLS ClientHello, as computed by `Fingerprint` in
`core/firewall/fingerprint.go`). They are **not** JA3 hashes and cannot be
compared with JA3 databases.

Provenance: the lists were inherited from the original balooProxy project
(41Baloo) and are maintained in this repository. Values come from ClientHello
observations recorded by the project maintainers. No values are invented:
a value is only added after it has been observed in a real ClientHello and
attributed to a client.

## JA4 lists

- `ja4_known.json` — JA4 values of known-good clients.
- `ja4_bot.json` — JA4 values of known bots.
- `ja4_malicious.json` — JA4 values that are blocked outright.

These files are **intentionally empty**. SonuShield computes JA4 from the
fields Go's `crypto/tls` stack exposes (cipher suites, curves, signature
schemes, ALPN, versions) because Go does not expose the raw ClientHello or
the full ordered extension list. The cipher hash follows the FoxIO JA4
specification exactly, but the extension count and extension hash are
approximated, so SonuShield JA4 values are only comparable with other
SonuShield-computed values — never with entries in external JA4 databases.
See the limitation note at the top of `core/firewall/ja4.go`.

### How to populate the JA4 lists

1. Run the proxy and visit `/_bProxy/fingerprint` from the client you want
   to classify. The page shows the JA4 value of the current connection.
2. Add the observed value to a local `ja4_fingerprints.json` file next to
   `config.json`:

   ```json
   {
     "known": { "t13d1516h2_...": "Chromium" },
     "bot": {},
     "malicious": {}
   }
   ```

   Local entries are merged over the fetched lists at startup and win on
   key conflicts. The file is optional; when it is missing, nothing changes.
3. Only add values you observed yourself, on your own proxy, from a client
   you could attribute. Never copy JA4 values from external databases —
   they will not match what this proxy computes.

JA4 only fills in when the legacy fingerprint is unknown, and the legacy
lists stay the primary classification signal. Firewall rules can also match
on JA4 directly with the `ip.ja4` field; see
[Firewall Rules](../../docs/firewall-rules.md).
