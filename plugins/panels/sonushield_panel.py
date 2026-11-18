#!/usr/bin/env python3
"""SonuShield hosting-panel client (Batch 8).

Provisions SonuShield domains from a hosting panel (cPanel/WHM, Plesk, or
any scripted environment) through the SonuShield control API v2. Standard
library only; no third-party packages.

Authentication: the API secret goes in the SONUSHIELD_API_SECRET
environment variable, or --secret on the command line (discouraged: it
shows up in process listings). The secret is sent only as the
X-SonuShield-Secret header to the --api-url host, and is never printed.

API v2 shape (see docs/api.md): reads are GET, writes are POST with query
parameters, and every response is {"success": bool, "results": {...}}.
Errors surface as {"success": false, "results": {"ERROR": code}}.

Commands:
  list-domains     list configured domains
  add-domain       create one domain from a template
  import-domains   create many domains from a JSON/CSV file (all-or-nothing)
  get-config       show a domain's safe (non-secret) settings
  templates        list domain templates

This client provisions domains only. Secrets (challenge keys, alert
tokens, webhook URLs) stay config-file-only by design and cannot be set
through the API. TLS certificate/key paths are supplied per domain at
creation; provisioning certificates themselves is the panel's job.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API_VERSION = "v2"


class Client:
    def __init__(self, api_url, secret, timeout=30):
        self.api_url = api_url.rstrip("/")
        self.secret = secret
        self.timeout = timeout

    def call(self, action, params=None, domain=None, method="GET"):
        path = "/_bProxy/api/v2/"
        if domain:
            path += urllib.parse.quote(domain, safe="") + "/"
        path += action
        if params:
            path += "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(
            self.api_url + path,
            method=method,
            headers={"X-SonuShield-Secret": self.secret},
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout,
                context=ssl.create_default_context(),
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except Exception:
                raise SystemExit("HTTP %s from proxy" % exc.code)
        except urllib.error.URLError as exc:
            raise SystemExit("cannot reach proxy: %s" % exc.reason)
        if not payload.get("success"):
            results = payload.get("results") or {}
            detail = results.get("ERROR_DETAIL", "")
            raise SystemExit(
                "proxy error: %s%s"
                % (results.get("ERROR", "unknown"), " — " + detail if detail else "")
            )
        return payload.get("results") or {}


def cmd_list_domains(client, _args):
    results = client.call("GET_DOMAINS")
    for domain in results.get("DOMAINS", []):
        print("%s\t%s\t%s" % (domain.get("NAME"), domain.get("BACKEND"), domain.get("SCHEME")))


def cmd_templates(client, _args):
    results = client.call("GET_DOMAIN_TEMPLATES")
    for template in results.get("TEMPLATES", []):
        print("%s\t%s" % (template.get("NAME"), template.get("DESCRIPTION", "")))


def cmd_add_domain(client, args):
    params = {
        "name": args.name,
        "backend": args.backend,
        "scheme": args.scheme,
        "template": args.template,
    }
    if args.certificate:
        params["certificate"] = args.certificate
    if args.key:
        params["key"] = args.key
    results = client.call("CREATE_DOMAIN_FROM_TEMPLATE", params, method="POST")
    print(json.dumps(results, indent=2, sort_keys=True))


def cmd_import_domains(client, args):
    with open(args.file, "r", encoding="utf-8") as handle:
        data = handle.read()
    results = client.call(
        "IMPORT_DOMAINS",
        {"format": args.format, "data": data},
        method="POST",
    )
    print(json.dumps(results, indent=2, sort_keys=True))


def cmd_get_config(client, args):
    results = client.call("GET_DOMAIN_CONFIG", domain=args.domain)
    print(json.dumps(results, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(description="SonuShield hosting-panel client")
    parser.add_argument("--api-url", required=True,
                        help="proxy base URL, e.g. https://proxy.example.com")
    parser.add_argument("--secret", default=os.environ.get("SONUSHIELD_API_SECRET", ""),
                        help="API secret (prefer the SONUSHIELD_API_SECRET env var)")
    parser.add_argument("--timeout", type=int, default=30)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-domains", help="list configured domains")
    sub.add_parser("templates", help="list domain templates")

    add = sub.add_parser("add-domain", help="create one domain from a template")
    add.add_argument("--name", required=True, help="domain name, e.g. example.com")
    add.add_argument("--backend", required=True, help="origin host:port")
    add.add_argument("--scheme", default="http", choices=["http", "https"])
    add.add_argument("--template", default="standard",
                     help="domain template name (see templates command)")
    add.add_argument("--certificate", help="path to the TLS certificate file on the proxy")
    add.add_argument("--key", help="path to the TLS key file on the proxy")

    imp = sub.add_parser("import-domains", help="create many domains from a file")
    imp.add_argument("--file", required=True)
    imp.add_argument("--format", default="json", choices=["json", "csv"])

    getc = sub.add_parser("get-config", help="show a domain's safe settings")
    getc.add_argument("--domain", required=True)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.secret:
        parser.error("no API secret: set SONUSHIELD_API_SECRET or pass --secret")
    client = Client(args.api_url, args.secret, timeout=args.timeout)
    commands = {
        "list-domains": cmd_list_domains,
        "templates": cmd_templates,
        "add-domain": cmd_add_domain,
        "import-domains": cmd_import_domains,
        "get-config": cmd_get_config,
    }
    commands[args.command](client, args)


if __name__ == "__main__":
    main()
